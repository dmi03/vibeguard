/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/shaper"
	"golang.zx2c4.com/wireguard/transport"
)

// StreamRole selects whether a StreamBind dials (client) or listens (server).
type StreamRole int

const (
	RoleClient StreamRole = iota
	RoleServer
)

// streamFrameMax bounds a single framed packet on the wire.
const streamFrameMax = 65535

// StreamBind implements conn.Bind by carrying WireGuard packets over a
// connection-oriented transport.Transport (e.g. REALITY). Each packet is framed
// on the stream as [2-byte big-endian length][packet]. It is the bridge that lets
// the packet-oriented WireGuard device (and the Phase-1 ObfsBind, which can wrap
// this bind) run over a byte stream: the AEAD-obfuscated packet becomes the
// payload inside the established transport session.
//
// Client role dials the server once (redialing on failure) and has a single
// endpoint. Server role listens, and maps each accepted stream to an endpoint
// keyed by its remote address.
type StreamBind struct {
	transport transport.Transport
	role      StreamRole
	dest      string // client: server address to dial; server: listen address
	shaper    *shaper.Shaper

	mu       sync.Mutex
	conns    map[string]*connState // endpoint string -> stream
	listener net.Listener
	recv     chan recvItem
	closing  chan struct{}
	started  bool
}

type connState struct {
	conn net.Conn
	wmu  sync.Mutex // serializes framed writes
	ep   Endpoint
}

type recvItem struct {
	data []byte
	ep   Endpoint
}

var _ Bind = (*StreamBind)(nil)

// NewStreamBind builds a StreamBind. For RoleClient, dest is the server address
// to dial (host:port). For RoleServer, dest is the listen address (may be empty
// to listen on the port passed to Open). shaper may be nil.
func NewStreamBind(t transport.Transport, role StreamRole, dest string, sh *shaper.Shaper) *StreamBind {
	return &StreamBind{
		transport: t,
		role:      role,
		dest:      dest,
		shaper:    sh,
		conns:     make(map[string]*connState),
	}
}

func (b *StreamBind) Open(port uint16) ([]ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.started {
		return nil, 0, ErrBindAlreadyOpen
	}
	b.recv = make(chan recvItem, 1024)
	b.closing = make(chan struct{})
	b.started = true

	actualPort := port
	if b.role == RoleServer {
		addr := b.dest
		if addr == "" {
			addr = ":" + strconv.Itoa(int(port))
		}
		ln, err := b.transport.Listen(addr)
		if err != nil {
			b.started = false
			return nil, 0, err
		}
		b.listener = ln
		if p := portFromAddr(ln.Addr()); p != 0 {
			actualPort = p
		}
		go b.acceptLoop(ln)
	} else {
		go b.dialLoop()
	}

	return []ReceiveFunc{b.receive}, actualPort, nil
}

func (b *StreamBind) acceptLoop(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		ep := &streamEndpoint{addr: c.RemoteAddr().String()}
		cs := &connState{conn: c, ep: ep}
		b.mu.Lock()
		b.conns[ep.addr] = cs
		b.mu.Unlock()
		go b.readLoop(cs)
	}
}

func (b *StreamBind) dialLoop() {
	backoff := time.Second
	for {
		select {
		case <-b.closing:
			return
		default:
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		c, err := b.transport.Dial(ctx, b.dest)
		cancel()
		if err != nil {
			select {
			case <-b.closing:
				return
			case <-time.After(backoff):
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = time.Second
		ep := &streamEndpoint{addr: b.dest}
		cs := &connState{conn: c, ep: ep}
		b.mu.Lock()
		b.conns[ep.addr] = cs
		b.mu.Unlock()
		b.readLoop(cs) // blocks until the connection dies, then redial
	}
}

func (b *StreamBind) readLoop(cs *connState) {
	defer func() {
		cs.conn.Close()
		b.mu.Lock()
		if b.conns[cs.ep.DstToString()] == cs {
			delete(b.conns, cs.ep.DstToString())
		}
		b.mu.Unlock()
	}()

	var hdr [2]byte
	for {
		if _, err := io.ReadFull(cs.conn, hdr[:]); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint16(hdr[:]))
		if n == 0 {
			continue
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(cs.conn, buf); err != nil {
			return
		}
		select {
		case b.recv <- recvItem{data: buf, ep: cs.ep}:
		case <-b.closing:
			return
		}
	}
}

func (b *StreamBind) receive(packets [][]byte, sizes []int, eps []Endpoint) (int, error) {
	// Block for at least one packet, then drain what's queued.
	var first recvItem
	select {
	case <-b.closing:
		return 0, net.ErrClosed
	case first = <-b.recv:
	}
	n := 0
	put := func(it recvItem) bool {
		if n >= len(packets) {
			return false
		}
		sizes[n] = copy(packets[n], it.data)
		eps[n] = it.ep
		n++
		return true
	}
	put(first)
	for n < len(packets) {
		select {
		case it := <-b.recv:
			if !put(it) {
				return n, nil
			}
		default:
			return n, nil
		}
	}
	return n, nil
}

func (b *StreamBind) Send(bufs [][]byte, ep Endpoint) error {
	b.mu.Lock()
	cs := b.conns[ep.DstToString()]
	if cs == nil && b.role == RoleClient {
		// Route all client traffic over the single dialled stream.
		for _, c := range b.conns {
			cs = c
			break
		}
	}
	b.mu.Unlock()
	if cs == nil {
		return nil // not connected yet; WireGuard will retransmit
	}

	for _, buf := range bufs {
		if len(buf) > streamFrameMax {
			continue
		}
		if b.shaper != nil {
			b.shaper.Pace(len(buf))
		}
		if err := writeFrame(cs, buf); err != nil {
			cs.conn.Close()
			return err
		}
	}
	return nil
}

func writeFrame(cs *connState, buf []byte) error {
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(buf)))
	cs.wmu.Lock()
	defer cs.wmu.Unlock()
	if _, err := cs.conn.Write(hdr[:]); err != nil {
		return err
	}
	_, err := cs.conn.Write(buf)
	return err
}

func (b *StreamBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.started {
		return nil
	}
	b.started = false
	select {
	case <-b.closing:
	default:
		close(b.closing)
	}
	if b.listener != nil {
		b.listener.Close()
		b.listener = nil
	}
	for _, cs := range b.conns {
		cs.conn.Close()
	}
	b.conns = make(map[string]*connState)
	return nil
}

func (b *StreamBind) SetMark(mark uint32) error { return nil }

func (b *StreamBind) ParseEndpoint(s string) (Endpoint, error) {
	return &streamEndpoint{addr: s}, nil
}

func (b *StreamBind) BatchSize() int { return 1 }

// Shaper returns the egress shaper (may be nil), so callers such as the UAPI can
// live-update pacing parameters.
func (b *StreamBind) Shaper() *shaper.Shaper { return b.shaper }

func portFromAddr(a net.Addr) uint16 {
	_, portStr, err := net.SplitHostPort(a.String())
	if err != nil {
		return 0
	}
	p, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return 0
	}
	return uint16(p)
}

// streamEndpoint is a conn.Endpoint identifying a stream peer by its address.
type streamEndpoint struct {
	addr string
}

var _ Endpoint = (*streamEndpoint)(nil)

func (e *streamEndpoint) ClearSrc()           {}
func (e *streamEndpoint) SrcToString() string { return "" }
func (e *streamEndpoint) DstToString() string { return e.addr }
func (e *streamEndpoint) DstToBytes() []byte  { return []byte(e.addr) }

func (e *streamEndpoint) DstIP() netip.Addr {
	if ap, err := netip.ParseAddrPort(e.addr); err == nil {
		return ap.Addr()
	}
	return netip.Addr{}
}

func (e *streamEndpoint) SrcIP() netip.Addr { return netip.Addr{} }
