/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package transport

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

// UDP is the UDP implementation of Transport. It presents each UDP flow as a
// byte stream (conn.StreamBind re-frames packets with a length prefix), so UDP
// slots into the same abstraction as stream transports like REALITY.
//
// NOTE: the production WireGuard UDP data path is conn.Bind/StdNetBind and is
// unaffected by this type. This implementation turns datagrams into a stream and
// is therefore reliable only over a lossless link (a lost datagram desynchronises
// the length framing); it exists for a uniform transport abstraction and testing.
type UDP struct{}

// NewUDP returns a UDP transport.
func NewUDP() *UDP { return &UDP{} }

func (UDP) Dial(ctx context.Context, dest string) (net.Conn, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "udp", dest)
	if err != nil {
		return nil, err
	}
	uc := c.(*net.UDPConn)
	return &packetStream{
		readDatagram: func() ([]byte, error) {
			buf := make([]byte, 65535)
			n, err := uc.Read(buf)
			if err != nil {
				return nil, err
			}
			return buf[:n], nil
		},
		writeDatagram: func(p []byte) (int, error) { return uc.Write(p) },
		closer:        uc,
		local:         uc.LocalAddr(),
		remote:        uc.RemoteAddr(),
	}, nil
}

func (UDP) Listen(laddr string) (net.Listener, error) {
	addr, err := net.ResolveUDPAddr("udp", laddr)
	if err != nil {
		return nil, err
	}
	pc, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}
	l := &udpListener{
		pc:      pc,
		accept:  make(chan *packetStream, 16),
		conns:   make(map[string]*packetStream),
		closing: make(chan struct{}),
	}
	go l.readLoop()
	return l, nil
}

// udpListener demultiplexes datagrams from a single UDP socket into one
// packetStream per remote address, presenting a net.Listener.
type udpListener struct {
	pc      *net.UDPConn
	accept  chan *packetStream
	closing chan struct{}

	mu    sync.Mutex
	conns map[string]*packetStream
}

func (l *udpListener) readLoop() {
	buf := make([]byte, 65535)
	for {
		n, raddr, err := l.pc.ReadFromUDP(buf)
		if err != nil {
			l.mu.Lock()
			for _, c := range l.conns {
				close(c.incoming)
			}
			l.conns = map[string]*packetStream{}
			l.mu.Unlock()
			close(l.accept)
			return
		}
		key := raddr.String()
		l.mu.Lock()
		c, ok := l.conns[key]
		if !ok {
			c = l.newServerConn(raddr, key)
			l.conns[key] = c
		}
		l.mu.Unlock()

		if !ok {
			select {
			case l.accept <- c:
			case <-l.closing:
				return
			}
		}

		data := make([]byte, n)
		copy(data, buf[:n])
		select {
		case c.incoming <- data:
		case <-l.closing:
			return
		default: // drop if the per-conn buffer is full
		}
	}
}

func (l *udpListener) newServerConn(raddr *net.UDPAddr, key string) *packetStream {
	c := &packetStream{
		incoming: make(chan []byte, 64),
		writeDatagram: func(p []byte) (int, error) {
			return l.pc.WriteToUDP(p, raddr)
		},
		closer: closeFunc(func() error {
			l.mu.Lock()
			delete(l.conns, key)
			l.mu.Unlock()
			return nil
		}),
		local:  l.pc.LocalAddr(),
		remote: raddr,
	}
	c.readDatagram = c.readFromChan
	return c
}

func (l *udpListener) Accept() (net.Conn, error) {
	c, ok := <-l.accept
	if !ok {
		return nil, net.ErrClosed
	}
	return c, nil
}

func (l *udpListener) Close() error {
	select {
	case <-l.closing:
	default:
		close(l.closing)
	}
	return l.pc.Close()
}

func (l *udpListener) Addr() net.Addr { return l.pc.LocalAddr() }

// packetStream adapts a datagram flow to a net.Conn byte stream. Reads serve
// bytes from the current datagram, refilling from the source when drained.
type packetStream struct {
	readDatagram  func() ([]byte, error)
	writeDatagram func(p []byte) (int, error)
	closer        interface{ Close() error }
	incoming      chan []byte // used by server-side conns
	local, remote net.Addr

	rbuf []byte
}

func (s *packetStream) readFromChan() ([]byte, error) {
	d, ok := <-s.incoming
	if !ok {
		return nil, net.ErrClosed
	}
	return d, nil
}

func (s *packetStream) Read(p []byte) (int, error) {
	for len(s.rbuf) == 0 {
		d, err := s.readDatagram()
		if err != nil {
			return 0, err
		}
		s.rbuf = d
	}
	n := copy(p, s.rbuf)
	s.rbuf = s.rbuf[n:]
	return n, nil
}

func (s *packetStream) Write(p []byte) (int, error) { return s.writeDatagram(p) }

func (s *packetStream) Close() error {
	if s.closer != nil {
		return s.closer.Close()
	}
	return nil
}

func (s *packetStream) LocalAddr() net.Addr  { return s.local }
func (s *packetStream) RemoteAddr() net.Addr { return s.remote }

var errDeadlineUnsupported = errors.New("transport/udp: deadlines not supported on demuxed conn")

func (s *packetStream) SetDeadline(t time.Time) error {
	if uc, ok := s.closer.(*net.UDPConn); ok {
		return uc.SetDeadline(t)
	}
	return errDeadlineUnsupported
}

func (s *packetStream) SetReadDeadline(t time.Time) error {
	if uc, ok := s.closer.(*net.UDPConn); ok {
		return uc.SetReadDeadline(t)
	}
	return errDeadlineUnsupported
}

func (s *packetStream) SetWriteDeadline(t time.Time) error {
	if uc, ok := s.closer.(*net.UDPConn); ok {
		return uc.SetWriteDeadline(t)
	}
	return errDeadlineUnsupported
}

type closeFunc func() error

func (f closeFunc) Close() error { return f() }
