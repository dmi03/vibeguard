/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/shaper"
)

// ObfsBind wraps any conn.Bind and transparently applies vibeguard's obfuscation
// layer (see obfs.go) to every datagram. Because it operates at the datagram
// boundary, GSO/GRO in the inner bind and the entire device/noise stack remain
// untouched. When no key is configured it is a pass-through.
type ObfsBind struct {
	inner Bind

	mu  sync.Mutex // guards cfg (the working configuration)
	cfg ObfsConfig

	ob atomic.Pointer[obfuscator] // nil => disabled/pass-through

	lastSend sync.Map // endpoint DstToString -> last send time (unixnano), for decoys
}

// obfsDecoyIdle is how long an endpoint must be silent before the next Send is
// treated as a fresh flow that gets decoy packets prepended.
const obfsDecoyIdle = 30 * time.Second

var (
	_ Bind = (*ObfsBind)(nil)

	obfsBufPool = sync.Pool{
		New: func() any {
			b := make([]byte, 0, 2048)
			return &b
		},
	}
)

// NewObfsBind wraps inner with an obfuscation layer that is initially disabled.
func NewObfsBind(inner Bind) *ObfsBind {
	return &ObfsBind{inner: inner}
}

// update mutates the working config under lock and republishes the obfuscator.
func (b *ObfsBind) update(mut func(c *ObfsConfig)) {
	b.mu.Lock()
	mut(&b.cfg)
	cfg := b.cfg
	b.mu.Unlock()
	if cfg.enabled() {
		b.ob.Store(newObfuscator(cfg))
	} else {
		b.ob.Store(nil)
	}
}

// SetKey sets the pre-shared obfuscation key and enables obfuscation. A zero key
// disables it.
func (b *ObfsBind) SetKey(k [32]byte) { b.update(func(c *ObfsConfig) { c.Key = k }) }

func (b *ObfsBind) SetJunkMin(v int)         { b.update(func(c *ObfsConfig) { c.JunkMin = v }) }
func (b *ObfsBind) SetJunkMax(v int)         { b.update(func(c *ObfsConfig) { c.JunkMax = v }) }
func (b *ObfsBind) SetJunkSizeMin(v int)     { b.update(func(c *ObfsConfig) { c.JunkSizeMin = v }) }
func (b *ObfsBind) SetJunkSizeMax(v int)     { b.update(func(c *ObfsConfig) { c.JunkSizeMax = v }) }
func (b *ObfsBind) SetPadHandshakeMax(v int) { b.update(func(c *ObfsConfig) { c.PadHandshakeMax = v }) }
func (b *ObfsBind) SetPadDataMax(v int)      { b.update(func(c *ObfsConfig) { c.PadDataMax = v }) }

// Enabled reports whether obfuscation is currently active.
func (b *ObfsBind) Enabled() bool { return b.ob.Load() != nil }

func (b *ObfsBind) Open(port uint16) ([]ReceiveFunc, uint16, error) {
	fns, actual, err := b.inner.Open(port)
	if err != nil {
		return nil, 0, err
	}
	wrapped := make([]ReceiveFunc, len(fns))
	for i := range fns {
		wrapped[i] = b.wrapReceive(fns[i])
	}
	return wrapped, actual, nil
}

func (b *ObfsBind) wrapReceive(fn ReceiveFunc) ReceiveFunc {
	return func(packets [][]byte, sizes []int, eps []Endpoint) (int, error) {
		n, err := fn(packets, sizes, eps)
		if err != nil {
			return n, err
		}
		o := b.ob.Load()
		if o == nil {
			return n, nil
		}
		for i := 0; i < n; i++ {
			if sizes[i] == 0 {
				continue
			}
			plain, derr := o.open(packets[i][:0], packets[i][:sizes[i]])
			if derr != nil {
				// Decoy or probe: drop it. RoutineReceiveIncoming skips any
				// datagram whose size is below MinMessageSize.
				sizes[i] = 0
				continue
			}
			sizes[i] = len(plain)
		}
		return n, nil
	}
}

func (b *ObfsBind) Send(bufs [][]byte, ep Endpoint) error {
	o := b.ob.Load()
	if o == nil {
		return b.inner.Send(bufs, ep)
	}

	b.maybeSendDecoys(o, ep)

	sealed := make([][]byte, 0, len(bufs))
	ptrs := make([]*[]byte, 0, len(bufs))
	defer func() {
		for _, p := range ptrs {
			obfsBufPool.Put(p)
		}
	}()
	for _, buf := range bufs {
		p := obfsBufPool.Get().(*[]byte)
		s, err := o.seal((*p)[:0], buf, o.padBudget(buf))
		if err != nil {
			return err
		}
		*p = s
		ptrs = append(ptrs, p)
		sealed = append(sealed, s)
	}
	return b.inner.Send(sealed, ep)
}

// maybeSendDecoys emits a random number of random-content decoy datagrams before
// the first packet of a fresh or long-idle flow (which is always a handshake
// initiation), breaking the "first UDP packet is 148 bytes" heuristic and adding
// cover traffic. Decoy count/size are local decisions and need not match the peer.
func (b *ObfsBind) maybeSendDecoys(o *obfuscator, ep Endpoint) {
	key := ep.DstToString()
	now := time.Now().UnixNano()
	prevAny, existed := b.lastSend.Swap(key, now)
	if o.cfg.JunkMax <= 0 {
		return
	}
	if existed && now-prevAny.(int64) < int64(obfsDecoyIdle) {
		return // active flow; no decoys
	}
	count := o.decoyCount()
	for i := 0; i < count; i++ {
		p := obfsBufPool.Get().(*[]byte)
		*p = o.makeDecoy((*p)[:0])
		// Errors on decoys are irrelevant; they are cover traffic.
		_ = b.inner.Send([][]byte{*p}, ep)
		obfsBufPool.Put(p)
	}
}

// Shaper returns the egress shaper of the wrapped bind, if any, so the UAPI can
// reach it through the ObfsBind wrapper.
func (b *ObfsBind) Shaper() *shaper.Shaper {
	if s, ok := b.inner.(interface{ Shaper() *shaper.Shaper }); ok {
		return s.Shaper()
	}
	return nil
}

func (b *ObfsBind) Close() error                             { return b.inner.Close() }
func (b *ObfsBind) SetMark(mark uint32) error                { return b.inner.SetMark(mark) }
func (b *ObfsBind) ParseEndpoint(s string) (Endpoint, error) { return b.inner.ParseEndpoint(s) }
func (b *ObfsBind) BatchSize() int                           { return b.inner.BatchSize() }
