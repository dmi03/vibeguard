/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"bytes"
	"net/netip"
	"sync"
	"testing"
)

func TestObfuscatorRoundTrip(t *testing.T) {
	o := newObfuscator(ObfsConfig{Key: DeriveObfsKey("correct horse battery staple")})
	cases := []struct {
		plain []byte
		pad   int
	}{
		{[]byte{}, 0},
		{[]byte{0x01, 0x00, 0x00, 0x00}, 0},
		{[]byte{0x04, 0x00, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef}, 200},
		{bytes.Repeat([]byte{0xaa}, 1420), 16},
	}
	for i, c := range cases {
		wire, err := o.seal(nil, c.plain, c.pad)
		if err != nil {
			t.Fatalf("case %d: seal: %v", i, err)
		}
		if len(wire) != obfsSaltSize+obfsLenSize+len(c.plain)+c.pad+obfsTagSize {
			t.Fatalf("case %d: unexpected wire length %d", i, len(wire))
		}
		// The bytes after the salt must not reveal the plaintext prefix.
		if len(c.plain) > 0 && bytes.Contains(wire[obfsSaltSize:], c.plain) {
			t.Fatalf("case %d: plaintext leaked into ciphertext", i)
		}
		got, err := o.open(nil, wire)
		if err != nil {
			t.Fatalf("case %d: open: %v", i, err)
		}
		if !bytes.Equal(got, c.plain) {
			t.Fatalf("case %d: got %x want %x", i, got, c.plain)
		}
	}
}

func TestObfuscatorWrongKey(t *testing.T) {
	a := newObfuscator(ObfsConfig{Key: DeriveObfsKey("alpha")})
	b := newObfuscator(ObfsConfig{Key: DeriveObfsKey("bravo")})
	wire, err := a.seal(nil, []byte("hello wireguard"), 32)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.open(nil, wire); err != errObfsAuth {
		t.Fatalf("expected auth failure with wrong key, got %v", err)
	}
}

func TestObfuscatorRejectsGarbage(t *testing.T) {
	o := newObfuscator(ObfsConfig{Key: DeriveObfsKey("k")})
	if _, err := o.open(nil, []byte{1, 2, 3}); err != errObfsShort {
		t.Fatalf("short datagram: got %v", err)
	}
	garbage := make([]byte, 200)
	// crypto/rand-free deterministic garbage; will fail the Poly1305 tag.
	for i := range garbage {
		garbage[i] = byte(i)
	}
	if _, err := o.open(nil, garbage); err != errObfsAuth {
		t.Fatalf("garbage datagram: got %v", err)
	}
}

func TestPadBudgetByType(t *testing.T) {
	o := newObfuscator(ObfsConfig{
		Key:             DeriveObfsKey("k"),
		PadHandshakeMax: 100,
		PadDataMax:      0,
	})
	// Transport packets (type 4) get no padding by config.
	if got := o.padBudget([]byte{0x04, 0, 0, 0}); got != 0 {
		t.Fatalf("transport pad = %d, want 0", got)
	}
	// Handshake packets (types 1..3) get padding within [0, PadHandshakeMax].
	for _, typ := range []byte{1, 2, 3} {
		for i := 0; i < 50; i++ {
			p := o.padBudget([]byte{typ, 0, 0, 0})
			if p < 0 || p > o.cfg.PadHandshakeMax {
				t.Fatalf("handshake pad out of range: %d", p)
			}
		}
	}
}

// memEndpoint is a trivial Endpoint for in-memory bind tests.
type memEndpoint string

func (e memEndpoint) ClearSrc()           {}
func (e memEndpoint) SrcToString() string { return "" }
func (e memEndpoint) DstToString() string { return string(e) }
func (e memEndpoint) DstToBytes() []byte  { return []byte(e) }
func (e memEndpoint) DstIP() netip.Addr   { return netip.Addr{} }
func (e memEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }

// fakeBind is an in-memory Bind: Send enqueues datagrams that the ReceiveFunc
// later dequeues, modelling a loopback link.
type fakeBind struct {
	mu sync.Mutex
	q  [][]byte
}

func (f *fakeBind) Open(port uint16) ([]ReceiveFunc, uint16, error) {
	return []ReceiveFunc{f.receive}, port, nil
}

func (f *fakeBind) receive(packets [][]byte, sizes []int, eps []Endpoint) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for len(f.q) > 0 && n < len(packets) {
		d := f.q[0]
		f.q = f.q[1:]
		copy(packets[n], d)
		sizes[n] = len(d)
		eps[n] = memEndpoint("peer")
		n++
	}
	return n, nil
}

func (f *fakeBind) Send(bufs [][]byte, ep Endpoint) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, b := range bufs {
		f.q = append(f.q, append([]byte(nil), b...))
	}
	return nil
}

func (f *fakeBind) Close() error                             { return nil }
func (f *fakeBind) SetMark(uint32) error                     { return nil }
func (f *fakeBind) ParseEndpoint(s string) (Endpoint, error) { return memEndpoint(s), nil }
func (f *fakeBind) BatchSize() int                           { return 1 }

func drain(t *testing.T, recv ReceiveFunc) (out [][]byte) {
	t.Helper()
	const cap = 64
	packets := make([][]byte, cap)
	for i := range packets {
		packets[i] = make([]byte, 4096)
	}
	sizes := make([]int, cap)
	eps := make([]Endpoint, cap)
	n, err := recv(packets, sizes, eps)
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	for i := 0; i < n; i++ {
		if sizes[i] == 0 {
			continue // dropped decoy/probe
		}
		out = append(out, append([]byte(nil), packets[i][:sizes[i]]...))
	}
	return out
}

func TestObfsBindRoundTrip(t *testing.T) {
	inner := &fakeBind{}
	b := NewObfsBind(inner)
	b.SetKey(DeriveObfsKey("shared secret"))

	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatal(err)
	}

	orig := []byte{0x01, 0x00, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef} // resembles a handshake init
	if err := b.Send([][]byte{orig}, memEndpoint("peer")); err != nil {
		t.Fatal(err)
	}

	got := drain(t, fns[0])
	if len(got) != 1 {
		t.Fatalf("recovered %d real packets, want 1 (decoys should be dropped)", len(got))
	}
	if !bytes.Equal(got[0], orig) {
		t.Fatalf("recovered %x, want %x", got[0], orig)
	}
}

func TestObfsBindDropsDecoys(t *testing.T) {
	inner := &fakeBind{}
	b := NewObfsBind(inner)
	// Force several decoys and no real data.
	b.update(func(c *ObfsConfig) {
		c.Key = DeriveObfsKey("k")
		c.JunkMin, c.JunkMax = 4, 4
		c.JunkSizeMin, c.JunkSizeMax = 60, 60
	})
	fns, _, _ := b.Open(0)
	if err := b.Send([][]byte{{0x04, 0, 0, 0, 1, 2, 3, 4}}, memEndpoint("peer")); err != nil {
		t.Fatal(err)
	}
	// 4 decoys were enqueued before the real packet; only the real one survives.
	inner.mu.Lock()
	queued := len(inner.q)
	inner.mu.Unlock()
	if queued != 5 {
		t.Fatalf("queued %d datagrams, want 5 (4 decoys + 1 real)", queued)
	}
	got := drain(t, fns[0])
	if len(got) != 1 {
		t.Fatalf("recovered %d real packets, want 1", len(got))
	}
}

func TestObfsBindDisabledPassthrough(t *testing.T) {
	inner := &fakeBind{}
	b := NewObfsBind(inner) // no key -> disabled

	orig := []byte{1, 2, 3, 4, 5}
	if err := b.Send([][]byte{orig}, memEndpoint("peer")); err != nil {
		t.Fatal(err)
	}
	inner.mu.Lock()
	if len(inner.q) != 1 || !bytes.Equal(inner.q[0], orig) {
		inner.mu.Unlock()
		t.Fatalf("send not a byte-identical pass-through")
	}
	inner.mu.Unlock()

	fns, _, _ := b.Open(0)
	got := drain(t, fns[0])
	if len(got) != 1 || !bytes.Equal(got[0], orig) {
		t.Fatalf("receive not a byte-identical pass-through: %v", got)
	}
}
