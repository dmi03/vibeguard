/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

// This file implements vibeguard's native traffic-obfuscation layer. Its purpose
// is to make WireGuard datagrams unclassifiable to DPI systems (e.g. Russia's
// TSPU/RKN) that fingerprint WireGuard by its fixed message-type bytes, its fixed
// handshake sizes (148/92/64), and its constant field layout.
//
// The scheme wraps every datagram in an AEAD envelope keyed by a pre-shared
// obfuscation key. After the random salt, the entire UDP payload is ciphertext,
// so there are no magic bytes, no zero fields, and (with padding) no fixed sizes.
// This is a *masking* layer only: WireGuard's Noise handshake remains the real
// security boundary. The key just makes packets opaque and defeats active probing
// (a censor without the key cannot forge an authenticating datagram, so the port
// silently blackholes probes and never reveals a WireGuard fingerprint).

package conn

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	mrand "math/rand/v2"
	"sync"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	obfsSaltSize = chacha20poly1305.NonceSizeX // 24, per-packet random nonce
	obfsTagSize  = chacha20poly1305.Overhead   // 16, Poly1305 tag
	obfsLenSize  = 2                           // real plaintext length header

	// ObfsOverhead is the constant number of bytes the obfuscation layer adds to
	// each datagram, excluding random padding. Used to advise a reduced MTU.
	ObfsOverhead = obfsSaltSize + obfsLenSize + obfsTagSize // 42

	obfsMaxPlaintext = 1<<16 - 1
)

var (
	errObfsAuth  = errors.New("obfs: authentication failed")
	errObfsShort = errors.New("obfs: datagram too short")
	errObfsLen   = errors.New("obfs: invalid length header")
)

// ObfsConfig configures the obfuscation layer. A zero Key means obfuscation is
// disabled and the bind passes datagrams through unchanged, keeping the fork a
// drop-in, wire-compatible wireguard-go.
type ObfsConfig struct {
	Key             [32]byte
	JunkMin         int // min number of decoy packets before a fresh handshake
	JunkMax         int // max number of decoy packets
	JunkSizeMin     int // min decoy datagram size (bytes)
	JunkSizeMax     int // max decoy datagram size (bytes)
	PadHandshakeMax int // max random padding for handshake/cookie packets
	PadDataMax      int // max random padding for transport packets
}

func (c *ObfsConfig) enabled() bool {
	return c != nil && c.Key != [32]byte{}
}

// normalize fills unset fields with sensible defaults. An all-zero junk range is
// treated as "unset" and defaulted; sizes and handshake padding default when zero.
func (c *ObfsConfig) normalize() {
	if c.JunkMin == 0 && c.JunkMax == 0 {
		c.JunkMin, c.JunkMax = 2, 5
	}
	if c.JunkMin < 0 {
		c.JunkMin = 0
	}
	if c.JunkMax < c.JunkMin {
		c.JunkMax = c.JunkMin
	}
	if c.JunkSizeMin <= 0 {
		c.JunkSizeMin = 40
	}
	if c.JunkSizeMax < c.JunkSizeMin {
		c.JunkSizeMax = c.JunkSizeMin
		if c.JunkSizeMax < 1200 {
			c.JunkSizeMax = 1200
		}
	}
	if c.PadHandshakeMax == 0 {
		c.PadHandshakeMax = 256
	}
	if c.PadHandshakeMax < 0 {
		c.PadHandshakeMax = 0
	}
	if c.PadDataMax < 0 {
		c.PadDataMax = 0
	}
}

// DeriveObfsKey derives a 32-byte obfuscation key from a human-friendly password.
// Both peers must derive the same key from the same password.
func DeriveObfsKey(password string) [32]byte {
	h, _ := blake2s.New256(nil)
	h.Write([]byte("vibeguard-obfs-v1"))
	h.Write([]byte{0})
	h.Write([]byte(password))
	var k [32]byte
	h.Sum(k[:0])
	return k
}

// obfuscator holds an immutable, normalized config plus its AEAD and scratch pool.
// A cipher.AEAD from chacha20poly1305 is safe for concurrent use.
type obfuscator struct {
	aead    cipher.AEAD
	cfg     ObfsConfig
	scratch sync.Pool
}

func newObfuscator(cfg ObfsConfig) *obfuscator {
	cfg.normalize()
	aead, _ := chacha20poly1305.NewX(cfg.Key[:])
	o := &obfuscator{aead: aead, cfg: cfg}
	o.scratch.New = func() any {
		b := make([]byte, 0, 2048)
		return &b
	}
	return o
}

func (o *obfuscator) getScratch(n int) *[]byte {
	p := o.scratch.Get().(*[]byte)
	if cap(*p) < n {
		*p = make([]byte, n)
	}
	*p = (*p)[:n]
	return p
}

func (o *obfuscator) putScratch(p *[]byte) {
	o.scratch.Put(p)
}

// seal wraps plaintext into an obfuscated datagram written into dst[:0] (growing
// dst if needed) and returns it. pad random padding bytes are added inside the
// encrypted region so they are invisible on the wire.
func (o *obfuscator) seal(dst, plaintext []byte, pad int) ([]byte, error) {
	n := len(plaintext)
	if n > obfsMaxPlaintext {
		return nil, errObfsLen
	}
	if pad < 0 {
		pad = 0
	}
	msgLen := obfsLenSize + n + pad
	total := obfsSaltSize + msgLen + obfsTagSize
	if cap(dst) < total {
		dst = make([]byte, 0, total)
	}
	dst = dst[:obfsSaltSize]
	if _, err := rand.Read(dst); err != nil {
		return nil, err
	}
	var nonce [obfsSaltSize]byte
	copy(nonce[:], dst)

	p := o.getScratch(msgLen)
	msg := *p
	binary.BigEndian.PutUint16(msg, uint16(n))
	copy(msg[obfsLenSize:], plaintext)
	if pad > 0 {
		if _, err := rand.Read(msg[obfsLenSize+n:]); err != nil {
			o.putScratch(p)
			return nil, err
		}
	}
	out := o.aead.Seal(dst, nonce[:], msg, nil)
	o.putScratch(p)
	return out, nil
}

// open de-obfuscates a wire datagram into dst[:0] and returns the original
// WireGuard datagram. It returns an error (silently dropped by the caller) for
// decoy packets and probes that fail authentication.
func (o *obfuscator) open(dst, wire []byte) ([]byte, error) {
	if len(wire) < obfsSaltSize+obfsTagSize+obfsLenSize {
		return nil, errObfsShort
	}
	var nonce [obfsSaltSize]byte
	copy(nonce[:], wire[:obfsSaltSize])
	ct := wire[obfsSaltSize:]

	p := o.getScratch(len(ct) - obfsTagSize)
	plain, err := o.aead.Open((*p)[:0], nonce[:], ct, nil)
	if err != nil {
		o.putScratch(p)
		return nil, errObfsAuth
	}
	if len(plain) < obfsLenSize {
		o.putScratch(p)
		return nil, errObfsShort
	}
	n := int(binary.BigEndian.Uint16(plain))
	if n > len(plain)-obfsLenSize {
		o.putScratch(p)
		return nil, errObfsLen
	}
	dst = append(dst[:0], plain[obfsLenSize:obfsLenSize+n]...)
	o.putScratch(p)
	return dst, nil
}

// padBudget returns a random padding size for a plaintext WireGuard datagram,
// larger for the rare handshake/cookie packets (whose fixed sizes are the strong
// fingerprint) and small/none for throughput-sensitive transport packets.
func (o *obfuscator) padBudget(plaintext []byte) int {
	max := o.cfg.PadDataMax
	if len(plaintext) >= 1 {
		switch plaintext[0] {
		case 1, 2, 3: // MessageInitiation / Response / CookieReply
			max = o.cfg.PadHandshakeMax
		}
	}
	if max <= 0 {
		return 0
	}
	return randIntn(max + 1)
}

func (o *obfuscator) decoyCount() int {
	lo, hi := o.cfg.JunkMin, o.cfg.JunkMax
	if hi <= 0 {
		return 0
	}
	return lo + randIntn(hi-lo+1)
}

// makeDecoy fills dst with a random-sized, random-content datagram that the peer
// will fail to authenticate and silently drop.
func (o *obfuscator) makeDecoy(dst []byte) []byte {
	lo, hi := o.cfg.JunkSizeMin, o.cfg.JunkSizeMax
	if lo < 1 {
		lo = 1
	}
	size := lo + randIntn(hi-lo+1)
	if cap(dst) < size {
		dst = make([]byte, size)
	}
	dst = dst[:size]
	rand.Read(dst)
	return dst
}

func randIntn(n int) int {
	if n <= 1 {
		return 0
	}
	return mrand.IntN(n)
}
