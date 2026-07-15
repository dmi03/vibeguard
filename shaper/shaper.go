/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

// Package shaper implements an egress traffic shaper used to make a tunnelled
// flow resist traffic-analysis. It operates purely on the send side (no changes
// to the WireGuard core): it paces outbound packets with randomized jitter,
// optionally caps the egress byte-rate to break the perfectly-symmetric
// upload/download profile typical of a VPN, and adds extra jitter to small
// (keepalive-sized) packets so keepalive timing is not a clean periodic signal.
package shaper

import (
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"
)

// Config configures the shaper. A zero/absent config (Enabled == false) makes
// every method a no-op pass-through.
type Config struct {
	Enabled bool

	JitterMinMs int // minimum per-packet delay (ms)
	JitterMaxMs int // maximum per-packet delay (ms)

	// KeepaliveJitterMs adds up to this many extra ms of delay to small packets
	// (<= SmallPacketMax bytes), so keepalives are not cleanly periodic.
	KeepaliveJitterMs int
	SmallPacketMax    int // byte threshold for "small"/keepalive packets

	// RateBytesPerSec caps the egress byte-rate (token bucket). 0 = unlimited.
	RateBytesPerSec int
}

func (c *Config) normalize() {
	if c.JitterMinMs < 0 {
		c.JitterMinMs = 0
	}
	if c.JitterMaxMs < c.JitterMinMs {
		c.JitterMaxMs = c.JitterMinMs
	}
	if c.KeepaliveJitterMs < 0 {
		c.KeepaliveJitterMs = 0
	}
	if c.SmallPacketMax <= 0 {
		c.SmallPacketMax = 64
	}
	if c.RateBytesPerSec < 0 {
		c.RateBytesPerSec = 0
	}
}

// Shaper paces outbound packets. It is safe for concurrent use.
type Shaper struct {
	cfg atomic.Pointer[Config]

	setMu   sync.Mutex // guards working (incremental config building)
	working Config

	mu     sync.Mutex // guards the token bucket
	tokens float64
	last   time.Time
}

// New returns a disabled shaper.
func New() *Shaper {
	return &Shaper{}
}

// SetConfig applies cfg wholesale. Enabled==false disables shaping.
func (s *Shaper) SetConfig(cfg Config) {
	s.setMu.Lock()
	s.working = cfg
	s.setMu.Unlock()
	cfg.normalize()
	s.cfg.Store(&cfg)
}

// update mutates the working config incrementally and republishes it.
func (s *Shaper) update(mut func(c *Config)) {
	s.setMu.Lock()
	mut(&s.working)
	cfg := s.working
	s.setMu.Unlock()
	cfg.normalize()
	s.cfg.Store(&cfg)
}

func (s *Shaper) SetEnabled(v bool)          { s.update(func(c *Config) { c.Enabled = v }) }
func (s *Shaper) SetJitterMinMs(v int)       { s.update(func(c *Config) { c.JitterMinMs = v }) }
func (s *Shaper) SetJitterMaxMs(v int)       { s.update(func(c *Config) { c.JitterMaxMs = v }) }
func (s *Shaper) SetKeepaliveJitterMs(v int) { s.update(func(c *Config) { c.KeepaliveJitterMs = v }) }
func (s *Shaper) SetSmallPacketMax(v int)    { s.update(func(c *Config) { c.SmallPacketMax = v }) }
func (s *Shaper) SetRateBytesPerSec(v int)   { s.update(func(c *Config) { c.RateBytesPerSec = v }) }

// Enabled reports whether shaping is currently active.
func (s *Shaper) Enabled() bool {
	c := s.cfg.Load()
	return c != nil && c.Enabled
}

// Pace blocks for the shaping delay appropriate to a packet of n bytes: an
// optional token-bucket wait to honour the egress rate cap, plus randomized
// jitter (with extra jitter for small/keepalive packets). It is a no-op when
// the shaper is disabled.
func (s *Shaper) Pace(n int) {
	c := s.cfg.Load()
	if c == nil || !c.Enabled {
		return
	}

	if d := s.rateDelay(c, n); d > 0 {
		time.Sleep(d)
	}

	jitter := c.JitterMaxMs - c.JitterMinMs
	delayMs := c.JitterMinMs
	if jitter > 0 {
		delayMs += rand.IntN(jitter + 1)
	}
	if n <= c.SmallPacketMax && c.KeepaliveJitterMs > 0 {
		delayMs += rand.IntN(c.KeepaliveJitterMs + 1)
	}
	if delayMs > 0 {
		time.Sleep(time.Duration(delayMs) * time.Millisecond)
	}
}

// rateDelay returns how long to wait so that emitting n bytes respects the
// configured egress rate, updating the token bucket.
func (s *Shaper) rateDelay(c *Config, n int) time.Duration {
	rate := float64(c.RateBytesPerSec)
	if rate <= 0 {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	if s.last.IsZero() {
		s.last = now
		s.tokens = rate // start with a one-second burst
	}
	s.tokens += now.Sub(s.last).Seconds() * rate
	if s.tokens > rate {
		s.tokens = rate // cap burst at one second's worth
	}
	s.last = now

	s.tokens -= float64(n)
	if s.tokens >= 0 {
		return 0
	}
	// Not enough tokens: wait for the deficit to refill.
	return time.Duration(-s.tokens / rate * float64(time.Second))
}
