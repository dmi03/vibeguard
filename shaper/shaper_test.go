/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package shaper

import (
	"testing"
	"time"
)

func TestDisabledIsNoop(t *testing.T) {
	s := New()
	start := time.Now()
	for i := 0; i < 100; i++ {
		s.Pace(1200)
	}
	if elapsed := time.Since(start); elapsed > 20*time.Millisecond {
		t.Fatalf("disabled shaper introduced delay: %v", elapsed)
	}
	if s.Enabled() {
		t.Fatal("shaper reports enabled without config")
	}
}

func TestJitterWithinBounds(t *testing.T) {
	s := New()
	s.SetConfig(Config{Enabled: true, JitterMinMs: 5, JitterMaxMs: 15})
	if !s.Enabled() {
		t.Fatal("shaper should be enabled")
	}
	for i := 0; i < 5; i++ {
		start := time.Now()
		s.Pace(1200)
		d := time.Since(start)
		if d < 4*time.Millisecond || d > 60*time.Millisecond {
			t.Fatalf("pace delay %v outside expected jitter bounds", d)
		}
	}
}

func TestRateCapDelays(t *testing.T) {
	s := New()
	// 10 KB/s, no jitter. The first ~1s burst is free; beyond that, sending
	// another 10 KB must take on the order of a second.
	s.SetConfig(Config{Enabled: true, RateBytesPerSec: 10000})
	s.Pace(10000) // consume the initial burst
	start := time.Now()
	s.Pace(10000)
	if d := time.Since(start); d < 500*time.Millisecond {
		t.Fatalf("rate cap did not delay: %v", d)
	}
}
