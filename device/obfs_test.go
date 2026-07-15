/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/conn/bindtest"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

// genObfsTestPair builds a connected device pair over the in-memory channel
// transport with each bind wrapped in a conn.ObfsBind. keys[i] is the hex
// obfuscation key for device i ("" leaves obfuscation disabled on that side).
// The channel transport is used (rather than real UDP sockets) so the test is
// independent of kernel UDP-offload support.
func genObfsTestPair(tb testing.TB, keys [2]string) (pair testPair) {
	cfg, endpointCfg := genConfigs(tb)
	inner := bindtest.NewChannelBinds()
	for i := range pair {
		p := &pair[i]
		bind := conn.NewObfsBind(inner[i])
		p.tun = tuntest.NewChannelTUN()
		p.ip = netip.AddrFrom4([4]byte{1, 0, 0, byte(i + 1)})
		p.dev = NewDevice(p.tun.TUN(), bind, NewLogger(LogLevelError, fmt.Sprintf("dev%d: ", i)))
		if err := p.dev.IpcSet(cfg[i]); err != nil {
			tb.Fatalf("failed to configure device %d: %v", i, err)
		}
		if keys[i] != "" {
			if err := p.dev.IpcSet("obfs_key=" + keys[i] + "\n"); err != nil {
				tb.Fatalf("failed to set obfs key on device %d: %v", i, err)
			}
		}
		if err := p.dev.Up(); err != nil {
			tb.Fatalf("failed to bring up device %d: %v", i, err)
		}
		endpointCfg[i^1] = fmt.Sprintf(endpointCfg[i^1], p.dev.net.port)
	}
	for i := range pair {
		p := &pair[i]
		if err := p.dev.IpcSet(endpointCfg[i]); err != nil {
			tb.Fatalf("failed to configure device endpoint %d: %v", i, err)
		}
		tb.Cleanup(p.dev.Close)
	}
	return
}

const obfsTestKey = "0f1e2d3c4b5a69788796a5b4c3d2e1f00112233445566778899aabbccddeeff0"

// TestTwoDeviceObfuscatedPing verifies that a handshake completes and traffic
// round-trips end-to-end when both peers run the obfuscation layer with a matching
// key, with obfuscation applied to every datagram.
func TestTwoDeviceObfuscatedPing(t *testing.T) {
	pair := genObfsTestPair(t, [2]string{obfsTestKey, obfsTestKey})
	t.Run("ping 1.0.0.1", func(t *testing.T) {
		pair.Send(t, Ping, nil)
	})
	t.Run("ping 1.0.0.2", func(t *testing.T) {
		pair.Send(t, Pong, nil)
	})
}

// TestObfuscatedKeyMismatch verifies that peers with different obfuscation keys
// cannot complete a handshake: the responder fails to de-obfuscate the initiator's
// datagrams and drops them, so no traffic transits.
func TestObfuscatedKeyMismatch(t *testing.T) {
	otherKey := "ffeeddccbbaa99887766554433221100f0e1d2c3b4a5968778695a4b3c2d1e0f"
	pair := genObfsTestPair(t, [2]string{obfsTestKey, otherKey})

	msg := tuntest.Ping(pair[1].ip, pair[0].ip)
	pair[1].tun.Outbound <- msg
	select {
	case <-pair[0].tun.Inbound:
		t.Fatal("packet transited despite mismatched obfuscation keys")
	case <-time.After(time.Second):
		// expected: handshake never completes, nothing arrives
	}
}
