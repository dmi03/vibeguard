/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/shaper"
	"golang.zx2c4.com/wireguard/transport"
)

// Transport and shaper environment variables. These select and configure the
// pluggable transport (default UDP, or REALITY) and the egress shaper. The same
// settings can be applied over the extended UAPI (see device/uapi.go).
const (
	ENV_WG_TRANSPORT = "WG_TRANSPORT" // "udp" (default) or "reality"
	ENV_WG_ROLE      = "WG_ROLE"      // "server" or "client" (inferred if unset)

	ENV_WG_REALITY_SERVER      = "WG_REALITY_SERVER"      // client: server address to dial (host:port)
	ENV_WG_REALITY_DEST        = "WG_REALITY_DEST"        // server: camouflage target (host:port, TLS 1.3)
	ENV_WG_REALITY_SERVERNAMES = "WG_REALITY_SERVERNAMES" // comma-separated SNIs (server); single SNI (client)
	ENV_WG_REALITY_PRIVATE_KEY = "WG_REALITY_PRIVATE_KEY" // server X25519 private key (hex)
	ENV_WG_REALITY_PUBLIC_KEY  = "WG_REALITY_PUBLIC_KEY"  // client: server X25519 public key (hex)
	ENV_WG_REALITY_SHORT_ID    = "WG_REALITY_SHORT_ID"    // short ID (hex)
	ENV_WG_REALITY_SHORT_IDS   = "WG_REALITY_SHORT_IDS"   // server: comma-separated short IDs (hex)
	ENV_WG_REALITY_FINGERPRINT = "WG_REALITY_FINGERPRINT" // client utls fingerprint (default chrome)

	ENV_WG_SHAPER                = "WG_SHAPER"               // "1"/"true" to enable
	ENV_WG_SHAPER_JITTER_MIN_MS  = "WG_SHAPER_JITTER_MIN_MS" //
	ENV_WG_SHAPER_JITTER_MAX_MS  = "WG_SHAPER_JITTER_MAX_MS" //
	ENV_WG_SHAPER_KEEPALIVE_MS   = "WG_SHAPER_KEEPALIVE_JITTER_MS"
	ENV_WG_SHAPER_SMALL_PKT_MAX  = "WG_SHAPER_SMALL_PACKET_MAX"
	ENV_WG_SHAPER_RATE_BYTES_SEC = "WG_SHAPER_RATE_BYTES_PER_SEC"
)

// newRealityBind builds the REALITY transport bind (StreamBind wrapped by
// ObfsBind, with an egress shaper) when WG_TRANSPORT=reality. It returns (nil,
// nil) when REALITY is not selected, so the caller falls back to the UDP path.
func newRealityBind() (conn.Bind, error) {
	if strings.ToLower(os.Getenv(ENV_WG_TRANSPORT)) != "reality" {
		return nil, nil
	}

	role, cfg, dest, err := realityConfigFromEnv()
	if err != nil {
		return nil, err
	}

	sh := shaper.New()
	if err := configureShaperFromEnv(sh); err != nil {
		return nil, err
	}

	streamBind := conn.NewStreamBind(transport.NewReality(cfg), role, dest, sh)

	// The AEAD obfuscation layer (Phase 1) can still wrap the stream as
	// defense-in-depth; it is a pass-through unless WG_OBFS_* is configured.
	obfsBind := conn.NewObfsBind(streamBind)
	if err := configureObfsFromEnv(obfsBind); err != nil {
		return nil, err
	}
	return obfsBind, nil
}

func realityConfigFromEnv() (conn.StreamRole, transport.RealityConfig, string, error) {
	var cfg transport.RealityConfig
	cfg.Show = os.Getenv("WG_REALITY_SHOW") == "1"
	cfg.Fingerprint = os.Getenv(ENV_WG_REALITY_FINGERPRINT)

	privHex := os.Getenv(ENV_WG_REALITY_PRIVATE_KEY)
	pubHex := os.Getenv(ENV_WG_REALITY_PUBLIC_KEY)

	role, err := realityRole(privHex, pubHex)
	if err != nil {
		return 0, cfg, "", err
	}

	names := splitCSV(os.Getenv(ENV_WG_REALITY_SERVERNAMES))
	if role == conn.RoleServer {
		cfg.Dest = os.Getenv(ENV_WG_REALITY_DEST)
		if cfg.Dest == "" {
			return 0, cfg, "", fmt.Errorf("%s is required for a REALITY server", ENV_WG_REALITY_DEST)
		}
		cfg.ServerNames = names
		cfg.PrivateKey, err = decodeKey(privHex, ENV_WG_REALITY_PRIVATE_KEY)
		if err != nil {
			return 0, cfg, "", err
		}
		cfg.ShortIds = splitCSV(os.Getenv(ENV_WG_REALITY_SHORT_IDS))
		return role, cfg, "", nil
	}

	// client
	dest := os.Getenv(ENV_WG_REALITY_SERVER)
	if dest == "" {
		return 0, cfg, "", fmt.Errorf("%s is required for a REALITY client", ENV_WG_REALITY_SERVER)
	}
	if len(names) > 0 {
		cfg.ServerName = names[0]
	}
	cfg.PublicKey, err = decodeKey(pubHex, ENV_WG_REALITY_PUBLIC_KEY)
	if err != nil {
		return 0, cfg, "", err
	}
	cfg.ShortId = os.Getenv(ENV_WG_REALITY_SHORT_ID)
	return role, cfg, dest, nil
}

func realityRole(privHex, pubHex string) (conn.StreamRole, error) {
	switch strings.ToLower(os.Getenv(ENV_WG_ROLE)) {
	case "server":
		return conn.RoleServer, nil
	case "client":
		return conn.RoleClient, nil
	case "":
		if privHex != "" {
			return conn.RoleServer, nil
		}
		if pubHex != "" {
			return conn.RoleClient, nil
		}
		return 0, fmt.Errorf("set %s=server|client (or %s/%s)", ENV_WG_ROLE, ENV_WG_REALITY_PRIVATE_KEY, ENV_WG_REALITY_PUBLIC_KEY)
	default:
		return 0, fmt.Errorf("%s must be server or client", ENV_WG_ROLE)
	}
}

func configureShaperFromEnv(sh *shaper.Shaper) error {
	if v := os.Getenv(ENV_WG_SHAPER); v != "1" && v != "true" {
		return nil
	}
	cfg := shaper.Config{Enabled: true}
	for _, e := range []struct {
		name string
		dst  *int
	}{
		{ENV_WG_SHAPER_JITTER_MIN_MS, &cfg.JitterMinMs},
		{ENV_WG_SHAPER_JITTER_MAX_MS, &cfg.JitterMaxMs},
		{ENV_WG_SHAPER_KEEPALIVE_MS, &cfg.KeepaliveJitterMs},
		{ENV_WG_SHAPER_SMALL_PKT_MAX, &cfg.SmallPacketMax},
		{ENV_WG_SHAPER_RATE_BYTES_SEC, &cfg.RateBytesPerSec},
	} {
		s := os.Getenv(e.name)
		if s == "" {
			continue
		}
		n, err := strconv.Atoi(s)
		if err != nil || n < 0 {
			return fmt.Errorf("%s must be a non-negative integer", e.name)
		}
		*e.dst = n
	}
	sh.SetConfig(cfg)
	return nil
}

func decodeKey(h, name string) ([]byte, error) {
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != 32 {
		return nil, fmt.Errorf("%s must be 64 hex characters (32-byte X25519 key)", name)
	}
	return b, nil
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
