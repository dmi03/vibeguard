/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package transport

import (
	"context"
	"encoding/hex"
	"errors"
	"net"

	reality "github.com/xtls/reality"
)

// RealityConfig configures the REALITY transport. Server-side fields (Dest,
// ServerNames, PrivateKey, ShortIds) are used by Listen; client-side fields
// (ServerName, PublicKey, ShortId, Fingerprint) are used by Dial. Keys are raw
// 32-byte X25519 values.
type RealityConfig struct {
	Show bool

	// Server side.
	Dest        string   // camouflage target, host:port (must serve TLS 1.3)
	ServerNames []string // acceptable SNIs
	PrivateKey  []byte   // server X25519 private key (32 bytes)
	ShortIds    []string // acceptable short IDs (hex, 0..16 chars)

	// Client side.
	ServerName  string // SNI to present (one of the server's ServerNames)
	PublicKey   []byte // server X25519 public key (32 bytes)
	ShortId     string // short ID (hex), must be one the server accepts
	Fingerprint string // utls fingerprint: chrome (default), firefox, safari, ios, edge, random
}

// Reality is the REALITY (TLS 1.3 mimicry) implementation of Transport.
type Reality struct {
	cfg RealityConfig
}

var _ Transport = (*Reality)(nil)

// NewReality returns a REALITY transport using cfg.
func NewReality(cfg RealityConfig) *Reality {
	return &Reality{cfg: cfg}
}

// Dial performs the REALITY client handshake to dest and returns the tunnelled
// stream. The server is authenticated via the REALITY signature; a genuine or
// MITM certificate fails the handshake.
func (r *Reality) Dial(ctx context.Context, dest string) (net.Conn, error) {
	var d net.Dialer
	raw, err := d.DialContext(ctx, "tcp", dest)
	if err != nil {
		return nil, err
	}
	conn, err := uClientHandshake(ctx, raw, r.cfg, dest)
	if err != nil {
		raw.Close()
		return nil, err
	}
	return conn, nil
}

// Listen starts a REALITY server on laddr. Authenticated clients get a tunnelled
// stream; unauthenticated probes are transparently proxied to the camouflage Dest.
func (r *Reality) Listen(laddr string) (net.Listener, error) {
	if len(r.cfg.PrivateKey) != 32 {
		return nil, errors.New("REALITY: server private key must be 32 bytes")
	}
	if r.cfg.Dest == "" {
		return nil, errors.New("REALITY: server Dest (camouflage target) is required")
	}
	names := make(map[string]bool, len(r.cfg.ServerNames))
	for _, n := range r.cfg.ServerNames {
		names[n] = true
	}
	shortIds := make(map[[8]byte]bool)
	if len(r.cfg.ShortIds) == 0 {
		shortIds[[8]byte{}] = true // accept the empty short ID
	}
	for _, s := range r.cfg.ShortIds {
		sid, err := parseShortID(s)
		if err != nil {
			return nil, err
		}
		shortIds[sid] = true
	}

	var dialer net.Dialer
	rc := &reality.Config{
		DialContext:            dialer.DialContext,
		Show:                   r.cfg.Show,
		Type:                   "tcp",
		Dest:                   r.cfg.Dest,
		ServerNames:            names,
		PrivateKey:             r.cfg.PrivateKey,
		ShortIds:               shortIds,
		SessionTicketsDisabled: true,
	}
	// Use NewListener (not reality.Listen, which inherits crypto/tls's
	// require-a-certificate check): REALITY generates certificates on the fly.
	inner, err := net.Listen("tcp", laddr)
	if err != nil {
		return nil, err
	}
	return reality.NewListener(inner, rc), nil
}

// parseShortID decodes a hex short ID (0..16 hex chars) into an 8-byte value,
// left-aligned and zero-padded.
func parseShortID(s string) ([8]byte, error) {
	var out [8]byte
	if s == "" {
		return out, nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return out, errors.New("REALITY: short ID must be hex")
	}
	if len(b) > 8 {
		return out, errors.New("REALITY: short ID longer than 8 bytes")
	}
	copy(out[:], b)
	return out, nil
}
