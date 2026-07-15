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

	"golang.zx2c4.com/wireguard/conn"
)

// Environment variables that bootstrap the obfuscation layer at process start.
// This is the practical way to configure obfuscation for the standard wireguard-go
// binary, since wg(8) cannot pass the extended UAPI keys. The same settings can
// also be supplied programmatically or over the UAPI socket (see device/uapi.go).
const (
	ENV_WG_OBFS_KEY               = "WG_OBFS_KEY"      // 64 hex chars (32 bytes)
	ENV_WG_OBFS_PASSWORD          = "WG_OBFS_PASSWORD" // any string, hashed to a key
	ENV_WG_OBFS_JUNK_MIN          = "WG_OBFS_JUNK_MIN"
	ENV_WG_OBFS_JUNK_MAX          = "WG_OBFS_JUNK_MAX"
	ENV_WG_OBFS_JUNK_SIZE_MIN     = "WG_OBFS_JUNK_SIZE_MIN"
	ENV_WG_OBFS_JUNK_SIZE_MAX     = "WG_OBFS_JUNK_SIZE_MAX"
	ENV_WG_OBFS_PAD_HANDSHAKE_MAX = "WG_OBFS_PAD_HANDSHAKE_MAX"
	ENV_WG_OBFS_PAD_DATA_MAX      = "WG_OBFS_PAD_DATA_MAX"
)

// newBind constructs the device's bind. If WG_TRANSPORT=reality it builds the
// REALITY stream transport (see transport_env.go); otherwise it uses the default
// UDP path wrapped with the obfuscation layer. In both cases, with no obfuscation
// key set the wrapper is a transparent pass-through and the fork behaves as stock
// wireguard-go.
func newBind() (conn.Bind, error) {
	if b, err := newRealityBind(); err != nil || b != nil {
		return b, err
	}
	bind := conn.NewObfsBind(conn.NewDefaultBind())
	if err := configureObfsFromEnv(bind); err != nil {
		return nil, err
	}
	return bind, nil
}

func configureObfsFromEnv(bind *conn.ObfsBind) error {
	if key := os.Getenv(ENV_WG_OBFS_KEY); key != "" {
		b, err := hex.DecodeString(key)
		if err != nil || len(b) != 32 {
			return fmt.Errorf("%s must be 64 hex characters", ENV_WG_OBFS_KEY)
		}
		var k [32]byte
		copy(k[:], b)
		bind.SetKey(k)
	} else if pw := os.Getenv(ENV_WG_OBFS_PASSWORD); pw != "" {
		bind.SetKey(conn.DeriveObfsKey(pw))
	} else {
		return nil // obfuscation disabled
	}

	type intEnv struct {
		name string
		set  func(int)
	}
	for _, e := range []intEnv{
		{ENV_WG_OBFS_JUNK_MIN, bind.SetJunkMin},
		{ENV_WG_OBFS_JUNK_MAX, bind.SetJunkMax},
		{ENV_WG_OBFS_JUNK_SIZE_MIN, bind.SetJunkSizeMin},
		{ENV_WG_OBFS_JUNK_SIZE_MAX, bind.SetJunkSizeMax},
		{ENV_WG_OBFS_PAD_HANDSHAKE_MAX, bind.SetPadHandshakeMax},
		{ENV_WG_OBFS_PAD_DATA_MAX, bind.SetPadDataMax},
	} {
		v := os.Getenv(e.name)
		if v == "" {
			continue
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return fmt.Errorf("%s must be a non-negative integer", e.name)
		}
		e.set(n)
	}
	return nil
}
