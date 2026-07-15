/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

// Package transport defines a pluggable connection-oriented transport used to
// carry WireGuard traffic. The default WireGuard path is UDP via conn.Bind and
// is unaffected by this package; transport is used by the packet-over-stream
// bridge (conn.StreamBind) to run WireGuard over stream transports such as
// REALITY (TLS 1.3 mimicry) when a raw UDP path is blocked or throttled.
//
// A Transport is a factory for byte streams: Dial produces a client stream to a
// destination and Listen accepts server streams. Read/Write/Close are provided
// by the returned net.Conn, per idiomatic Go.
package transport

import (
	"context"
	"net"
)

// Transport creates connection-oriented byte streams.
type Transport interface {
	// Dial opens a client stream to dest (host:port).
	Dial(ctx context.Context, dest string) (net.Conn, error)
	// Listen accepts server streams on laddr (host:port).
	Listen(laddr string) (net.Listener, error)
}
