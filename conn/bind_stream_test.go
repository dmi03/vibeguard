/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"bytes"
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

// oneShotTransport wires a StreamBind to a single pre-connected net.Conn (one end
// of a net.Pipe), so client and server StreamBinds can be tested in-memory without
// real sockets.
type oneShotTransport struct {
	dialConn   net.Conn
	listenConn net.Conn
}

func (t *oneShotTransport) Dial(ctx context.Context, dest string) (net.Conn, error) {
	return t.dialConn, nil
}

func (t *oneShotTransport) Listen(laddr string) (net.Listener, error) {
	l := &oneShotListener{ch: make(chan net.Conn, 1), closed: make(chan struct{}), conn: t.listenConn}
	l.ch <- t.listenConn
	return l, nil
}

type oneShotListener struct {
	conn   net.Conn
	ch     chan net.Conn
	closed chan struct{}
}

func (l *oneShotListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *oneShotListener) Close() error {
	select {
	case <-l.closed:
	default:
		close(l.closed)
	}
	return nil
}

func (l *oneShotListener) Addr() net.Addr { return l.conn.LocalAddr() }

func waitConns(b *StreamBind) bool {
	for i := 0; i < 200; i++ {
		b.mu.Lock()
		n := len(b.conns)
		b.mu.Unlock()
		if n > 0 {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return false
}

func recvOne(t *testing.T, fn ReceiveFunc) ([]byte, Endpoint) {
	t.Helper()
	packets := [][]byte{make([]byte, 4096)}
	sizes := []int{0}
	eps := []Endpoint{nil}
	n, err := fn(packets, sizes, eps)
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 packet, got %d", n)
	}
	return append([]byte(nil), packets[0][:sizes[0]]...), eps[0]
}

func TestStreamBindRoundTrip(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	srv := NewStreamBind(&oneShotTransport{listenConn: serverConn}, RoleServer, "", nil)
	cli := NewStreamBind(&oneShotTransport{dialConn: clientConn}, RoleClient, "server:51820", nil)

	srvFns, _, err := srv.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	cliFns, _, err := cli.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	if !waitConns(cli) || !waitConns(srv) {
		t.Fatal("connections not established")
	}

	// client -> server
	up := []byte{0x01, 0x00, 0x00, 0x00, 0xaa, 0xbb, 0xcc}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := cli.Send([][]byte{up}, &streamEndpoint{addr: "server:51820"}); err != nil {
			t.Errorf("client send: %v", err)
		}
	}()
	got, clientEp := recvOne(t, srvFns[0])
	wg.Wait()
	if !bytes.Equal(got, up) {
		t.Fatalf("server got %x, want %x", got, up)
	}

	// server -> client, replying to the endpoint it learned
	down := []byte{0x04, 0x00, 0x00, 0x00, 0x11, 0x22}
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := srv.Send([][]byte{down}, clientEp); err != nil {
			t.Errorf("server send: %v", err)
		}
	}()
	got2, _ := recvOne(t, cliFns[0])
	wg.Wait()
	if !bytes.Equal(got2, down) {
		t.Fatalf("client got %x, want %x", got2, down)
	}
}

func TestStreamBindOversizedFrameSkipped(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	srv := NewStreamBind(&oneShotTransport{listenConn: serverConn}, RoleServer, "", nil)
	cli := NewStreamBind(&oneShotTransport{dialConn: clientConn}, RoleClient, "server:1", nil)
	srvFns, _, err := srv.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	cliFns, _, err := cli.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	_ = cliFns
	defer cli.Close()
	if !waitConns(cli) || !waitConns(srv) {
		t.Fatal("connections not established")
	}

	// An oversized buffer is skipped; a following valid one still transits.
	oversize := make([]byte, streamFrameMax+1)
	valid := []byte{0x02, 0x00, 0x00, 0x00, 0x42}
	go cli.Send([][]byte{oversize, valid}, &streamEndpoint{addr: "server:1"})

	got, _ := recvOne(t, srvFns[0])
	if !bytes.Equal(got, valid) {
		t.Fatalf("server got %x, want %x", got, valid)
	}
}

func TestStreamBindCloseUnblocksReceive(t *testing.T) {
	serverConn, _ := net.Pipe()
	srv := NewStreamBind(&oneShotTransport{listenConn: serverConn}, RoleServer, "", nil)
	fns, _, err := srv.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		packets := [][]byte{make([]byte, 64)}
		sizes := []int{0}
		eps := []Endpoint{nil}
		fns[0](packets, sizes, eps)
		close(done)
	}()
	time.Sleep(20 * time.Millisecond)
	srv.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("receive did not unblock on Close")
	}
}
