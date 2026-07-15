/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package transport

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

// tls13Dest starts a local TLS 1.3 server used as the REALITY camouflage target.
func tls13Dest(t *testing.T) net.Listener {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		DNSNames:     []string{"example.com", "www.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				io.Copy(io.Discard, c)
				c.Close()
			}(c)
		}
	}()
	return ln
}

func genX25519(t *testing.T) (priv, pub []byte) {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k.Bytes(), k.PublicKey().Bytes()
}

// TestRealityHandshake runs a full REALITY server + client over loopback with a
// local TLS 1.3 camouflage dest, and checks that an authenticated client can
// tunnel bytes while a client with the wrong server key is rejected.
func TestRealityHandshake(t *testing.T) {
	dest := tls13Dest(t)
	defer dest.Close()
	destAddr := dest.Addr().String()

	priv, pub := genX25519(t)
	const shortID = "01ab"

	server := NewReality(RealityConfig{
		Dest:        destAddr,
		ServerNames: []string{"example.com"},
		PrivateKey:  priv,
		ShortIds:    []string{shortID},
	})
	ln, err := server.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("reality listen: %v", err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		} else {
			accepted <- nil
		}
	}()

	client := NewReality(RealityConfig{
		ServerName:  "example.com",
		PublicKey:   pub,
		ShortId:     shortID,
		Fingerprint: "chrome",
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cconn, err := client.Dial(ctx, ln.Addr().String())
	if err != nil {
		t.Fatalf("reality client handshake failed: %v", err)
	}
	defer cconn.Close()

	sconn := <-accepted
	if sconn == nil {
		t.Fatal("server did not accept an authenticated client")
	}
	defer sconn.Close()

	// Tunnel a payload client -> server.
	msg := []byte("hello through reality")
	go cconn.Write(msg)
	buf := make([]byte, len(msg))
	sconn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(sconn, buf); err != nil {
		t.Fatalf("server read: %v", err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("got %q, want %q", buf, msg)
	}

	// Negative: wrong server public key must fail authentication.
	_, wrongPub := genX25519(t)
	bad := NewReality(RealityConfig{
		ServerName:  "example.com",
		PublicKey:   wrongPub,
		ShortId:     shortID,
		Fingerprint: "chrome",
	})
	go func() {
		c, err := ln.Accept()
		if err == nil && c != nil {
			c.Close()
		}
	}()
	ctx2, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()
	if _, err := bad.Dial(ctx2, ln.Addr().String()); err == nil {
		t.Fatal("expected handshake failure with wrong server key")
	}
}
