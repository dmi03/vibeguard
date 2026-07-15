/* SPDX-License-Identifier: MPL-2.0
 *
 * The REALITY client handshake below is ported from Xray-core
 * (github.com/xtls/xray-core, transport/internet/reality, MPL-2.0) so this fork
 * does not reimplement the security-critical client auth from scratch. Only this
 * file is under MPL-2.0; the rest of vibeguard is MIT. Changes from upstream:
 * the peer certificate is parsed from the callback's rawCerts (no unsafe/reflect
 * reach into utls internals), and the anti-detection "spider" crawl on
 * verification failure is omitted (we simply fail the handshake).
 *
 * Copyright (C) the Xray-core authors.
 */

package transport

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/hkdf"
)

// realityClientVersion is written into the ClientHello session id. The server
// only range-checks it when MinClientVer/MaxClientVer are configured, which we
// leave unset, so the exact value is unimportant.
var realityClientVersion = [3]byte{1, 0, 0}

// uClientHandshake performs the REALITY client handshake over c and returns the
// established connection (a *utls.UConn, which is a net.Conn) on success. It
// authenticates the server via the REALITY signature; a genuine/MITM certificate
// causes an error.
func uClientHandshake(ctx context.Context, c net.Conn, cfg RealityConfig, dest string) (net.Conn, error) {
	sni := cfg.ServerName
	if sni == "" {
		if host, _, err := net.SplitHostPort(dest); err == nil {
			sni = host
		} else {
			sni = dest
		}
	}

	shortId, err := parseShortID(cfg.ShortId)
	if err != nil {
		return nil, err
	}
	serverPub, err := ecdh.X25519().NewPublicKey(cfg.PublicKey)
	if err != nil {
		return nil, errors.New("REALITY: invalid server public key")
	}

	var authKey []byte
	verified := false

	utlsConfig := &utls.Config{
		ServerName:             sni,
		InsecureSkipVerify:     true,
		SessionTicketsDisabled: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("REALITY: no certificate")
			}
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}
			if pub, ok := cert.PublicKey.(ed25519.PublicKey); ok {
				h := hmac.New(sha512.New, authKey)
				h.Write(pub)
				if hmac.Equal(h.Sum(nil), cert.Signature) {
					verified = true
					return nil
				}
			}
			return errors.New("REALITY: server certificate not authenticated (possible MITM or redirect)")
		},
	}

	uConn := utls.UClient(c, utlsConfig, fingerprintFor(cfg.Fingerprint))
	if err := uConn.BuildHandshakeState(); err != nil {
		return nil, err
	}

	hello := uConn.HandshakeState.Hello
	hello.SessionId = make([]byte, 32)
	copy(hello.Raw[39:], hello.SessionId) // zero the session-id region (fixed offset)
	hello.SessionId[0] = realityClientVersion[0]
	hello.SessionId[1] = realityClientVersion[1]
	hello.SessionId[2] = realityClientVersion[2]
	hello.SessionId[3] = 0 // reserved
	binary.BigEndian.PutUint32(hello.SessionId[4:], uint32(time.Now().Unix()))
	copy(hello.SessionId[8:], shortId[:])

	ks := uConn.HandshakeState.State13.KeyShareKeys
	if ks == nil {
		return nil, errors.New("REALITY: fingerprint has no TLS 1.3 key share")
	}
	ecdhe := ks.Ecdhe
	if ecdhe == nil {
		ecdhe = ks.MlkemEcdhe
	}
	if ecdhe == nil {
		return nil, errors.New("REALITY: selected fingerprint does not support TLS 1.3")
	}

	authKey, err = ecdhe.ECDH(serverPub)
	if err != nil {
		return nil, err
	}
	if _, err := hkdf.New(sha256.New, authKey, hello.Random[:20], []byte("REALITY")).Read(authKey); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(authKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	aead.Seal(hello.SessionId[:0], hello.Random[20:], hello.SessionId[:16], hello.Raw)
	copy(hello.Raw[39:], hello.SessionId)

	if err := uConn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	if !verified {
		return nil, errors.New("REALITY: server not authenticated")
	}
	return uConn, nil
}

func fingerprintFor(name string) utls.ClientHelloID {
	switch name {
	case "firefox":
		return utls.HelloFirefox_Auto
	case "safari":
		return utls.HelloSafari_Auto
	case "ios":
		return utls.HelloIOS_Auto
	case "edge":
		return utls.HelloEdge_Auto
	case "random", "randomized":
		return utls.HelloRandomized
	case "chrome", "":
		return utls.HelloChrome_Auto
	default:
		return utls.HelloChrome_Auto
	}
}
