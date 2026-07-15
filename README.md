# Go Implementation of [WireGuard](https://www.wireguard.com/)

This is an implementation of WireGuard in Go.

## Usage

Most Linux kernel WireGuard users are used to adding an interface with `ip link add wg0 type wireguard`. With wireguard-go, instead simply run:

```
$ wireguard-go wg0
```

This will create an interface and fork into the background. To remove the interface, use the usual `ip link del wg0`, or if your system does not support removing interfaces directly, you may instead remove the control socket via `rm -f /var/run/wireguard/wg0.sock`, which will result in wireguard-go shutting down.

To run wireguard-go without forking to the background, pass `-f` or `--foreground`:

```
$ wireguard-go -f wg0
```

When an interface is running, you may use [`wg(8)`](https://git.zx2c4.com/wireguard-tools/about/src/man/wg.8) to configure it, as well as the usual `ip(8)` and `ifconfig(8)` commands.

To run with more logging you may set the environment variable `LOG_LEVEL=debug`.

## Obfuscation (censorship circumvention)

This fork adds a native traffic-obfuscation layer that makes WireGuard datagrams
unclassifiable to DPI systems (such as Russia's TSPU/RKN) which fingerprint
WireGuard by its fixed message-type bytes, its fixed handshake sizes (148/92/64
bytes), and its constant field layout.

When enabled, every UDP datagram is wrapped in an AEAD envelope keyed by a
pre-shared **obfuscation key**:

```
[ 24-byte random salt ][ XChaCha20-Poly1305( key, salt, [len][packet][padding] ) ]
```

After the random salt the entire payload is ciphertext, so there are no magic
bytes, no zero fields, and — with random padding on handshake packets — no fixed
sizes. A random number of random-content decoy datagrams is also sent ahead of each
fresh handshake, breaking the "first UDP packet is 148 bytes" heuristic. Because a
censor without the key cannot forge an authenticating datagram, the port silently
drops probes and never reveals a WireGuard fingerprint (anti active-probing).

This is a *masking* layer only: WireGuard's Noise handshake remains the real
security boundary. Both peers must run this fork and share the same obfuscation
key. When no key is configured, the layer is a transparent pass-through and the
program behaves as stock wireguard-go.

### Configuration

The simplest way is via environment variables at process start (all optional
except the key/password):

```
WG_OBFS_PASSWORD=your-shared-secret wireguard-go wg0
```

| Variable | Meaning | Default |
| --- | --- | --- |
| `WG_OBFS_KEY` | 64 hex chars (32-byte key) | — |
| `WG_OBFS_PASSWORD` | any string, hashed to a key (alternative to `WG_OBFS_KEY`) | — |
| `WG_OBFS_JUNK_MIN` / `WG_OBFS_JUNK_MAX` | decoy packet count range | 2 / 5 |
| `WG_OBFS_JUNK_SIZE_MIN` / `WG_OBFS_JUNK_SIZE_MAX` | decoy size range (bytes) | 40 / 1200 |
| `WG_OBFS_PAD_HANDSHAKE_MAX` | max random padding on handshake packets | 256 |
| `WG_OBFS_PAD_DATA_MAX` | max random padding on transport packets | 0 |

The same settings can also be applied over the UAPI socket using the device-level
keys `obfs_key`, `obfs_password`, `obfs_junk_min`, `obfs_junk_max`,
`obfs_junk_size_min`, `obfs_junk_size_max`, `obfs_pad_handshake_max`, and
`obfs_pad_data_max`.

### MTU

Obfuscation adds a constant 42 bytes of overhead per datagram (plus any padding).
To avoid IP fragmentation, lower the interface MTU accordingly — e.g. set
`MTU = 1380` in your `wg-quick` config when obfuscation is enabled.

## Pluggable transports: REALITY (TLS 1.3 mimicry)

Uniform-random UDP (the obfuscation above) defeats protocol fingerprinting, but
some censors throttle or drop *unclassifiable* UDP outright (this is why QUIC/
HTTP-3 is degraded in Russia — DPI cannot inspect it). For those conditions this
fork can carry WireGuard over a **REALITY** stream instead of UDP: the connection
looks like a genuine TLS 1.3 visit to a real, allow-listed website, and an
unauthorized prober is transparently forwarded to that real site.

The transport is pluggable (`transport/` package). UDP remains the default, fast
path (`conn.Bind`, unchanged). REALITY is an alternative selected with
`WG_TRANSPORT=reality`; WireGuard packets (optionally still AEAD-obfuscated) are
length-framed and carried as the payload of the REALITY session via the
`conn.StreamBind` bridge.

> **Trade-offs.** REALITY rides TCP, so tunnelling UDP over it incurs TCP-over-TCP
> behaviour under loss — use it as a fallback when UDP is blocked, not as the
> default. REALITY is inherently client↔server: one side listens, the other dials.

### Generating keys

REALITY authenticates with an X25519 keypair (same curve as WireGuard):

```
priv_b64=$(wg genkey); pub_b64=$(printf '%s' "$priv_b64" | wg pubkey)
printf 'PRIVATE_KEY (hex): '; printf '%s' "$priv_b64" | base64 -d | xxd -p -c256
printf 'PUBLIC_KEY  (hex): '; printf '%s' "$pub_b64"  | base64 -d | xxd -p -c256
short_id=$(openssl rand -hex 8)   # 0..8 bytes, even hex length
```

### Server

```
WG_TRANSPORT=reality \
WG_ROLE=server \
WG_REALITY_DEST=www.microsoft.com:443 \
WG_REALITY_SERVERNAMES=www.microsoft.com \
WG_REALITY_PRIVATE_KEY=<priv_hex> \
WG_REALITY_SHORT_IDS=<short_id> \
wireguard-go wg0
```

Set the WireGuard `ListenPort` to the port clients dial (e.g. 443).

### Client

```
WG_TRANSPORT=reality \
WG_ROLE=client \
WG_REALITY_SERVER=<server_ip>:443 \
WG_REALITY_SERVERNAMES=www.microsoft.com \
WG_REALITY_PUBLIC_KEY=<pub_hex> \
WG_REALITY_SHORT_ID=<short_id> \
WG_REALITY_FINGERPRINT=chrome \
wireguard-go wg0
```

Set the peer `Endpoint` in the WireGuard config to the same `<server_ip>:443`.

### Choosing the camouflage `dest`

`WG_REALITY_DEST` (and the matching `WG_REALITY_SERVERNAMES`) is the real site your
traffic impersonates. Pick it carefully — a poor choice is itself a signal:

- **Must serve TLS 1.3 and support X25519** key exchange (REALITY relays that
  site's real handshake). Verify with `openssl s_client -connect host:443 -tls1_3`.
- **High-traffic site on a shared IP / large CDN**, so your flows blend into a
  large crowd going to the same address.
- **Reachable and *not blocked* from the censored region**, and ideally
  low-latency from the server (it is dialed during every handshake).
- **Not a domain you own or control**, and not the server's own domain — it must be
  an unrelated, popular third party.

### Traffic shaper (optional)

An egress shaper (`shaper/` package) resists traffic-analysis without touching the
WireGuard core: randomized inter-packet jitter, an egress byte-rate cap to break
the symmetric upload/download profile of a VPN, and extra jitter on small
keepalive packets. Configure via env (or the UAPI keys `shaper_*`):

```
WG_SHAPER=1
WG_SHAPER_JITTER_MIN_MS=0
WG_SHAPER_JITTER_MAX_MS=8
WG_SHAPER_KEEPALIVE_JITTER_MS=250
WG_SHAPER_RATE_BYTES_PER_SEC=0        # 0 = unlimited
```

> **Licensing note.** The REALITY client handshake in
> `transport/reality_client.go` is ported from Xray-core and is licensed
> **MPL-2.0** (noted in that file's header). Everything else in this fork is MIT.

## Platforms

### Linux

This will run on Linux; however you should instead use the kernel module, which is faster and better integrated into the OS. See the [installation page](https://www.wireguard.com/install/) for instructions.

### macOS

This runs on macOS using the utun driver. It does not yet support sticky sockets, and won't support fwmarks because of Darwin limitations. Since the utun driver cannot have arbitrary interface names, you must either use `utun[0-9]+` for an explicit interface name or `utun` to have the kernel select one for you. If you choose `utun` as the interface name, and the environment variable `WG_TUN_NAME_FILE` is defined, then the actual name of the interface chosen by the kernel is written to the file specified by that variable.

### Windows

This runs on Windows, but you should instead use it from the more [fully featured Windows app](https://git.zx2c4.com/wireguard-windows/about/), which uses this as a module.

### FreeBSD

This will run on FreeBSD. It does not yet support sticky sockets. Fwmark is mapped to `SO_USER_COOKIE`.

### OpenBSD

This will run on OpenBSD. It does not yet support sticky sockets. Fwmark is mapped to `SO_RTABLE`. Since the tun driver cannot have arbitrary interface names, you must either use `tun[0-9]+` for an explicit interface name or `tun` to have the program select one for you. If you choose `tun` as the interface name, and the environment variable `WG_TUN_NAME_FILE` is defined, then the actual name of the interface chosen by the kernel is written to the file specified by that variable.

## Building

This requires an installation of the latest version of [Go](https://go.dev/).

```
$ git clone https://git.zx2c4.com/wireguard-go
$ cd wireguard-go
$ make
```

## License

    Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
    
    Permission is hereby granted, free of charge, to any person obtaining a copy of
    this software and associated documentation files (the "Software"), to deal in
    the Software without restriction, including without limitation the rights to
    use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
    of the Software, and to permit persons to whom the Software is furnished to do
    so, subject to the following conditions:
    
    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.
    
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
