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
