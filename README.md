# TunnixNode

[![Release](https://img.shields.io/github/v/release/huzgnm/tunnix-node)](https://github.com/huzgnm/tunnix-node/releases)
[![Build](https://img.shields.io/github/actions/workflow/status/huzgnm/tunnix-node/release.yml)](https://github.com/huzgnm/tunnix-node/actions)
[![Docker](https://img.shields.io/badge/ghcr.io-huzgnm%2Ftunnix--node-blue)](https://github.com/huzgnm/tunnix-node/pkgs/container/tunnix-node)

TunnixNode is a proxy node backend written in Rust. It connects to a panel, serves the
panel's users over Xray-compatible protocols, and reports traffic and online devices back.

It is a drop-in replacement for [v2node](https://github.com/wyx2685/v2node) and
[remnawave/node](https://github.com/remnawave/node) and works with standard Xray, sing-box and
Hysteria clients. No Go runtime and no garbage collector are involved, which keeps memory use low
and latency stable under load.

## Supported panels

| Panel | Mode | Notes |
|---|---|---|
| [XiaoBoard](https://github.com/wyx2685/v2board) (wyx2685/v2board) | pull | Same API as v2node (`/api/v2/server/config`), device limit, online IPs |
| [Xboard](https://github.com/cedar2025/Xboard) | pull | Device limit, online IPs, node load status |
| [V2Board](https://github.com/v2board/v2board) 1.7.x | pull | VMess, Trojan, Shadowsocks |
| [Remnawave](https://github.com/remnawave) | push | Implements the remnawave/node API (mTLS + JWT); the panel sends an Xray config |

Several panel nodes and one Remnawave node can run in the same process.
Panel developers: see the [panel integration guide](docs/panel-integration.md).

## Features

- Multi-user inbounds with live user updates; removed or expired users are disconnected on the next sync.
- Per-user traffic accounting. Failed reports are retained and retried, so no traffic is lost.
- Per-user speed limit (`speed_limit`, Mbps) and concurrent device limit (`device_limit`, by IP).
- Hot reload of node configuration without dropping established connections.
- REALITY fallback behaves like Xray: unknown SNI and unauthenticated handshakes are relayed to the destination.
- Built-in outbound filter that blocks private and loopback ranges of the host.
- ACME certificates (HTTP-01 and Cloudflare DNS-01) with automatic renewal.
- Static Linux binaries (amd64, arm64) and a multi-arch container image.

## Protocols and transports

| Protocol | TCP | UDP | Security |
|---|:---:|:---:|---|
| VLESS | Yes | Yes | TLS, REALITY, XTLS Vision, ML-KEM-768 encryption |
| VMess (AEAD) | Yes | Yes | TLS |
| Trojan | Yes | Yes | TLS, REALITY |
| Shadowsocks (AEAD, 2022) | Yes | Yes | Multi-user 2022 via identity headers |
| Hysteria2 | Yes | Yes | QUIC, Salamander obfuscation |
| TUIC v5 | Yes | Yes | QUIC |
| AnyTLS | Yes | Yes | TLS |

Transports: RAW/TCP, WebSocket (including early data), gRPC, HTTPUpgrade, XHTTP.

Not supported yet: mKCP, multi-user Shadowsocks 2022 with ChaCha20, DNS-01 providers other than Cloudflare.

## Installation

Run as root on a Linux server (amd64 or arm64).

### Xboard, XiaoBoard, V2Board

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/huzgnm/tunnix-node/main/scripts/install.sh) \
  --panel xiaoboard --api-host 'https://panel.example.com' --node-id 1 --api-key 'SERVER_TOKEN'
```

| Option | Description |
|---|---|
| `--panel` | `xiaoboard`, `xboard`, `v2board` or `remnawave` (default `xiaoboard`) |
| `--api-host`, `--node-id`, `--api-key` | Panel URL, node ID and server token (same flags as v2node) |
| `--node-type` | V2Board only: `vmess`, `trojan` or `shadowsocks` |
| `--mode` | `docker` (default) or `systemd` |
| `--version` | Release tag, e.g. `v0.1.0` (default: latest) |
| `--replace` | Replace existing nodes instead of adding to them |
| `--bbr` | Enable TCP BBR |

Running the script again with another node adds it to the same instance. Without options the
script asks interactively.

### Remnawave

Create the node in the panel and copy `SECRET_KEY` from its docker-compose snippet:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/huzgnm/tunnix-node/main/scripts/install.sh) \
  --panel remnawave --secret-key 'SECRET_KEY' --node-port 2222
```

Supported inbound protocols are VLESS, VMess, Trojan, Shadowsocks and Hysteria with the
transports listed above; other inbounds in the profile are ignored. Restrict `NODE_PORT` to the
panel's IP address.

### Docker

```yaml
services:
  tunnix-node:
    image: ghcr.io/huzgnm/tunnix-node:latest
    container_name: tunnix-node
    restart: always
    network_mode: host
    volumes:
      - /etc/tunnix-node:/etc/tunnix-node
      - /var/lib/tunnix-node:/var/lib/tunnix-node
    # Remnawave only:
    # environment:
    #   - NODE_PORT=2222
    #   - SECRET_KEY=...
```

### Binary

Download an archive from [Releases](https://github.com/huzgnm/tunnix-node/releases), then:

```bash
tunnix-node server -c /etc/tunnix-node/config.json
```

## Management

The installer adds a `tunnix` command:

```text
tunnix start | stop | restart | status | log
tunnix add --panel xboard --api-host URL --node-id 2 --api-key KEY
tunnix remove --api-host URL --node-id 2
tunnix config        edit /etc/tunnix-node/config.json
tunnix update        update to the latest release
tunnix x25519        generate a REALITY key pair
tunnix uninstall
```

## Configuration

`/etc/tunnix-node/config.json` uses the same field names as v2node, so an existing v2node
configuration can be copied as is (`PanelType` defaults to `xiaoboard`).

```json
{
  "Log": { "Level": "info" },
  "Nodes": [
    { "PanelType": "xiaoboard", "ApiHost": "https://panel.example.com", "NodeID": 1, "ApiKey": "TOKEN" },
    { "PanelType": "xboard", "ApiHost": "https://xboard.example.com", "NodeID": 7, "ApiKey": "TOKEN", "Timeout": 15 }
  ],
  "Remnawave": { "NodePort": 2222, "SecretKey": "..." },
  "AcmeEmail": "admin@example.com"
}
```

| Field | Description |
|---|---|
| `Log.Level` | `error`, `warn`, `info`, `debug` or `trace` (`RUST_LOG` overrides) |
| `Nodes[].PanelType` | `xiaoboard`, `xboard` or `v2board` |
| `Nodes[].ApiHost`, `NodeID`, `ApiKey` | Panel connection |
| `Nodes[].NodeType` | V2Board only: `vmess`, `trojan`, `shadowsocks` |
| `Nodes[].Timeout` | Panel request timeout in seconds (default 15) |
| `Nodes[].SpeedLimit` | Node-wide speed limit in Mbps, applied with per-user limits (default 0 = none) |
| `Remnawave` | Remnawave mode; `NODE_PORT` / `SECRET_KEY` environment variables also work |
| `AcmeEmail` | Optional ACME account contact |
| `DnsHijack` | Answer client DNS queries (port 53) with the server's resolver, as v2node does (default `true`) |
| `DataDir` | State directory (default `/var/lib/tunnix-node`) |

### TLS certificates

The certificate mode is taken from the panel (`cert_mode`):

| Mode | Behaviour |
|---|---|
| `http` | Let's Encrypt via HTTP-01. Port 80 must be reachable while issuing and renewing. |
| `dns` | Let's Encrypt via DNS-01. Cloudflare: `provider = cloudflare`, `dns_env = CF_DNS_API_TOKEN=...` (or `CF_API_EMAIL` and `CF_API_KEY`). |
| `file` | Uses `cert_file` and `key_file` on the server. |
| `remote` | Uses the certificate and key sent by the panel. |
| `self` | Self-signed certificate. |

Certificates are stored in `<DataDir>/acme/<domain>/` and renewed 30 days before expiry without
dropping connections. If issuance fails the node starts with a self-signed certificate and retries
hourly. Using `http` or `dns` implies acceptance of the Let's Encrypt subscriber agreement.

Xray 26 clients no longer support `allowInsecure`; with self-signed certificates clients must pin
the certificate (`pinnedPeerCertSha256`).

## Building from source

Requires Rust 1.99 or newer.

```bash
cargo build --release -p tunnix-node
```

Static Linux binaries are built with [cargo-zigbuild](https://github.com/rust-cross/cargo-zigbuild):

```bash
cargo zigbuild --release -p tunnix-node --target x86_64-unknown-linux-musl
cargo zigbuild --release -p tunnix-node --target aarch64-unknown-linux-musl
```

Container image from source:

```bash
docker build -f docker/Dockerfile.source -t tunnix-node .
```

Pushing a `v*` tag runs the release workflow, which publishes the archives and the
`ghcr.io/huzgnm/tunnix-node` image.

## Performance

Measured on 2026-11-27 with the scripts in [`bench/`](bench) on a 4 vCPU KVM server in Frankfurt
(Ubuntu 24.04). All three nodes served the same VLESS + REALITY + Vision inbound to one test user.
The client ran on the same host and downloaded from a server in the same data centre; each
implementation was run twice and the results averaged.

| Metric | TunnixNode 0.1.2 | v2node 0.4.7 | remnawave/node 3.4.6 |
|---|---:|---:|---:|
| Memory, idle (MiB) | **31** | 56 | 163 (Xray core: 38) |
| Memory, 8-stream download (MiB) | **42** | 70 | 170 (Xray core: 44) |
| Memory, 2000 idle connections (MiB) | **172** | 203 | 301 (Xray core: 175) |
| Memory per connection (KiB) | 67 | 69 | 67 |
| CPU per Gbit/s (% of one core) | **59** | 105 | 116 |
| Throughput, 8 streams (Mbit/s) | 824 | 748 | 785 |
| Time to first byte, median (ms) | 37 | 38 | 37 |
| DNS query through the node, median (ms) | **0.35** | 0.55 | 2.2 |
| Traffic recorded / bytes downloaded | 100.3 % | 100.3 % | 100.3 % |

Notes:

- v2node 0.4.7 embeds Xray 26.10.31; remnawave/node 3.4.6 runs Xray 26.11.9 (`rw-core`) next
  to a Node.js control process (`rw-node`). Its memory is shown in total and for the Xray core alone.
- Throughput was limited by the network path; all three reached similar rates.
- DNS is answered by the server's resolver in TunnixNode and v2node (`DnsHijack`), and forwarded
  to the requested server by remnawave/node.
- Recorded traffic is the payload exchanged with destinations, matching Xray's accounting.

To reproduce, follow [`bench/README.md`](bench/README.md).

## Project layout

| Path | Contents |
|---|---|
| `crates/node` | Panel clients, Remnawave API, ACME, configuration builder, CLI |
| `crates/core` | Protocol core, a fork of [shoes](https://github.com/cfal/shoes); TunnixNode changes are in `src/tunnix/` |
| `scripts/install.sh` | Installer and the `tunnix` management command |
| `scripts/dev` | Local test helpers (mock panel, mock Cloudflare API) |
| `bench` | Benchmark scripts |

## Acknowledgements

The protocol core is based on [shoes](https://github.com/cfal/shoes) by Alex Lau. Protocol
behaviour follows [Xray-core](https://github.com/XTLS/Xray-core) and
[sing-box](https://github.com/SagerNet/sing-box) for client compatibility.

## License

Proprietary. See [LICENSE](LICENSE). The code under `crates/core` is derived from shoes and
remains under the MIT License; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
