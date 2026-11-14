# mcsoak

Unified network & transport probe server for HTTP/1.1, HTTP/2, HTTP/3 (QUIC), eBPF XDP/TC reflection, passive TCP SYN fingerprinting, and authoritative DNS leak detection.

## Architecture

`mcsoak` consolidates multiple network diagnostic planes into a single Go binary (`cmd/mcsoak`):

- **HTTP/1.1 + HTTP/2 (`:8443` TCP/TLS)**: Serves diagnostic endpoints, WebSocket echo, synthetic HTML/asset waterfalls, and gzip burst payloads over TLS (loaded from disk or auto-generated ECDSA self-signed cert with SANs from `SOAK_PUBLIC_IPV4` / `SOAK_PUBLIC_IPV6`).
- **HTTP/3 QUIC (`:9443` UDP)**: Optional `quic-go/http3` listener sharing the same route handler and TLS configuration.
- **XDP/TC Pulse Reflector (`:7777` UDP/TCP)**: eBPF-accelerated packet reflector attached to `-iface`. Filters internet background noise using a 4-byte `"MCP\x00"` / `"MCP\x01"` UDP magic header and a 1-byte `0x4D` TCP SYN-cookie ISN noise filter.
- **In-Process TCP SYN Fingerprinter (`AF_PACKET`)**: Captures incoming TCP SYN packets on `-iface` for the configured `-listen` port and stores passive OS/stack fingerprints keyed by client IP.
- **Authoritative DNS Leak Oracle (`:53` UDP/TCP)**: 32K ring-buffer authoritative DNS server for `-dns-domain` (default `sight.muterconn.com`) that records client resolver queries for leak verification.

## CLI Flags & Environment Variables

CLI flags override environment variables, which fall back to defaults:

| Flag | Env Var | Default | Description |
| :--- | :--- | :--- | :--- |
| `-listen` | `SOAK_LISTEN` | `:8443` | HTTPS / HTTP/2 listen address |
| `-quic` | `SOAK_QUIC` | `true` | Enable HTTP/3 QUIC listener |
| `-quic-listen` | `SOAK_QUIC_LISTEN` | `:9443` | HTTP/3 QUIC UDP listen address |
| `-token` | `SOAK_TOKEN` | `""` | Static bearer/query auth token (empty disables auth) |
| `-cert` | `SOAK_CERT` | `""` | Path to TLS certificate file |
| `-key` | `SOAK_KEY` | `""` | Path to TLS private key file |
| `-iface` | `SOAK_IFACE` | `eth0` | Network interface for eBPF reflector & `AF_PACKET` sniffer |
| `-reflector` | `SOAK_REFLECTOR` | `false` | Enable eBPF XDP/TC pulse reflector |
| `-tcpfp-sniff` | `SOAK_TCPFP_SNIFF` | `false` | Enable in-process `AF_PACKET` TCP SYN sniffer |
| `-dnsleak` | `SOAK_DNSLEAK` | `false` | Enable authoritative DNS leak oracle |
| `-dns-listen` | `SOAK_DNS_LISTEN` | `:53` | DNS leak oracle listen address |
| `-dns-domain` | `SOAK_DNS_DOMAIN` | `sight.muterconn.com` | Base domain for DNS leak oracle |
| — | `SOAK_PUBLIC_IPV4` | `""` | Public IPv4 added to auto-generated TLS SANs |
| — | `SOAK_PUBLIC_IPV6` | `""` | Public IPv6 added to auto-generated TLS SANs |

## HTTP Routes & Authentication

When `-token` / `SOAK_TOKEN` is non-empty, all routes **except `/health`** require authentication via either:
- Header: `Authorization: Bearer <token>`
- Query parameter: `?token=<token>`

Token comparison uses constant-time comparison (`subtle.ConstantTimeCompare`). Unauthenticated requests receive `401 Unauthorized`.

| Route | Auth | Description |
| :--- | :--- | :--- |
| `/health` | Public | Returns `{"status":"ok","time":"..."}` for liveness/deployment checks |
| `/echo` | Protected | Echoes client IP, HTTP protocol, TLS info, headers, and matched TCP fingerprint |
| `/fp` | Protected | Returns passive TCP SYN fingerprint for client IP (or `?ip=<addr>`) |
| `/dns` | Protected | Registers a DNS leak test token with the DNS leak oracle |
| `/dns/check` | Protected | Queries observed DNS lookups for a registered leak token |
| `/reflector/stats` | Protected | Returns eBPF reflector packet/byte counters (`?ips=true` includes source IPs) |
| `/ws` | Protected | WebSocket echo endpoint (text/binary + ping/pong) |
| `/page` | Protected | Synthetic HTML page referencing 15 CSS, 10 SVG, and 25 JS sub-resources + `/ws` |
| `/assets/` | Protected | Serves deterministic sub-resources (`/assets/(chunk\|style\|img)_<n>.(js\|css\|svg)`) |
| `/burst` | Protected | Serves a pre-compressed ~10 KB gzipped JSON payload |

## Deployment & Rollback

`scripts/deploy.sh` provides a deterministic, idempotent installer and updater for Debian/Ubuntu hosts:

```bash
# Build from source and deploy
sudo ./scripts/deploy.sh

# Deploy a pre-built binary
sudo ./scripts/deploy.sh --binary ./mcsoak

# Preview actions without modifying the system
./scripts/deploy.sh --dry-run

# Overwrite /etc/default/mcsoak with the default template
sudo ./scripts/deploy.sh --reconfigure
```

### Release Layout & Automatic Rollback

- Releases are installed into `/opt/mcsoak/releases/<git-sha>/mcsoak` with an atomic symlink `/opt/mcsoak/current` (keeping the last 3 releases).
- Runs as a dedicated `mcsoak` system user with `AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_BPF CAP_PERFMON` (no full root required).
- Applies QUIC/XDP kernel buffer tuning in `/etc/sysctl.d/99-mcsoak.conf` and preserves operator edits in `/etc/default/mcsoak`.
- After `systemctl restart mcsoak`, the script polls `https://127.0.0.1:8443/health`. If health verification fails, `/opt/mcsoak/current` is automatically rolled back to the previous release and `mcsoak` is restarted.
