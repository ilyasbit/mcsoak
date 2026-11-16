# mcsoak

Unified network & transport probe server for HTTP/1.1, HTTP/2, HTTP/3 (QUIC), eBPF XDP/TC reflection, passive TCP SYN fingerprinting, and authoritative DNS leak detection.

## Architecture

`mcsoak` consolidates multiple network diagnostic planes into a single Go binary (`cmd/mcsoak`):

- **HTTP/1.1 + HTTP/2 (`:8443` TCP/TLS)**: Serves diagnostic endpoints, WebSocket echo, synthetic HTML/asset waterfalls, and gzip burst payloads over TLS (loaded from disk or auto-generated ECDSA self-signed cert with SANs from `MCSOAK_PUBLIC_IPV4` / `MCSOAK_PUBLIC_IPV6`, idempotently persisted to `-cert` / `-key`, e.g. `/var/lib/mcsoak/cert.pem` and `/var/lib/mcsoak/key.pem`).
- **HTTP/3 QUIC (`:9443` UDP)**: Optional `quic-go/http3` listener sharing the same route handler and TLS configuration.
- **XDP/TC Pulse Reflector (`:7777` UDP/TCP)**: eBPF-accelerated packet reflector attached to `-iface`. Filters internet background noise using a 4-byte `"MCP\x00"` / `"MCP\x01"` UDP magic header and a 1-byte `0x4D` TCP SYN-cookie ISN noise filter.
- **In-Process TCP SYN Fingerprinter (`AF_PACKET`)**: Captures incoming TCP SYN packets on `-iface` for the configured `-listen` port and stores passive OS/stack fingerprints keyed by client IP.
- **Authoritative DNS Leak Oracle (`:53` UDP/TCP)**: 32K ring-buffer authoritative DNS server for `-dns-domain` (default `dns.muterconn.com`, NS `ns1.dns.muterconn.com,ns2.dns.muterconn.com`) that records client resolver queries for leak verification. When `-dns-listen` is empty, it auto-binds `<MCSOAK_PUBLIC_IPV4>:53` and `[<MCSOAK_PUBLIC_IPV6>]:53` so local `127.0.0.53:53` (`systemd-resolved`) is never disturbed.

## CLI Flags & Environment Variables

CLI flags override environment variables, which fall back to defaults:

| Flag | Env Var | Default | Description |
| :--- | :--- | :--- | :--- |
| `-listen` | `MCSOAK_LISTEN` | `:8443` | HTTPS / HTTP/2 listen address |
| `-quic` | `MCSOAK_QUIC` | `true` | Enable HTTP/3 QUIC listener |
| `-quic-listen` | `MCSOAK_QUIC_LISTEN` | `:9443` | HTTP/3 QUIC UDP listen address |
| `-token` | `MCSOAK_TOKEN` | `""` | Static bearer/query auth token (empty disables auth) |
| `-cert` | `MCSOAK_CERT` | `""` | Path to TLS certificate file (auto-generated & persisted if missing/invalid) |
| `-key` | `MCSOAK_KEY` | `""` | Path to TLS private key file (auto-generated & persisted if missing/invalid) |
| `-iface` | `MCSOAK_IFACE` | `eth0` | Network interface for eBPF reflector & `AF_PACKET` sniffer |
| `-reflector` | `MCSOAK_REFLECTOR` | `false` | Enable eBPF XDP/TC pulse reflector |
| `-tcpfp-sniff` | `MCSOAK_TCPFP_SNIFF` | `false` | Enable in-process `AF_PACKET` TCP SYN sniffer |
| `-dnsleak` | `MCSOAK_DNSLEAK` | `false` | Enable authoritative DNS leak oracle |
| `-dns-listen` | `MCSOAK_DNS_LISTEN` | `""` | Comma-separated DNS listen addresses (empty auto-binds public IPv4/IPv6 `:53`) |
| `-dns-domain` | `MCSOAK_DNS_DOMAIN` | `dns.muterconn.com` | Base domain for DNS leak oracle |
| `-dns-ns` | `MCSOAK_DNS_NS` | `ns1.dns.muterconn.com,ns2.dns.muterconn.com` | Comma-separated authoritative nameservers for DNS leak oracle |
| `-dns-validate-ns` | `MCSOAK_DNS_VALIDATE_NS` | `false` | Validate NS delegation via public resolver on startup |
| `-dns-resolver` | `MCSOAK_DNS_RESOLVER` | `1.1.1.1:53` | Resolver address used for NS delegation validation |
| `-asn-db` | `MCSOAK_ASN_DB` | `""` | Path to MaxMind .mmdb ASN database |
| — | `MCSOAK_PUBLIC_IPV4` | `""` | Public IPv4 added to auto-generated TLS SANs, DNS leak `:53` bind, and A echo |
| — | `MCSOAK_PUBLIC_IPV6` | `""` | Public IPv6 added to auto-generated TLS SANs, DNS leak `:53` bind, and AAAA echo |

## HTTP Routes & Authentication

When `-token` / `MCSOAK_TOKEN` is non-empty, all routes **except `/health`** require authentication via either:
- Header: `Authorization: Bearer <token>`
- Query parameter: `?token=<token>`

Token comparison uses constant-time comparison (`subtle.ConstantTimeCompare`). Unauthenticated requests receive `401 Unauthorized`.

| Route | Auth | Description |
| :--- | :--- | :--- |
| `/health` | Public | Returns `{"status":"ok","time":"..."}` for liveness/deployment checks |
| `/echo` | Protected | Echoes client IP, HTTP protocol, TLS info, headers, and matched TCP fingerprint |
| `/fp` | Protected | Returns passive TCP SYN fingerprint for client IP (or `?ip=<addr>`) |
| `/asn` | Protected | Returns MaxMind ASN lookup for client IP (or `?ip=<addr>`) when `-asn-db` is configured |
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
- Runs as a dedicated `mcsoak` system user with `AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_BPF CAP_PERFMON` (no full root required) and `StateDirectory=mcsoak` (`/var/lib/mcsoak` for persisted TLS cert/key).
- Applies QUIC/XDP kernel buffer tuning in `/etc/sysctl.d/99-mcsoak.conf` and preserves operator edits in `/etc/default/mcsoak`.
- Validates that `MCSOAK_PUBLIC_IPV4` or `MCSOAK_PUBLIC_IPV6` is configured when `-dnsleak` is enabled, and derives the `/health` check port from `MCSOAK_LISTEN` / `-listen`.
- After `systemctl restart mcsoak`, the script polls `https://127.0.0.1:<port>/health`. If health verification fails, `/opt/mcsoak/current` is automatically rolled back to the previous release and `mcsoak` is restarted.
