# mcsoak

Standalone soak testing target and in-process mock server library for Muterconn networks.

`mcsoak` provides high-concurrency HTTP/1.1, HTTP/2, TLS, and WebSocket soak endpoints capable of verifying client connection pooling, keep-alives, burst decompressions, and TCP fingerprinting telemetry.

## Architecture Overview

`mcsoak` is engineered with dual usage in mind:
1. **Standalone Daemon**: Deployed as a continuous soak testing target (e.g. in Frankfurt WAN target on port `9443`) handling continuous synthetic traffic and thundering-herd scenarios.
2. **In-process Library**: Can be embedded directly into Go test suites or integration test benches for sub-minute stress testing, race condition detection, and benchmark runs.

```
+-------------------------------------------------------------+
|                        mcsoak Server                        |
|                                                             |
|  /health            - Health check (200 OK)                 |
|  /api/echo          - Echoes client headers, proto, TLS     |
|  /api/fingerprint   - Echoes headers + queries tcp-fp       |
|  /ws                - WebSocket RFC 6455 echo & ping/pong   |
|  /page              - HTML5 page referencing 50 subassets   |
|  /assets/           - Deterministic JS/CSS/SVG payloads     |
|  /burst             - Pre-gzipped 10KB JSON payload         |
+------------------------------+------------------------------+
                               |
                (Optional internal query)
                               v
                  +-------------------------+
                  |      tcp-fp Daemon      |
                  |    (:8080/check?ip=...) |
                  +-------------------------+
```

## Endpoints Specification

- `GET /health`:
  Returns `{"status": "ok", "time": "<RFC3339Nano>"}` with `200 OK`.
- `GET /api/echo`:
  Returns client IP, protocol, TLS metadata (version, cipher suite, negotiated ALPN), and request headers.
- `GET /api/fingerprint`:
  Same as `/api/echo`, but also queries a local or remote `tcp-fp` daemon (`?ip=<clientIP>`) within 500ms and merges the resulting TCP fingerprint object.
- `GET /ws`:
  WebSocket endpoint supporting text and binary bidirectional frame echo and ping/pong keepalive frames.
- `GET /page`:
  Lightweight HTML page requesting 50 sub-resources (15 CSS stylesheets, 10 SVG icons, 25 JS scripts) and establishing a WebSocket connection.
- `GET /assets/(chunk|style|img)_<index>.(js|css|svg)`:
  Dynamically generated, deterministic 2KB assets with appropriate MIME types for multiplexing and asset pipelining soak tests.
- `GET /burst`:
  Returns a pre-compressed ~10KB payload with `Content-Encoding: gzip` to test decompression pipelines under high load.

## CLI Usage

```bash
# Run with auto-generated self-signed certificates
go run ./cmd/mcsoak -listen :9443

# Run with custom TLS certificates and TCP fingerprint daemon integration
go run ./cmd/mcsoak \
  -listen :9443 \
  -cert /path/to/cert.pem \
  -key /path/to/key.pem \
  -tcpfp http://127.0.0.1:8080
```

Configuration can also be passed via environment variables:
- `MCSOAK_LISTEN` (default: `:9443`)
- `MCSOAK_CERT_FILE`
- `MCSOAK_KEY_FILE`
- `MCSOAK_TCP_FP_URL` (default: `http://127.0.0.1:8080`)

## In-Process Library Usage

```go
package main

import (
    "net/http/httptest"
    "github.com/ilyasbit/mcsoak"
)

func main() {
    srv := mcsoak.NewServer("http://127.0.0.1:8080")
    ts := httptest.NewServer(srv.Routes())
    defer ts.Close()

    // Execute soak or benchmark requests against ts.URL
}
```

## Running Tests

Run the test suite with the race detector enabled:

```bash
go test -v -race ./...
go vet ./...
```

## Deployment

Deployment automation for Frankfurt WAN target (`de1.muterconn.com`) is provided in `scripts/deploy.sh`:

```bash
chmod +x scripts/deploy.sh
./scripts/deploy.sh
```

The script cross-compiles a static `linux/arm64` binary, transfers it to the target host via SCP, configures and restarts the systemd unit `mc-soak-server`, and verifies the remote `/health` endpoint over IPv6/HTTPS.
