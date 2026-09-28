#!/usr/bin/env bash
set -euo pipefail

REMOTE_HOST="${MCSOAK_REMOTE_HOST:-de1.muterconn.com}"
REMOTE_USER="${MCSOAK_REMOTE_USER:-root}"
REMOTE_DEST="/usr/local/bin/mcsoak"

echo "==> Building mcsoak for linux/arm64..."
mkdir -p bin
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o bin/mcsoak-linux-arm64 ./cmd/mcsoak

echo "==> Deploying binary to ${REMOTE_USER}@${REMOTE_HOST}..."
scp bin/mcsoak-linux-arm64 "${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_DEST}.new"

ssh "${REMOTE_USER}@${REMOTE_HOST}" bash -c "
  mv ${REMOTE_DEST}.new ${REMOTE_DEST}
  chmod +x ${REMOTE_DEST}

  cat << 'EOF' > /etc/systemd/system/mc-soak-server.service
[Unit]
Description=MCSOak Soak Test Daemon
After=network.target

[Service]
Type=simple
User=nobody
WorkingDirectory=/tmp
ExecStart=/usr/local/bin/mcsoak -listen :9443 -tcpfp http://127.0.0.1:8080
Restart=always
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now mc-soak-server
  systemctl restart mc-soak-server
"

echo "==> Verifying remote /health endpoint over IPv6/HTTPS..."
curl -k -fsSL --ipv6 "https://${REMOTE_HOST}:9443/health" || curl -k -fsSL "https://${REMOTE_HOST}:9443/health"
echo "\n==> Deployment successfully verified."
