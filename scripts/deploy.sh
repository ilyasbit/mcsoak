#!/usr/bin/env bash
set -euo pipefail

# Deterministic, idempotent installer & updater for mcsoak on Debian/Ubuntu VPS.
# Usage: scripts/deploy.sh [--binary <path>] [--reconfigure] [--dry-run] [--help]

APP_NAME="mcsoak"
BASE_DIR="/opt/mcsoak"
RELEASES_DIR="${BASE_DIR}/releases"
CURRENT_LINK="${BASE_DIR}/current"
KEEP_RELEASES=3

SYSCTL_CONF="/etc/sysctl.d/99-mcsoak.conf"
ENV_FILE="/etc/default/mcsoak"
SERVICE_FILE="/etc/systemd/system/mcsoak.service"
HEALTH_URL="https://127.0.0.1:8443/health"

BINARY_PATH=""
RECONFIGURE=false
DRY_RUN=false

usage() {
  cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Deterministic, idempotent installer and updater for mcsoak.

Options:
  --binary <path>   Deploy a pre-built mcsoak binary instead of building from source
  --reconfigure     Overwrite existing ${ENV_FILE} with default template
  --dry-run         Print planned actions without modifying the system
  -h, --help        Show this help message and exit
EOF
}

log() {
  printf '[deploy] %s\n' "$*"
}

run_cmd() {
  if [[ "${DRY_RUN}" == "true" ]]; then
    printf '[dry-run] %s\n' "$*"
  else
    "$@"
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --binary)
      if [[ $# -lt 2 || -z "$2" ]]; then
        echo "Error: --binary requires a file path" >&2
        exit 1
      fi
      BINARY_PATH="$2"
      shift 2
      ;;
    --reconfigure)
      RECONFIGURE=true
      shift
      ;;
    --dry-run)
      DRY_RUN=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Error: unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ "${DRY_RUN}" == "false" && "${EUID}" -ne 0 ]]; then
  echo "Error: must run as root (or use --dry-run)" >&2
  exit 1
fi

if [[ -n "${BINARY_PATH}" && ! -f "${BINARY_PATH}" ]]; then
  echo "Error: binary not found at ${BINARY_PATH}" >&2
  exit 1
fi

# Determine release identifier from git SHA or UTC timestamp fallback
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
if git -C "${REPO_ROOT}" rev-parse --short HEAD >/dev/null 2>&1; then
  RELEASE_ID="$(git -C "${REPO_ROOT}" rev-parse --short HEAD)"
else
  RELEASE_ID="$(date -u +%Y%m%d%H%M%S)"
fi

RELEASE_DIR="${RELEASES_DIR}/${RELEASE_ID}"
RELEASE_BIN="${RELEASE_DIR}/${APP_NAME}"

# 1. Ensure dedicated system user/group
if ! id -u "${APP_NAME}" >/dev/null 2>&1; then
  log "Creating system user and group '${APP_NAME}'"
  run_cmd useradd --system --no-create-home --shell /usr/sbin/nologin "${APP_NAME}"
else
  log "System user '${APP_NAME}' already exists"
fi

# 2. Prepare immutable release directory and binary
log "Preparing release ${RELEASE_ID} at ${RELEASE_DIR}"
run_cmd install -d -o "${APP_NAME}" -g "${APP_NAME}" -m 0755 "${BASE_DIR}" "${RELEASES_DIR}" "${RELEASE_DIR}"

if [[ -n "${BINARY_PATH}" ]]; then
  log "Installing pre-built binary from ${BINARY_PATH}"
  run_cmd install -o "${APP_NAME}" -g "${APP_NAME}" -m 0755 "${BINARY_PATH}" "${RELEASE_BIN}"
else
  log "Building ${APP_NAME} from source in ${REPO_ROOT}"
  if [[ "${DRY_RUN}" == "true" ]]; then
    printf '[dry-run] (cd %q && go build -o %q ./cmd/mcsoak)\n' "${REPO_ROOT}" "${RELEASE_BIN}"
  else
    (cd "${REPO_ROOT}" && go build -o "${RELEASE_BIN}" ./cmd/mcsoak)
    chown "${APP_NAME}:${APP_NAME}" "${RELEASE_BIN}"
    chmod 0755 "${RELEASE_BIN}"
  fi
fi

# 3. Idempotent sysctl configuration for QUIC UDP buffers & XDP
SYSCTL_TMP="$(mktemp)"
cat > "${SYSCTL_TMP}" <<'EOF'
# mcsoak QUIC UDP buffer & XDP/AF_PACKET tuning
net.core.rmem_max = 26214400
net.core.wmem_max = 26214400
net.core.rmem_default = 2621440
net.core.wmem_default = 2621440
net.core.netdev_max_backlog = 16384
EOF

if [[ ! -f "${SYSCTL_CONF}" ]] || ! cmp -s "${SYSCTL_TMP}" "${SYSCTL_CONF}"; then
  log "Updating ${SYSCTL_CONF} and applying sysctl settings"
  run_cmd install -o root -g root -m 0644 "${SYSCTL_TMP}" "${SYSCTL_CONF}"
  run_cmd sysctl --system >/dev/null
else
  log "${SYSCTL_CONF} is already up to date"
fi
rm -f "${SYSCTL_TMP}"

# 4. Idempotent /etc/default/mcsoak environment template
if [[ ! -f "${ENV_FILE}" || "${RECONFIGURE}" == "true" ]]; then
  log "Writing environment template to ${ENV_FILE}"
  ENV_TMP="$(mktemp)"
  cat > "${ENV_TMP}" <<'EOF'
# mcsoak operator configuration
MCSOAK_PUBLIC_IPV4=
MCSOAK_PUBLIC_IPV6=
MCSOAK_TOKEN=
MCSOAK_IFACE=eth0
MCSOAK_DNS_DOMAIN=dns.muterconn.com
MCSOAK_DNS_NS=ns1.dns.muterconn.com,ns2.dns.muterconn.com
MCSOAK_DNS_VALIDATE_NS=true
MCSOAK_CERT=/var/lib/mcsoak/cert.pem
MCSOAK_KEY=/var/lib/mcsoak/key.pem
MCSOAK_FLAGS="-listen :8443 -quic=true -quic-listen :9443 -reflector -tcpfp-sniff -dnsleak"
EOF
  run_cmd install -o root -g "${APP_NAME}" -m 0640 "${ENV_TMP}" "${ENV_FILE}"
  rm -f "${ENV_TMP}"
else
  log "Preserving existing ${ENV_FILE} (pass --reconfigure to overwrite)"
fi

# 5. Idempotent systemd unit file
UNIT_TMP="$(mktemp)"
cat > "${UNIT_TMP}" <<'EOF'
[Unit]
Description=mcsoak Unified Network & Transport Probe Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=mcsoak
Group=mcsoak
EnvironmentFile=-/etc/default/mcsoak
ExecStart=/opt/mcsoak/current/mcsoak -iface ${MCSOAK_IFACE} $MCSOAK_FLAGS
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576

# Grant minimal capabilities for :53 bind, XDP/TC eBPF reflector, and AF_PACKET sniffer
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_BPF CAP_PERFMON
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_BPF CAP_PERFMON

NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
StateDirectory=mcsoak
ReadOnlyPaths=/opt/mcsoak

[Install]
WantedBy=multi-user.target
EOF

UNIT_CHANGED=false
if [[ ! -f "${SERVICE_FILE}" ]] || ! cmp -s "${UNIT_TMP}" "${SERVICE_FILE}"; then
  log "Updating ${SERVICE_FILE}"
  run_cmd install -o root -g root -m 0644 "${UNIT_TMP}" "${SERVICE_FILE}"
  UNIT_CHANGED=true
else
  log "${SERVICE_FILE} is already up to date"
fi
rm -f "${UNIT_TMP}"

# Derive HEALTH_URL port and validate DNS leak public IP requirements from /etc/default/mcsoak
derive_health_url() {
  local listen_val=""
  local port="8443"
  if [[ -f "${ENV_FILE}" ]]; then
    local env_listen=""
    local env_flags=""
    env_listen="$(grep -E '^MCSOAK_LISTEN=' "${ENV_FILE}" | tail -n1 | cut -d= -f2- | tr -d '"' | tr -d "'" || true)"
    env_flags="$(grep -E '^MCSOAK_FLAGS=' "${ENV_FILE}" | tail -n1 | cut -d= -f2- | tr -d '"' | tr -d "'" || true)"
    if [[ "${env_flags}" =~ -listen[[:space:]]+([^[:space:]]+) ]]; then
      listen_val="${BASH_REMATCH[1]}"
    elif [[ -n "${env_listen}" ]]; then
      listen_val="${env_listen}"
    fi
  fi
  if [[ -n "${listen_val}" && "${listen_val}" =~ :([0-9]+)$ ]]; then
    port="${BASH_REMATCH[1]}"
  fi
  HEALTH_URL="https://127.0.0.1:${port}/health"
}

validate_dnsleak_env() {
  if [[ "${DRY_RUN}" == "true" || ! -f "${ENV_FILE}" ]]; then
    return 0
  fi
  local dnsleak_enabled=false
  local env_dnsleak=""
  local env_flags=""
  env_dnsleak="$(grep -E '^MCSOAK_DNSLEAK=' "${ENV_FILE}" | tail -n1 | cut -d= -f2- | tr -d '"' | tr -d "'" | xargs || true)"
  env_flags="$(grep -E '^MCSOAK_FLAGS=' "${ENV_FILE}" | tail -n1 | cut -d= -f2- | tr -d '"' | tr -d "'" || true)"
  if [[ "${env_dnsleak}" == "true" || "${env_dnsleak}" == "1" || "${env_dnsleak}" == "yes" ]]; then
    dnsleak_enabled=true
  elif [[ "${env_flags}" =~ (^|[[:space:]])-dnsleak(=true)?([[:space:]]|$) ]]; then
    dnsleak_enabled=true
  fi
  if [[ "${dnsleak_enabled}" == "true" ]]; then
    local pub_v4=""
    local pub_v6=""
    pub_v4="$(grep -E '^MCSOAK_PUBLIC_IPV4=' "${ENV_FILE}" | tail -n1 | cut -d= -f2- | tr -d '"' | tr -d "'" | xargs || true)"
    pub_v6="$(grep -E '^MCSOAK_PUBLIC_IPV6=' "${ENV_FILE}" | tail -n1 | cut -d= -f2- | tr -d '"' | tr -d "'" | xargs || true)"
    if [[ -z "${pub_v4}" && -z "${pub_v6}" ]]; then
      echo "Error: -dnsleak is enabled in ${ENV_FILE}, but both MCSOAK_PUBLIC_IPV4 and MCSOAK_PUBLIC_IPV6 are empty." >&2
      echo "Please set at least one public IP in ${ENV_FILE} before restarting ${APP_NAME}." >&2
      exit 1
    fi
  fi
}

derive_health_url
validate_dnsleak_env

# 6. Atomic symlink switch with rollback tracking
PREV_TARGET=""
if [[ -L "${CURRENT_LINK}" ]]; then
  PREV_TARGET="$(readlink -f "${CURRENT_LINK}" || true)"
fi

log "Atomically switching ${CURRENT_LINK} -> ${RELEASE_DIR}"
run_cmd ln -sfn "${RELEASE_DIR}" "${CURRENT_LINK}"

if [[ "${UNIT_CHANGED}" == "true" ]]; then
  run_cmd systemctl daemon-reload
fi
run_cmd systemctl enable "${APP_NAME}" >/dev/null 2>&1 || true
log "Restarting ${APP_NAME} service"
run_cmd systemctl restart "${APP_NAME}"

# 7. Post-restart /health verification with automatic rollback
verify_health() {
  local attempts=10
  local delay=1
  local i
  for ((i = 1; i <= attempts; i++)); do
    if curl -ksSf --max-time 3 "${HEALTH_URL}" >/dev/null 2>&1; then
      return 0
    fi
    sleep "${delay}"
  done
  return 1
}

if [[ "${DRY_RUN}" == "true" ]]; then
  log "[dry-run] Would verify ${HEALTH_URL} and rollback to '${PREV_TARGET:-none}' on failure"
else
  if verify_health; then
    log "Health check passed: ${HEALTH_URL}"
  else
    log "ERROR: Health check failed at ${HEALTH_URL}"
    if [[ -n "${PREV_TARGET}" && "${PREV_TARGET}" != "${RELEASE_DIR}" && -d "${PREV_TARGET}" ]]; then
      log "Rolling back ${CURRENT_LINK} -> ${PREV_TARGET}"
      ln -sfn "${PREV_TARGET}" "${CURRENT_LINK}"
      systemctl restart "${APP_NAME}" || true
      log "Rollback complete; previous release restored."
    else
      log "No valid previous release available for rollback."
    fi
    exit 1
  fi
fi

# 8. Prune old releases, keeping last N=3
if [[ "${DRY_RUN}" == "true" ]]; then
  log "[dry-run] Would prune old releases in ${RELEASES_DIR}, keeping last ${KEEP_RELEASES}"
else
  mapfile -t ALL_RELEASES < <(ls -1dt "${RELEASES_DIR}"/*/ 2>/dev/null | sed 's:/*$::')
  if (( ${#ALL_RELEASES[@]} > KEEP_RELEASES )); then
    for old_rel in "${ALL_RELEASES[@]:KEEP_RELEASES}"; do
      if [[ "${old_rel}" != "${RELEASE_DIR}" && "${old_rel}" != "${PREV_TARGET}" ]]; then
        log "Pruning old release ${old_rel}"
        rm -rf "${old_rel}"
      fi
    done
  fi
fi

log "Deployment of ${APP_NAME} (${RELEASE_ID}) complete."
