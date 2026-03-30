#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

DOMAIN=""
ORIGIN_ADDRESS=""
EDGE_MODE="direct"
INSTALL_PREFIX="/opt/genwaf"
CONFIG_DIR="/etc/genwaf"
STATE_DIR="/var/lib/genwaf"
PUBLIC_INTERFACE=""
SYSTEM_NAME="genwaf-production"

# Chuẩn port cố định của dự án.
WAF_PORT="80"
ADMIN_LISTEN="127.0.0.1:90"

SKIP_DEPS=0
SKIP_SYSTEMD=0
SKIP_SERVICE_USER=0
SKIP_FIREWALL=0

usage() {
  cat <<'EOF'
Usage:
  sudo ./scripts/install-vps.sh \
    --domain app.example.com \
    --origin 10.0.0.10:8080 \
    [--edge-mode direct|cloudflare] \
    [--install-prefix /opt/genwaf] \
    [--config-dir /etc/genwaf] \
    [--state-dir /var/lib/genwaf] \
    [--interface eth0] \
    [--system-name genwaf-app] \
    [--skip-deps] \
    [--skip-systemd] \
    [--skip-service-user] \
    [--skip-firewall]

Lưu ý:
- Script này phải chạy bằng root hoặc sudo nếu muốn cài thật.
- Script không nhúng hay lưu mật khẩu root vào repo.
- Nếu port 80 hoặc 90 đang bị chiếm, script sẽ cố gắng giải phóng rồi chạy lại dịch vụ.
EOF
}

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "thiếu lệnh bắt buộc: $1" >&2
    exit 1
  fi
}

detect_interface() {
  ip route get 1.1.1.1 2>/dev/null | awk '/dev/ {for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}'
}

wait_for_http() {
  local url="$1"
  local attempts="${2:-30}"
  for _ in $(seq 1 "$attempts"); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "hết thời gian chờ $url" >&2
  return 1
}

free_port_if_needed() {
  local port="$1"
  /usr/bin/fuser -k "${port}/tcp" >/dev/null 2>&1 || true
}

render_config() {
  "$ROOT_DIR/scripts/render-production-config.sh" \
    --output "$CONFIG_DIR/genwaf.yaml" \
    --domain "$DOMAIN" \
    --origin "$ORIGIN_ADDRESS" \
    --system-name "$SYSTEM_NAME" \
    --listen-port "$WAF_PORT" \
    --state-dir "$STATE_DIR" \
    --interface "$PUBLIC_INTERFACE" \
    --edge-mode "$EDGE_MODE" \
    --xdp-enabled false
}

build_binaries() {
  mkdir -p "$ROOT_DIR/build"
  go build -o "$ROOT_DIR/build/genctl" ./cmd/genctl
  cmake -S "$ROOT_DIR/cpp" -B "$ROOT_DIR/build" >/dev/null
  cmake --build "$ROOT_DIR/build" --target gendp >/dev/null
}

install_dependencies() {
  apt-get update
  apt-get install -y \
    build-essential \
    clang \
    cmake \
    curl \
    jq \
    libbpf-dev \
    libssl-dev \
    openssl \
    pkg-config \
    psmisc \
    python3
}

start_services_with_retry() {
  local attempts=5
  for _ in $(seq 1 "$attempts"); do
    free_port_if_needed 80
    free_port_if_needed 90

    systemctl restart genwaf-genctl.service || true
    systemctl restart genwaf-gendp.service || true

    if wait_for_http "http://127.0.0.1:90/healthz" 10 && wait_for_http "http://127.0.0.1:80/healthz" 10; then
      return 0
    fi
  done
  echo "không thể khởi động dịch vụ GEN WAF thành công sau nhiều lần thử" >&2
  return 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain)
      DOMAIN="$2"
      shift 2
      ;;
    --origin)
      ORIGIN_ADDRESS="$2"
      shift 2
      ;;
    --edge-mode)
      EDGE_MODE="$2"
      shift 2
      ;;
    --install-prefix)
      INSTALL_PREFIX="$2"
      shift 2
      ;;
    --config-dir)
      CONFIG_DIR="$2"
      shift 2
      ;;
    --state-dir)
      STATE_DIR="$2"
      shift 2
      ;;
    --interface)
      PUBLIC_INTERFACE="$2"
      shift 2
      ;;
    --system-name)
      SYSTEM_NAME="$2"
      shift 2
      ;;
    --skip-deps)
      SKIP_DEPS=1
      shift
      ;;
    --skip-systemd)
      SKIP_SYSTEMD=1
      shift
      ;;
    --skip-service-user)
      SKIP_SERVICE_USER=1
      shift
      ;;
    --skip-firewall)
      SKIP_FIREWALL=1
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "tham số không hợp lệ: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -z "$DOMAIN" || -z "$ORIGIN_ADDRESS" ]]; then
  usage >&2
  exit 1
fi

if [[ -z "$PUBLIC_INTERFACE" ]]; then
  PUBLIC_INTERFACE="$(detect_interface)"
fi
if [[ -z "$PUBLIC_INTERFACE" ]]; then
  PUBLIC_INTERFACE="eth0"
fi

if [[ "$SKIP_SYSTEMD" -eq 0 ]]; then
  if [[ "$INSTALL_PREFIX" != "/opt/genwaf" || "$CONFIG_DIR" != "/etc/genwaf" || "$STATE_DIR" != "/var/lib/genwaf" ]]; then
    echo "nếu bật systemd thì hiện tại phải dùng đúng đường dẫn chuẩn /opt, /etc, /var/lib" >&2
    exit 1
  fi
fi

if [[ "$SKIP_DEPS" -eq 0 || "$SKIP_SYSTEMD" -eq 0 || "$SKIP_SERVICE_USER" -eq 0 ]]; then
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "chế độ cài đặt này cần quyền root hoặc sudo" >&2
    exit 1
  fi
fi

require_command go
require_command cmake
require_command curl
require_command python3

if [[ "$SKIP_DEPS" -eq 0 ]]; then
  install_dependencies
fi

build_binaries

mkdir -p "$INSTALL_PREFIX/bin" "$CONFIG_DIR" "$STATE_DIR"

install -m 0755 "$ROOT_DIR/build/genctl" "$INSTALL_PREFIX/bin/genctl"
install -m 0755 "$ROOT_DIR/build/gendp" "$INSTALL_PREFIX/bin/gendp"

if [[ "$SKIP_SERVICE_USER" -eq 0 ]]; then
  if ! getent group genwaf >/dev/null 2>&1; then
    groupadd --system genwaf
  fi
  if ! id -u genwaf >/dev/null 2>&1; then
    useradd --system --gid genwaf --home "$STATE_DIR" --shell /usr/sbin/nologin genwaf
  fi
  chown -R genwaf:genwaf "$INSTALL_PREFIX" "$CONFIG_DIR" "$STATE_DIR"
fi

render_config

"$INSTALL_PREFIX/bin/genctl" validate -config "$CONFIG_DIR/genwaf.yaml" >/dev/null
"$INSTALL_PREFIX/bin/genctl" compile -config "$CONFIG_DIR/genwaf.yaml" -output "$STATE_DIR/effective.json" >/dev/null

cat > "$CONFIG_DIR/genwaf.env" <<EOF
GENWAF_PORT=$WAF_PORT
GENWAF_ADMIN_LISTEN=$ADMIN_LISTEN
GENWAF_CONFIG=$CONFIG_DIR/genwaf.yaml
GENWAF_EFFECTIVE=$STATE_DIR/effective.json
EOF

if [[ "$SKIP_SYSTEMD" -eq 0 ]]; then
  install -m 0644 "$ROOT_DIR/deploy/systemd/genwaf-gendp.service" /etc/systemd/system/genwaf-gendp.service
  install -m 0644 "$ROOT_DIR/deploy/systemd/genwaf-genctl.service" /etc/systemd/system/genwaf-genctl.service
  systemctl daemon-reload
  systemctl enable genwaf-genctl.service
  systemctl enable genwaf-gendp.service
  start_services_with_retry
fi

if [[ "$SKIP_FIREWALL" -eq 0 ]] && command -v ufw >/dev/null 2>&1; then
  ufw allow 80/tcp >/dev/null 2>&1 || true
fi

cat <<EOF
cài đặt hoàn tất
config: $CONFIG_DIR/genwaf.yaml
effective: $STATE_DIR/effective.json
waf public: http://$DOMAIN:80/
admin nội bộ: http://127.0.0.1:90/dashboard
EOF
