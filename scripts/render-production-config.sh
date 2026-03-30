#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

TEMPLATE_PATH="${TEMPLATE_PATH:-$ROOT_DIR/configs/templates/single-node.vps.yaml.tmpl}"
OUTPUT_PATH=""
DOMAIN=""
ORIGIN_ADDRESS=""
SYSTEM_NAME="genwaf-production"
LISTEN_PORT="80"
STATE_DIR="/var/lib/genwaf"
PUBLIC_INTERFACE=""
EDGE_MODE="direct"
XDP_ENABLED="false"

usage() {
  cat <<'EOF'
Usage:
  ./scripts/render-production-config.sh \
    --output /etc/genwaf/genwaf.yaml \
    --domain app.example.com \
    --origin 10.0.0.10:8080 \
    [--system-name genwaf-app] \
    [--state-dir /var/lib/genwaf] \
    [--interface eth0] \
    [--edge-mode direct|cloudflare] \
    [--xdp-enabled true|false]

Ghi chú:
- port public chuẩn của GEN WAF là 80
- port admin genctl được giữ riêng ở installer/systemd là 90
EOF
}

detect_interface() {
  ip route get 1.1.1.1 2>/dev/null | awk '/dev/ {for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output)
      OUTPUT_PATH="$2"
      shift 2
      ;;
    --domain)
      DOMAIN="$2"
      shift 2
      ;;
    --origin)
      ORIGIN_ADDRESS="$2"
      shift 2
      ;;
    --system-name)
      SYSTEM_NAME="$2"
      shift 2
      ;;
    --listen-port)
      LISTEN_PORT="$2"
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
    --edge-mode)
      EDGE_MODE="$2"
      shift 2
      ;;
    --xdp-enabled)
      XDP_ENABLED="$2"
      shift 2
      ;;
    --template)
      TEMPLATE_PATH="$2"
      shift 2
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

if [[ -z "$OUTPUT_PATH" || -z "$DOMAIN" || -z "$ORIGIN_ADDRESS" ]]; then
  usage >&2
  exit 1
fi

if [[ -z "$PUBLIC_INTERFACE" ]]; then
  PUBLIC_INTERFACE="$(detect_interface)"
fi
if [[ -z "$PUBLIC_INTERFACE" ]]; then
  PUBLIC_INTERFACE="eth0"
fi

case "$EDGE_MODE" in
  direct)
    EDGE_ENABLED="false"
    LOCK_ORIGIN_TO_CF="false"
    TRUST_CF_HEADERS="false"
    REAL_IP_FROM_EDGE_ONLY="false"
    ALLOW_CF_ONLY="false"
    ;;
  cloudflare)
    EDGE_ENABLED="true"
    LOCK_ORIGIN_TO_CF="true"
    TRUST_CF_HEADERS="true"
    REAL_IP_FROM_EDGE_ONLY="true"
    ALLOW_CF_ONLY="false"
    ;;
  *)
    echo "edge-mode chỉ nhận direct hoặc cloudflare" >&2
    exit 1
    ;;
esac

case "$XDP_ENABLED" in
  true)
    XDP_MODE="adaptive"
    PER_IP_GUARD="true"
    ;;
  false)
    XDP_MODE="off"
    PER_IP_GUARD="false"
    ;;
  *)
    echo "xdp-enabled chỉ nhận true hoặc false" >&2
    exit 1
    ;;
esac

mkdir -p "$(dirname "$OUTPUT_PATH")"

python3 - \
  "$TEMPLATE_PATH" \
  "$OUTPUT_PATH" \
  "$SYSTEM_NAME" \
  "$DOMAIN" \
  "$ORIGIN_ADDRESS" \
  "$LISTEN_PORT" \
  "$STATE_DIR" \
  "$PUBLIC_INTERFACE" \
  "$EDGE_ENABLED" \
  "$LOCK_ORIGIN_TO_CF" \
  "$TRUST_CF_HEADERS" \
  "$REAL_IP_FROM_EDGE_ONLY" \
  "$ALLOW_CF_ONLY" \
  "$XDP_ENABLED" \
  "$XDP_MODE" \
  "$PER_IP_GUARD" <<'PY'
import pathlib
import sys

template_path = pathlib.Path(sys.argv[1])
output_path = pathlib.Path(sys.argv[2])
body = template_path.read_text()
replacements = {
    "__SYSTEM_NAME__": sys.argv[3],
    "__DOMAIN__": sys.argv[4],
    "__ORIGIN_ADDRESS__": sys.argv[5],
    "__LISTEN_PORT__": sys.argv[6],
    "__STATE_DIR__": sys.argv[7],
    "__PUBLIC_INTERFACE__": sys.argv[8],
    "__EDGE_ENABLED__": sys.argv[9],
    "__LOCK_ORIGIN_TO_CF__": sys.argv[10],
    "__TRUST_CF_HEADERS__": sys.argv[11],
    "__REAL_IP_FROM_EDGE_ONLY__": sys.argv[12],
    "__ALLOW_CF_ONLY__": sys.argv[13],
    "__XDP_ENABLED__": sys.argv[14],
    "__XDP_MODE__": sys.argv[15],
    "__PER_IP_GUARD__": sys.argv[16],
}
for key, value in replacements.items():
    body = body.replace(key, value)
output_path.write_text(body)
PY

echo "đã render config tại: $OUTPUT_PATH"
