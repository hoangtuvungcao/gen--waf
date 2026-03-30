#!/usr/bin/env bash
set -euo pipefail

REPO_URL="https://github.com/hoangtuvungcao/gen--waf.git"
REPO_REF="main"
WORK_DIR="/opt/genwaf-src"
INSTALL_ARGS=()

usage() {
  cat <<'EOF'
Usage:
  curl -fsSL https://raw.githubusercontent.com/hoangtuvungcao/gen--waf/main/scripts/bootstrap-vps.sh | \
    sudo bash -s -- \
      --domain app.example.com \
      --origin 10.0.0.10:8080 \
      [--edge-mode cloudflare]

Tác dụng:
- cài công cụ nền cho VPS trắng
- clone source code mới nhất
- chuẩn bị môi trường build/run cho GEN WAF
- gọi installer production chính
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo-url)
      REPO_URL="$2"
      shift 2
      ;;
    --repo-ref)
      REPO_REF="$2"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      INSTALL_ARGS+=("$1")
      shift
      ;;
  esac
done

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "bootstrap cần chạy bằng root hoặc sudo" >&2
  exit 1
fi

apt-get update
apt-get install -y ca-certificates curl git

rm -rf "$WORK_DIR"
git clone --depth 1 --branch "$REPO_REF" "$REPO_URL" "$WORK_DIR"

cd "$WORK_DIR"
bash ./scripts/prepare-vps-host.sh --skip-firewall
bash ./scripts/install-vps.sh --skip-deps "${INSTALL_ARGS[@]}"
