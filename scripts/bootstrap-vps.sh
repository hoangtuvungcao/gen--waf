#!/usr/bin/env bash
set -euo pipefail

REPO_URL=""
REPO_REF="main"
WORK_DIR="/tmp/genwaf-bootstrap"
INSTALL_ARGS=()

usage() {
  cat <<'EOF'
Usage:
  curl -fsSL https://raw.githubusercontent.com/<org>/<repo>/main/scripts/bootstrap-vps.sh | \
    sudo bash -s -- \
      --repo-url https://github.com/<org>/<repo>.git \
      --repo-ref main \
      --domain app.example.com \
      --origin 10.0.0.10:8080 \
      [--edge-mode cloudflare]
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

if [[ -z "$REPO_URL" ]]; then
  echo "bắt buộc phải truyền --repo-url" >&2
  usage >&2
  exit 1
fi

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "bootstrap cần chạy bằng root hoặc sudo" >&2
  exit 1
fi

apt-get update
apt-get install -y ca-certificates curl git

rm -rf "$WORK_DIR"
git clone --depth 1 --branch "$REPO_REF" "$REPO_URL" "$WORK_DIR"

cd "$WORK_DIR"
bash ./scripts/install-vps.sh "${INSTALL_ARGS[@]}"
