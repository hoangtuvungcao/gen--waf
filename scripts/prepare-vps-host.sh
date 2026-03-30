#!/usr/bin/env bash
set -euo pipefail

GO_VERSION="latest"
SKIP_GO=0
SKIP_SYSCTL=0
SKIP_FIREWALL=0
CHECK_ONLY=0

usage() {
  cat <<'EOF'
Usage:
  sudo ./scripts/prepare-vps-host.sh \
    [--go-version latest|go1.x.y] \
    [--skip-go] \
    [--skip-sysctl] \
    [--skip-firewall]

Mục tiêu:
- chuẩn bị một VPS trắng thành môi trường phù hợp để build và chạy GEN WAF
- cài toolchain hệ thống, Go, thư viện build, và tinh chỉnh kernel cơ bản

Chế độ kiểm tra:
  ./scripts/prepare-vps-host.sh --check-only
EOF
}

log() {
  echo "[prepare-host] $*"
}

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "script này cần chạy bằng root hoặc sudo" >&2
    exit 1
  fi
}

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64)
      echo "amd64"
      ;;
    aarch64|arm64)
      echo "arm64"
      ;;
    *)
      echo "kiến trúc chưa được hỗ trợ: $(uname -m)" >&2
      exit 1
      ;;
  esac
}

resolve_go_version() {
  if [[ "$GO_VERSION" != "latest" ]]; then
    echo "$GO_VERSION"
    return 0
  fi

  curl -fsSL "https://go.dev/dl/?mode=json" | python3 -c '
import json
import sys

items = json.load(sys.stdin)
for item in items:
    if item.get("stable"):
        print(item["version"])
        break
else:
    raise SystemExit("không lấy được phiên bản Go stable mới nhất")
'
}

install_base_packages() {
  log "cài gói hệ thống cần thiết"
  apt-get update
  apt-get install -y \
    build-essential \
    ca-certificates \
    clang \
    cmake \
    curl \
    git \
    jq \
    libbpf-dev \
    libssl-dev \
    openssl \
    pkg-config \
    psmisc \
    python3 \
    tar \
    ufw \
    xz-utils
}

install_go() {
  local version arch archive url tmp_dir
  version="$(resolve_go_version)"
  arch="$(detect_arch)"
  archive="${version}.linux-${arch}.tar.gz"
  url="https://go.dev/dl/${archive}"
  tmp_dir="$(mktemp -d)"

  log "cài Go ${version} cho ${arch}"
  curl -fsSL "$url" -o "${tmp_dir}/${archive}"
  rm -rf /usr/local/go
  tar -C /usr/local -xzf "${tmp_dir}/${archive}"
  ln -sf /usr/local/go/bin/go /usr/local/bin/go
  ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt

  cat > /etc/profile.d/genwaf-go.sh <<'EOF'
export PATH="/usr/local/go/bin:$PATH"
EOF

  rm -rf "$tmp_dir"
  log "đã cài $(/usr/local/go/bin/go version)"
}

apply_sysctl_profile() {
  log "ghi profile sysctl cho GEN WAF"
  cat > /etc/sysctl.d/99-genwaf.conf <<'EOF'
# Tinh chỉnh cơ bản để reverse proxy chịu tải ổn hơn.
net.core.somaxconn = 4096
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_syncookies = 1
net.ipv4.ip_local_port_range = 10240 65535
net.ipv4.tcp_fin_timeout = 15
EOF

  sysctl --system >/dev/null
}

configure_firewall() {
  if ! command -v ufw >/dev/null 2>&1; then
    return 0
  fi

  log "mở firewall cho SSH và cổng public 80"
  ufw allow OpenSSH >/dev/null 2>&1 || true
  ufw allow 80/tcp >/dev/null 2>&1 || true
}

print_plan() {
  local arch go_version
  arch="$(detect_arch)"
  if [[ "$SKIP_GO" -eq 0 ]]; then
    go_version="$(resolve_go_version)"
  else
    go_version="bo qua"
  fi

  cat <<EOF
kiem_tra=ok
kien_truc=${arch}
go=${go_version}
sysctl=$([[ "$SKIP_SYSCTL" -eq 0 ]] && echo bat || echo tat)
firewall=$([[ "$SKIP_FIREWALL" -eq 0 ]] && echo bat || echo tat)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --go-version)
      GO_VERSION="$2"
      shift 2
      ;;
    --skip-go)
      SKIP_GO=1
      shift
      ;;
    --skip-sysctl)
      SKIP_SYSCTL=1
      shift
      ;;
    --skip-firewall)
      SKIP_FIREWALL=1
      shift
      ;;
    --check-only)
      CHECK_ONLY=1
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

if [[ "$CHECK_ONLY" -eq 1 ]]; then
  print_plan
  exit 0
fi

require_root
install_base_packages

if [[ "$SKIP_GO" -eq 0 ]]; then
  install_go
fi

if [[ "$SKIP_SYSCTL" -eq 0 ]]; then
  apply_sysctl_profile
fi

if [[ "$SKIP_FIREWALL" -eq 0 ]]; then
  configure_firewall
fi

log "môi trường VPS đã sẵn sàng để cài GEN WAF"
