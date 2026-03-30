#!/usr/bin/env bash
set -euo pipefail

WAF_URL="http://127.0.0.1:80"
ADMIN_URL="http://127.0.0.1:90"
HOST_HEADER=""

usage() {
  cat <<'EOF'
Usage:
  ./scripts/smoke-install.sh \
    --waf-url http://127.0.0.1:80 \
    --admin-url http://127.0.0.1:90 \
    --host app.example.com
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --waf-url)
      WAF_URL="$2"
      shift 2
      ;;
    --admin-url)
      ADMIN_URL="$2"
      shift 2
      ;;
    --host)
      HOST_HEADER="$2"
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

if [[ -z "$HOST_HEADER" ]]; then
  echo "bắt buộc phải truyền --host" >&2
  exit 1
fi

curl -fsS "$WAF_URL/healthz" >/dev/null
curl -fsS "$ADMIN_URL/healthz" >/dev/null

STATUS_JSON="$(curl -fsS "$WAF_URL/__genwaf/status")"
HEALTHY_BACKENDS="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("healthy_backends", 0))' <<<"$STATUS_JSON")"
if [[ "$HEALTHY_BACKENDS" -lt 1 ]]; then
  echo "mong đợi ít nhất một backend healthy, hiện tại là $HEALTHY_BACKENDS" >&2
  exit 1
fi

ROOT_STATUS="$(curl -sS -o /tmp/genwaf-smoke-root.out -w '%{http_code}' -H "Host: $HOST_HEADER" "$WAF_URL/")"
if [[ "$ROOT_STATUS" != "200" ]]; then
  echo "request vào / phải trả 200, nhưng đang là $ROOT_STATUS" >&2
  exit 1
fi

LOGIN_STATUS="$(curl -sS -o /tmp/genwaf-smoke-login.out -w '%{http_code}' -H "Host: $HOST_HEADER" "$WAF_URL/login")"
if [[ "$LOGIN_STATUS" != "403" ]]; then
  echo "request vào /login phải trả 403 challenge, nhưng đang là $LOGIN_STATUS" >&2
  exit 1
fi

grep -q "Protected by GEN WAF" /tmp/genwaf-smoke-login.out

curl -fsS "$ADMIN_URL/v1/effective" >/dev/null
curl -fsS "$ADMIN_URL/v1/status" >/dev/null

echo "smoke test đã pass"
