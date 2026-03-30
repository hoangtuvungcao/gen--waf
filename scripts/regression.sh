#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

cleanup() {
  if [[ -n "${GENDP_PID:-}" ]]; then kill "${GENDP_PID}" >/dev/null 2>&1 || true; fi
  if [[ -n "${SAMPLE_PID:-}" ]]; then kill "${SAMPLE_PID}" >/dev/null 2>&1 || true; fi
  if [[ -n "${CTRL_PID:-}" ]]; then kill "${CTRL_PID}" >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT

echo "[regression] building Go and C++ targets"
go build ./...
cmake -S cpp -B build >/dev/null
cmake --build build >/dev/null

fuser -k 8081/tcp >/dev/null 2>&1 || true
fuser -k 18080/tcp >/dev/null 2>&1 || true
fuser -k 18081/tcp >/dev/null 2>&1 || true

echo "[regression] validating profiles"
for f in configs/profiles/*.yaml; do
  go run ./cmd/genctl validate -config "$f" >/dev/null
done

mkdir -p runtime

echo "[regression] starting sample backend"
go run ./cmd/sampleweb -listen :8081 -name regression-web >/tmp/genwaf-regression-sample.log 2>&1 &
SAMPLE_PID=$!
sleep 1

echo "[regression] compiling effective config"
go run ./cmd/genctl compile -config configs/profiles/01-single-domain-single-backend.yaml -output runtime/effective.json >/dev/null

echo "[regression] compiling xdp profile"
./build/genxdp-loader --config runtime/effective.json --output runtime/xdp-profile.json >/dev/null
grep -q '"xdp_allowlist_entries"' runtime/xdp-profile.json

echo "[regression] starting controller for dashboard smoke test"
go run ./cmd/genctl serve -config configs/profiles/05-multi-node-shared-policy.yaml -listen :18081 >/tmp/genwaf-regression-controller.log 2>&1 &
CTRL_PID=$!
sleep 1
curl -fsS http://127.0.0.1:18081/dashboard | grep -q "GEN WAF Control Center"

echo "[regression] checking fingerprint-driven escalation"
python3 - <<'PY'
import json
import urllib.request

payload = {
    "node_id": "regression-fp",
    "window_seconds": 15,
    "observations": [
        {"client_ip": "198.51.100.11", "fingerprint_id": "fp-regression", "tls_fingerprint": "ja4:regression", "http_fingerprint": "http-regression", "requests": 20, "challenge_failures": 3, "sensitive_hits": 1},
        {"client_ip": "198.51.100.12", "fingerprint_id": "fp-regression", "tls_fingerprint": "ja4:regression", "http_fingerprint": "http-regression", "requests": 20, "challenge_failures": 3, "sensitive_hits": 1},
        {"client_ip": "198.51.100.13", "fingerprint_id": "fp-regression", "tls_fingerprint": "ja4:regression", "http_fingerprint": "http-regression", "requests": 20, "challenge_failures": 3, "sensitive_hits": 1},
        {"client_ip": "198.51.100.14", "fingerprint_id": "fp-regression", "tls_fingerprint": "ja4:regression", "http_fingerprint": "http-regression", "requests": 20, "challenge_failures": 3, "sensitive_hits": 1},
    ],
}
req = urllib.request.Request(
    "http://127.0.0.1:18081/v1/cluster/observations",
    data=json.dumps(payload).encode(),
    headers={"Content-Type": "application/json"},
    method="POST",
)
with urllib.request.urlopen(req, timeout=5) as resp:
    body = json.load(resp)
if body.get("processed", 0) < 4:
    raise SystemExit("fingerprint observation batch was not processed")
with urllib.request.urlopen("http://127.0.0.1:18081/v1/status", timeout=5) as resp:
    status = json.load(resp)
if status.get("current_mode") != "elevated":
    raise SystemExit(f"expected elevated mode, got {status.get('current_mode')!r}")
with urllib.request.urlopen("http://127.0.0.1:18081/v1/cluster/decisions", timeout=5) as resp:
    decisions = json.load(resp)
if not any(item.get("fingerprint_id") == "fp-regression" for item in decisions):
    raise SystemExit("expected fingerprint-based shared decision")
PY
curl -fsS http://127.0.0.1:18081/dashboard | grep -q "Hot Fingerprints"

echo "[regression] checking genagent shared sync outputs"
go run ./cmd/genagent \
  -controller http://127.0.0.1:18081 \
  -output runtime/effective-agent.json \
  -decisions-output runtime/cluster-decisions-agent.json \
  -rate-limits-output runtime/cluster-rate-limits-agent.json \
  -observations-input runtime/node-observations.json \
  -node-id regression-a \
  -node-addr 127.0.0.1 \
  -node-role ingress \
  -xdp-auto-apply=false \
  -once >/tmp/genwaf-regression-agent.log 2>&1
grep -q '"shared_rate_limit_path"' runtime/effective-agent.json
grep -q '"observations"' runtime/cluster-rate-limits.json

echo "[regression] starting gendp"
./build/gendp --config runtime/effective.json --port 18080 >/tmp/genwaf-regression-gendp.log 2>&1 &
GENDP_PID=$!
sleep 1

echo "[regression] checking normal request path"
curl -fsS \
  -H 'Host: test.bacsycay.click' \
  -H 'X-Edge-Verified: cloudflare' \
  -H 'CF-Connecting-IP: 198.51.100.10' \
  http://127.0.0.1:18080/ | grep -q "GEN WAF Demo"

echo "[regression] checking challenge page"
curl -sS \
  -H 'Host: test.bacsycay.click' \
  -H 'X-Edge-Verified: cloudflare' \
  -H 'CF-Connecting-IP: 198.51.100.10' \
  http://127.0.0.1:18080/login | grep -q "Protected by GEN WAF"

echo "[regression] checking request fingerprint export"
curl -sSD - \
  -H 'Host: test.bacsycay.click' \
  -H 'X-Edge-Verified: cloudflare' \
  -H 'CF-Connecting-IP: 198.51.100.21' \
  -H 'X-JA4: regression-ja4' \
  -H 'User-Agent: regression-fingerprint/1.0' \
  -H 'Accept: text/html' \
  -H 'Accept-Language: en-US' \
  http://127.0.0.1:18080/login | grep -qi '^X-GENWAF-Fingerprint:'

echo "[regression] checking chunked request support"
python3 - <<'PY'
import socket

request = (
    "POST /api/hello HTTP/1.1\r\n"
    "Host: test.bacsycay.click\r\n"
    "X-Edge-Verified: cloudflare\r\n"
    "CF-Connecting-IP: 198.51.100.10\r\n"
    "Transfer-Encoding: chunked\r\n"
    "Connection: close\r\n"
    "\r\n"
    "5\r\nhello\r\n"
    "6\r\n world\r\n"
    "0\r\n\r\n"
)

with socket.create_connection(("127.0.0.1", 18080), timeout=5) as sock:
    sock.sendall(request.encode())
    response = sock.recv(4096).decode("utf-8", "replace")

if "unsupported" in response or "501" in response:
    raise SystemExit("chunked request still unsupported")
PY

echo "[regression] checking http parser corpus"
bash ./scripts/http_parser_corpus.sh >/tmp/genwaf-http-corpus.log 2>&1

echo "[regression] all checks passed"
