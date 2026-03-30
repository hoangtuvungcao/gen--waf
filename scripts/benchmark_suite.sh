#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

OUT_DIR="${1:-runtime/benchmarks/$(date -u +%Y%m%dT%H%M%SZ)}"
BASELINE_PROFILE="${BASELINE_PROFILE:-configs/benchmarks/edge-baseline.json}"
MOBILE_PROFILE="${MOBILE_PROFILE:-configs/benchmarks/mobile-lossy.json}"
CERT_DIR="${CERT_DIR:-runtime/dev-edge-certs}"
CERT_FILE="${CERT_FILE:-$CERT_DIR/cert.pem}"
KEY_FILE="${KEY_FILE:-$CERT_DIR/key.pem}"

mkdir -p "$OUT_DIR"

cleanup() {
  if [[ -n "${EDGE_PID:-}" ]]; then kill "${EDGE_PID}" >/dev/null 2>&1 || true; fi
  if [[ -n "${GENDP_PID:-}" ]]; then kill "${GENDP_PID}" >/dev/null 2>&1 || true; fi
  if [[ -n "${SAMPLE_PID:-}" ]]; then kill "${SAMPLE_PID}" >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT

profile_value() {
  local profile="$1"
  local query="$2"
  jq -r "$query" "$profile"
}

run_edge_case() {
  local profile="$1"
  local label="$2"
  local path="$3"
  local protocol="$4"
  local output_name="$5"
  local concurrency
  local duration_seconds
  local timeout_ms
  local vary_client_ip
  local request_jitter
  local close_idle
  local disable_keepalives

  if [[ "$path" == "/login" ]]; then
    concurrency="$(profile_value "$profile" '.challenge_concurrency')"
  else
    concurrency="$(profile_value "$profile" '.pass_through_concurrency')"
  fi
  duration_seconds="$(profile_value "$profile" '.duration_seconds')"
  timeout_ms="$(profile_value "$profile" '.timeout_ms')"
  vary_client_ip="$(profile_value "$profile" '.vary_client_ip')"
  request_jitter="$(profile_value "$profile" '.request_jitter_max_ms')"
  close_idle="$(profile_value "$profile" '.close_idle_every_request')"
  disable_keepalives="$(profile_value "$profile" '.disable_keepalives')"

  echo "[benchmark] ${label} ${path} over ${protocol}"
  go run ./cmd/genbench \
    -target "https://127.0.0.1:18443${path}" \
    -protocol "$protocol" \
    -host test.bacsycay.click \
    -concurrency "$concurrency" \
    -duration "${duration_seconds}s" \
    -timeout "${timeout_ms}ms" \
    -vary-client-ip="$vary_client_ip" \
    -client-ip-header X-GenWAF-Benchmark-Client-IP \
    -request-jitter-max-ms "$request_jitter" \
    -close-idle-every-request="$close_idle" \
    -disable-keepalives="$disable_keepalives" \
    -send-edge-headers=false \
    -insecure-skip-verify \
    -json > "$OUT_DIR/$output_name"
}

echo "[benchmark] output dir: $OUT_DIR"
echo "[benchmark] building binaries"
go build ./...
cmake -S cpp -B build >/dev/null
cmake --build build >/dev/null

fuser -k 8081/tcp >/dev/null 2>&1 || true
fuser -k 18080/tcp >/dev/null 2>&1 || true
fuser -k 18443/tcp >/dev/null 2>&1 || true
fuser -k 18443/udp >/dev/null 2>&1 || true

mkdir -p "$CERT_DIR"
if [[ ! -f "$CERT_FILE" || ! -f "$KEY_FILE" ]]; then
  echo "[benchmark] generating self-signed cert for genedge"
  openssl req -x509 -newkey rsa:2048 -sha256 -nodes \
    -keyout "$KEY_FILE" \
    -out "$CERT_FILE" \
    -days 2 \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1
fi

echo "[benchmark] starting sample backend"
go run ./cmd/sampleweb -listen :8081 -name benchmark-web >/tmp/genwaf-benchmark-sample.log 2>&1 &
SAMPLE_PID=$!
sleep 1

echo "[benchmark] compiling effective config"
go run ./cmd/genctl compile -config configs/profiles/01-single-domain-single-backend.yaml -output runtime/effective.json >/dev/null

echo "[benchmark] starting gendp"
./build/gendp --config runtime/effective.json --port 18080 >/tmp/genwaf-benchmark-gendp.log 2>&1 &
GENDP_PID=$!
sleep 1

echo "[benchmark] starting genedge"
go run ./cmd/genedge \
  -listen :18443 \
  -upstream http://127.0.0.1:18080 \
  -cert "$CERT_FILE" \
  -key "$KEY_FILE" >/tmp/genwaf-benchmark-genedge.log 2>&1 &
EDGE_PID=$!
sleep 2

echo "[benchmark] direct gendp baseline pass-through"
go run ./cmd/genbench \
  -target http://127.0.0.1:18080/ \
  -host test.bacsycay.click \
  -concurrency 32 \
  -duration 5s \
  -vary-client-ip \
  -json > "$OUT_DIR/pass_through.json"

echo "[benchmark] direct gendp challenge-heavy route"
go run ./cmd/genbench \
  -target http://127.0.0.1:18080/login \
  -host test.bacsycay.click \
  -concurrency 16 \
  -duration 5s \
  -vary-client-ip \
  -json > "$OUT_DIR/challenge_route.json"

while IFS= read -r protocol; do
  run_edge_case "$BASELINE_PROFILE" "edge-baseline" "/" "$protocol" "edge_baseline_pass_${protocol}.json"
  run_edge_case "$BASELINE_PROFILE" "edge-baseline" "/login" "$protocol" "edge_baseline_challenge_${protocol}.json"
done < <(profile_value "$BASELINE_PROFILE" '.protocols[]')

while IFS= read -r protocol; do
  run_edge_case "$MOBILE_PROFILE" "mobile-lossy" "/" "$protocol" "mobile_lossy_pass_${protocol}.json"
  run_edge_case "$MOBILE_PROFILE" "mobile-lossy" "/login" "$protocol" "mobile_lossy_challenge_${protocol}.json"
done < <(profile_value "$MOBILE_PROFILE" '.protocols[]')

echo "[benchmark] runtime status snapshot"
curl -fsS http://127.0.0.1:18080/__genwaf/status > "$OUT_DIR/gendp-status.json"

echo "[benchmark] suite complete"
echo "[benchmark] artifacts:"
find "$OUT_DIR" -maxdepth 1 -type f -name '*.json' | sort | sed 's#^#  - #'
