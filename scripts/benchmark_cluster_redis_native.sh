#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

OUT_DIR="${1:-runtime/benchmarks/cluster-redis-native}"
PROFILE="${PROFILE:-configs/benchmarks/cluster-redis-native.json}"
CONFIG_PATH="${CONFIG_PATH:-configs/profiles/06-multi-node-redis-native-benchmark.yaml}"
CERT_DIR="${CERT_DIR:-runtime/dev-edge-certs}"
CERT_FILE="${CERT_FILE:-$CERT_DIR/cert.pem}"
KEY_FILE="${KEY_FILE:-$CERT_DIR/key.pem}"
REDIS_ADDR="${REDIS_ADDR:-127.0.0.1:16379}"

mkdir -p "$OUT_DIR"

cleanup() {
  if [[ -n "${EDGE_A_PID:-}" ]]; then kill "${EDGE_A_PID}" >/dev/null 2>&1 || true; fi
  if [[ -n "${EDGE_B_PID:-}" ]]; then kill "${EDGE_B_PID}" >/dev/null 2>&1 || true; fi
  if [[ -n "${GENDP_A_PID:-}" ]]; then kill "${GENDP_A_PID}" >/dev/null 2>&1 || true; fi
  if [[ -n "${GENDP_B_PID:-}" ]]; then kill "${GENDP_B_PID}" >/dev/null 2>&1 || true; fi
  if [[ -n "${REDIS_PID:-}" ]]; then kill "${REDIS_PID}" >/dev/null 2>&1 || true; fi
  if [[ -n "${SAMPLE_A_PID:-}" ]]; then kill "${SAMPLE_A_PID}" >/dev/null 2>&1 || true; fi
  if [[ -n "${SAMPLE_B_PID:-}" ]]; then kill "${SAMPLE_B_PID}" >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT

profile_value() {
  local profile="$1"
  local query="$2"
  jq -r "$query" "$profile"
}

patch_effective_paths() {
  local src="$1"
  local dst="$2"
  local node_dir="$3"
  jq \
    --arg obs "$node_dir/node-observations.json" \
    --arg dec "$node_dir/cluster-decisions.json" \
    --arg rl "$node_dir/cluster-rate-limits.json" \
    '.local_observation_path = $obs | .local_decision_path = $dec | .shared_rate_limit_path = $rl' \
    "$src" > "$dst"
}

run_cluster_case() {
  local path="$1"
  local protocol="$2"
  local output_name="$3"
  local concurrency
  local duration_seconds
  local timeout_ms
  local vary_client_ip
  local request_jitter
  local close_idle
  local disable_keepalives

  if [[ "$path" == "/login" ]]; then
    concurrency="$(profile_value "$PROFILE" '.challenge_concurrency')"
  else
    concurrency="$(profile_value "$PROFILE" '.pass_through_concurrency')"
  fi
  duration_seconds="$(profile_value "$PROFILE" '.duration_seconds')"
  timeout_ms="$(profile_value "$PROFILE" '.timeout_ms')"
  vary_client_ip="$(profile_value "$PROFILE" '.vary_client_ip')"
  request_jitter="$(profile_value "$PROFILE" '.request_jitter_max_ms')"
  close_idle="$(profile_value "$PROFILE" '.close_idle_every_request')"
  disable_keepalives="$(profile_value "$PROFILE" '.disable_keepalives')"

  echo "[cluster-benchmark] ${path} over ${protocol}"
  go run ./cmd/genbench \
    -targets "https://127.0.0.1:18443${path},https://127.0.0.1:18444${path}" \
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

echo "[cluster-benchmark] output dir: $OUT_DIR"
echo "[cluster-benchmark] building binaries"
go build ./...
cmake -S cpp -B build >/dev/null
cmake --build build >/dev/null

echo "[cluster-benchmark] validating config"
go run ./cmd/genctl validate -config "$CONFIG_PATH" >/dev/null

fuser -k 8081/tcp >/dev/null 2>&1 || true
fuser -k 8082/tcp >/dev/null 2>&1 || true
fuser -k 18080/tcp >/dev/null 2>&1 || true
fuser -k 18082/tcp >/dev/null 2>&1 || true
fuser -k 18443/tcp >/dev/null 2>&1 || true
fuser -k 18443/udp >/dev/null 2>&1 || true
fuser -k 18444/tcp >/dev/null 2>&1 || true
fuser -k 18444/udp >/dev/null 2>&1 || true
fuser -k 16379/tcp >/dev/null 2>&1 || true

mkdir -p "$CERT_DIR" runtime/cluster-bench/node-a runtime/cluster-bench/node-b
if [[ ! -f "$CERT_FILE" || ! -f "$KEY_FILE" ]]; then
  echo "[cluster-benchmark] generating self-signed cert for genedge"
  openssl req -x509 -newkey rsa:2048 -sha256 -nodes \
    -keyout "$KEY_FILE" \
    -out "$CERT_FILE" \
    -days 2 \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1
fi

echo "[cluster-benchmark] starting embedded redis"
go run ./cmd/genredisdev -listen "$REDIS_ADDR" >/tmp/genwaf-cluster-bench-redis.log 2>&1 &
REDIS_PID=$!
sleep 1

echo "[cluster-benchmark] starting sample backends"
go run ./cmd/sampleweb -listen :8081 -name cluster-app-a >/tmp/genwaf-cluster-bench-sample-a.log 2>&1 &
SAMPLE_A_PID=$!
go run ./cmd/sampleweb -listen :8082 -name cluster-app-b >/tmp/genwaf-cluster-bench-sample-b.log 2>&1 &
SAMPLE_B_PID=$!
sleep 1

echo "[cluster-benchmark] compiling node configs"
go run ./cmd/genctl compile -config "$CONFIG_PATH" -output runtime/cluster-bench/base-effective.json >/dev/null
patch_effective_paths runtime/cluster-bench/base-effective.json runtime/cluster-bench/node-a/effective.json runtime/cluster-bench/node-a
patch_effective_paths runtime/cluster-bench/base-effective.json runtime/cluster-bench/node-b/effective.json runtime/cluster-bench/node-b

echo "[cluster-benchmark] starting gendp nodes"
./build/gendp --config runtime/cluster-bench/node-a/effective.json --port 18080 >/tmp/genwaf-cluster-bench-gendp-a.log 2>&1 &
GENDP_A_PID=$!
./build/gendp --config runtime/cluster-bench/node-b/effective.json --port 18082 >/tmp/genwaf-cluster-bench-gendp-b.log 2>&1 &
GENDP_B_PID=$!
sleep 1

echo "[cluster-benchmark] starting genedge nodes"
go run ./cmd/genedge \
  -listen :18443 \
  -upstream http://127.0.0.1:18080 \
  -cert "$CERT_FILE" \
  -key "$KEY_FILE" >/tmp/genwaf-cluster-bench-edge-a.log 2>&1 &
EDGE_A_PID=$!
go run ./cmd/genedge \
  -listen :18444 \
  -upstream http://127.0.0.1:18082 \
  -cert "$CERT_FILE" \
  -key "$KEY_FILE" >/tmp/genwaf-cluster-bench-edge-b.log 2>&1 &
EDGE_B_PID=$!
sleep 2

while IFS= read -r protocol; do
  run_cluster_case "/" "$protocol" "cluster_pass_${protocol}.json"
  run_cluster_case "/login" "$protocol" "cluster_challenge_${protocol}.json"
done < <(profile_value "$PROFILE" '.protocols[]')

echo "[cluster-benchmark] collecting status snapshots"
curl -fsS http://127.0.0.1:18080/__genwaf/status > "$OUT_DIR/node_a_status.json"
curl -fsS http://127.0.0.1:18082/__genwaf/status > "$OUT_DIR/node_b_status.json"

echo "[cluster-benchmark] suite complete"
echo "[cluster-benchmark] artifacts:"
find "$OUT_DIR" -maxdepth 1 -type f -name '*.json' | sort | sed 's#^#  - #'
