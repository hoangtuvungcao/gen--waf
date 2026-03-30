#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

STACK_DIR="${1:-runtime/product-stack}"
CONFIG_PATH="${CONFIG_PATH:-configs/profiles/06-multi-node-redis-native-benchmark.yaml}"
CERT_DIR="${CERT_DIR:-runtime/dev-edge-certs}"
CERT_FILE="${CERT_FILE:-$CERT_DIR/cert.pem}"
KEY_FILE="${KEY_FILE:-$CERT_DIR/key.pem}"
REDIS_ADDR="${REDIS_ADDR:-127.0.0.1:16379}"
CTRL_ADDR="${CTRL_ADDR:-127.0.0.1:18081}"

mkdir -p "$STACK_DIR/node-a" "$STACK_DIR/node-b" "$CERT_DIR"

cleanup() {
  for pid_var in EDGE_A_PID EDGE_B_PID GENDP_A_PID GENDP_B_PID AGENT_A_PID AGENT_B_PID CTRL_PID REDIS_PID SAMPLE_A_PID SAMPLE_B_PID; do
    if [[ -n "${!pid_var:-}" ]]; then kill "${!pid_var}" >/dev/null 2>&1 || true; fi
  done
}
trap cleanup EXIT

wait_for_http() {
  local url="$1"
  local attempts="${2:-40}"
  for _ in $(seq 1 "$attempts"); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
  done
  echo "timeout waiting for $url" >&2
  return 1
}

wait_for_file() {
  local path="$1"
  local attempts="${2:-40}"
  for _ in $(seq 1 "$attempts"); do
    if [[ -s "$path" ]]; then
      return 0
    fi
    sleep 0.25
  done
  echo "timeout waiting for file $path" >&2
  return 1
}

redis_check() {
  local mode="$1"
  local key="$2"
  local value="${3:-}"
  local temp_source
  temp_source="$(mktemp "$STACK_DIR/redis-check-XXXXXX.go")"
  cat > "$temp_source" <<'EOF'
package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

func main() {
	if len(os.Args) < 4 {
		fmt.Fprintln(os.Stderr, "usage: <addr> <mode> <key> [value]")
		os.Exit(2)
	}
	addr := os.Args[1]
	mode := os.Args[2]
	key := os.Args[3]
	want := ""
	if len(os.Args) > 4 {
		want = os.Args[4]
	}
	client := redis.NewClient(&redis.Options{Addr: addr})
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	switch mode {
	case "ping":
		if err := client.Ping(ctx).Err(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "exists":
		keys, err := client.Keys(ctx, key).Result()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if len(keys) == 0 {
			fmt.Fprintf(os.Stderr, "no redis keys matching %s\n", key)
			os.Exit(1)
		}
		fmt.Println(strings.Join(keys, ","))
	case "contains":
		body, err := os.ReadFile(key)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if !strings.Contains(string(body), want) {
			fmt.Fprintf(os.Stderr, "%s does not contain %s\n", key, want)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "unsupported mode %s\n", mode)
		os.Exit(2)
	}
}
EOF
  if [[ -n "$value" ]]; then
    go run "$temp_source" "$REDIS_ADDR" "$mode" "$key" "$value"
  else
    go run "$temp_source" "$REDIS_ADDR" "$mode" "$key"
  fi
  rm -f "$temp_source"
}

echo "[product-smoke] building binaries"
go build ./...
cmake -S cpp -B build >/dev/null
cmake --build build >/dev/null

echo "[product-smoke] validating config"
go run ./cmd/genctl validate -config "$CONFIG_PATH" >/dev/null

fuser -k 8081/tcp >/dev/null 2>&1 || true
fuser -k 8082/tcp >/dev/null 2>&1 || true
fuser -k 16379/tcp >/dev/null 2>&1 || true
fuser -k 18080/tcp >/dev/null 2>&1 || true
fuser -k 18082/tcp >/dev/null 2>&1 || true
fuser -k 18081/tcp >/dev/null 2>&1 || true
fuser -k 18443/tcp >/dev/null 2>&1 || true
fuser -k 18443/udp >/dev/null 2>&1 || true
fuser -k 18444/tcp >/dev/null 2>&1 || true
fuser -k 18444/udp >/dev/null 2>&1 || true

if [[ ! -f "$CERT_FILE" || ! -f "$KEY_FILE" ]]; then
  echo "[product-smoke] generating self-signed cert for genedge"
  openssl req -x509 -newkey rsa:2048 -sha256 -nodes \
    -keyout "$KEY_FILE" \
    -out "$CERT_FILE" \
    -days 2 \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1
fi

echo "[product-smoke] starting embedded redis"
go run ./cmd/genredisdev -listen "$REDIS_ADDR" >/tmp/genwaf-product-redis.log 2>&1 &
REDIS_PID=$!
sleep 1
redis_check ping _

echo "[product-smoke] starting controller"
go run ./cmd/genctl serve -config "$CONFIG_PATH" -listen "${CTRL_ADDR#127.0.0.1}" >/tmp/genwaf-product-controller.log 2>&1 &
CTRL_PID=$!
wait_for_http "http://${CTRL_ADDR}/healthz"

echo "[product-smoke] starting sample backends"
go run ./cmd/sampleweb -listen :8081 -name product-node-a >/tmp/genwaf-product-sample-a.log 2>&1 &
SAMPLE_A_PID=$!
go run ./cmd/sampleweb -listen :8082 -name product-node-b >/tmp/genwaf-product-sample-b.log 2>&1 &
SAMPLE_B_PID=$!
sleep 1

echo "[product-smoke] starting agents"
go run ./cmd/genagent \
  -controller "http://${CTRL_ADDR}" \
  -output "$STACK_DIR/node-a/controller-effective.json" \
  -decisions-output "$STACK_DIR/node-a/cluster-decisions.json" \
  -observations-input "$STACK_DIR/node-a/node-observations.json" \
  -rate-limits-output "$STACK_DIR/node-a/cluster-rate-limits.json" \
  -node-id ingress-a \
  -node-addr 127.0.0.1 \
  -node-role ingress \
  -interval 1s \
  -xdp-auto-apply=false >/tmp/genwaf-product-agent-a.log 2>&1 &
AGENT_A_PID=$!
go run ./cmd/genagent \
  -controller "http://${CTRL_ADDR}" \
  -output "$STACK_DIR/node-b/controller-effective.json" \
  -decisions-output "$STACK_DIR/node-b/cluster-decisions.json" \
  -observations-input "$STACK_DIR/node-b/node-observations.json" \
  -rate-limits-output "$STACK_DIR/node-b/cluster-rate-limits.json" \
  -node-id ingress-b \
  -node-addr 127.0.0.1 \
  -node-role ingress \
  -interval 1s \
  -xdp-auto-apply=false >/tmp/genwaf-product-agent-b.log 2>&1 &
AGENT_B_PID=$!

wait_for_file "$STACK_DIR/node-a/controller-effective.json"
wait_for_file "$STACK_DIR/node-b/controller-effective.json"

echo "[product-smoke] patching effective configs for node-local file paths and low RL thresholds"
jq \
  --arg obs "$STACK_DIR/node-a/node-observations.json" \
  --arg dec "$STACK_DIR/node-a/cluster-decisions.json" \
  --arg rl "$STACK_DIR/node-a/cluster-rate-limits.json" \
  '.local_observation_path = $obs | .local_decision_path = $dec | .shared_rate_limit_path = $rl | .rate_limit_rps = 3 | .rate_limit_burst = 5' \
  "$STACK_DIR/node-a/controller-effective.json" > "$STACK_DIR/node-a/effective.json"
jq \
  --arg obs "$STACK_DIR/node-b/node-observations.json" \
  --arg dec "$STACK_DIR/node-b/cluster-decisions.json" \
  --arg rl "$STACK_DIR/node-b/cluster-rate-limits.json" \
  '.local_observation_path = $obs | .local_decision_path = $dec | .shared_rate_limit_path = $rl | .rate_limit_rps = 3 | .rate_limit_burst = 5' \
  "$STACK_DIR/node-b/controller-effective.json" > "$STACK_DIR/node-b/effective.json"

echo "[product-smoke] starting gendp nodes"
./build/gendp --config "$STACK_DIR/node-a/effective.json" --port 18080 >/tmp/genwaf-product-gendp-a.log 2>&1 &
GENDP_A_PID=$!
./build/gendp --config "$STACK_DIR/node-b/effective.json" --port 18082 >/tmp/genwaf-product-gendp-b.log 2>&1 &
GENDP_B_PID=$!
wait_for_http "http://127.0.0.1:18080/healthz"
wait_for_http "http://127.0.0.1:18082/healthz"

echo "[product-smoke] starting genedge nodes"
go run ./cmd/genedge \
  -listen :18443 \
  -upstream http://127.0.0.1:18080 \
  -cert "$CERT_FILE" \
  -key "$KEY_FILE" >/tmp/genwaf-product-edge-a.log 2>&1 &
EDGE_A_PID=$!
go run ./cmd/genedge \
  -listen :18444 \
  -upstream http://127.0.0.1:18082 \
  -cert "$CERT_FILE" \
  -key "$KEY_FILE" >/tmp/genwaf-product-edge-b.log 2>&1 &
EDGE_B_PID=$!
sleep 2

echo "[product-smoke] checking nodes registered"
python3 - <<'PY'
import json, urllib.request, sys, time
for _ in range(20):
    with urllib.request.urlopen("http://127.0.0.1:18081/v1/nodes", timeout=5) as resp:
        nodes = json.load(resp)
    if len(nodes) >= 2:
        sys.exit(0)
    time.sleep(0.5)
raise SystemExit("expected at least 2 registered nodes")
PY

echo "[product-smoke] checking pass-through on both nodes"
for port in 18443 18444; do
  curl -ksS \
    -H 'Host: test.bacsycay.click' \
    -H 'X-GenWAF-Benchmark-Client-IP: 198.51.100.10' \
    "https://127.0.0.1:${port}/" | grep -q "GEN WAF Demo"
done

echo "[product-smoke] checking challenge on sensitive route"
for port in 18443 18444; do
  status="$(curl -ksS -o "$STACK_DIR/challenge-${port}.html" -w '%{http_code}' \
    -H 'Host: test.bacsycay.click' \
    -H 'X-GenWAF-Benchmark-Client-IP: 198.51.100.20' \
    "https://127.0.0.1:${port}/login")"
  [[ "$status" == "403" ]]
  grep -q "Protected by GEN WAF" "$STACK_DIR/challenge-${port}.html"
done

echo "[product-smoke] checking redis-native shared rate-limit across nodes"
rate_statuses="$STACK_DIR/rate-limit-statuses.txt"
: > "$rate_statuses"
for i in $(seq 1 14); do
  port=18443
  if (( i % 2 == 0 )); then
    port=18444
  fi
  curl -ksS -o /dev/null -w "%{http_code}\n" \
    -H 'Host: test.bacsycay.click' \
    -H 'X-GenWAF-Benchmark-Client-IP: 198.51.100.99' \
    "https://127.0.0.1:${port}/" >> "$rate_statuses"
done
grep -q '^429$' "$rate_statuses"
redis_check exists 'genwaf-bench:rl:gen-waf-multi-node-redis-bench:198.51.100.99'

echo "[product-smoke] checking controller-shared block propagation"
python3 - <<'PY'
import json, urllib.request
payload = {
    "client_ip": "198.51.100.250",
    "action": "temporary_ban",
    "reason": "product smoke shared block",
    "source": "product-smoke",
    "ttl_seconds": 30,
}
req = urllib.request.Request(
    "http://127.0.0.1:18081/v1/cluster/decisions",
    data=json.dumps(payload).encode(),
    headers={"Content-Type": "application/json"},
    method="POST",
)
with urllib.request.urlopen(req, timeout=5) as resp:
    body = json.load(resp)
if body.get("action") != "temporary_ban":
    raise SystemExit("shared decision publish failed")
PY
sleep 2
grep -q '198.51.100.250' "$STACK_DIR/node-a/cluster-decisions.json"
grep -q '198.51.100.250' "$STACK_DIR/node-b/cluster-decisions.json"
for port in 18443 18444; do
  status="$(curl -ksS -o /dev/null -w '%{http_code}' \
    -H 'Host: test.bacsycay.click' \
    -H 'X-GenWAF-Benchmark-Client-IP: 198.51.100.250' \
    "https://127.0.0.1:${port}/")"
  [[ "$status" == "403" ]]
done

echo "[product-smoke] checking observation flow back to controller"
sleep 2
python3 - <<'PY'
import json, urllib.request
with urllib.request.urlopen("http://127.0.0.1:18081/v1/cluster/observations", timeout=5) as resp:
    items = json.load(resp)
if not items:
    raise SystemExit("expected controller observations")
PY
wait_for_file "$STACK_DIR/node-a/node-observations.json"
wait_for_file "$STACK_DIR/node-b/node-observations.json"

echo "[product-smoke] all product stack checks passed"
