#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROMETHEUS_DIR="${PROMETHEUS_DIR:-$ROOT_DIR/runtime/prometheus}"
PROMETHEUS_VERSION="${PROMETHEUS_VERSION:-v2.51.0}"
PROMETHEUS_DOWNLOAD_URL="https://github.com/prometheus/prometheus/releases/download/$PROMETHEUS_VERSION/prometheus-${PROMETHEUS_VERSION#v}.linux-amd64.tar.gz"
GENCTL_METRICS_TARGET="${GENCTL_METRICS_TARGET:-127.0.0.1:90}"

usage() {
  cat <<'EOF'
Usage: ./scripts/setup_prometheus.sh {install|config|start|stop}
EOF
}

command_name="${1:-config}"

case "$command_name" in
  install)
    mkdir -p "$PROMETHEUS_DIR"
    cd "$PROMETHEUS_DIR"
    if [[ ! -f prometheus ]]; then
      curl -fsSL "$PROMETHEUS_DOWNLOAD_URL" | tar xz --strip-components=1
    fi
    echo "prometheus installed in $PROMETHEUS_DIR"
    ;;

  config)
    mkdir -p "$PROMETHEUS_DIR"
    cat > "$PROMETHEUS_DIR/prometheus.yml" <<EOF
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - alerts.yml

scrape_configs:
  - job_name: genwaf-controller
    static_configs:
      - targets: ["$GENCTL_METRICS_TARGET"]
EOF

    cat > "$PROMETHEUS_DIR/alerts.yml" <<'EOF'
groups:
  - name: genwaf_alerts
    interval: 30s
    rules:
      - alert: GenWAFRedisConnectionDown
        expr: genwaf_redis_connection_ok == 0
        for: 2m
        annotations:
          summary: "GEN WAF cannot reach Redis"

      - alert: GenWAFRegisteredNodesLow
        expr: genwaf_registered_nodes < 1
        for: 5m
        annotations:
          summary: "GEN WAF node registry is empty"
EOF
    echo "prometheus configuration written to $PROMETHEUS_DIR"
    ;;

  start)
    cd "$PROMETHEUS_DIR"
    if [[ ! -f prometheus ]]; then
      echo "prometheus binary not found; run install first" >&2
      exit 1
    fi
    ./prometheus \
      --config.file=prometheus.yml \
      --storage.tsdb.path="$PROMETHEUS_DIR/data" \
      > "$PROMETHEUS_DIR/prometheus.log" 2>&1 &
    echo $! > "$PROMETHEUS_DIR/prometheus.pid"
    echo "prometheus started"
    ;;

  stop)
    if [[ -f "$PROMETHEUS_DIR/prometheus.pid" ]]; then
      kill "$(cat "$PROMETHEUS_DIR/prometheus.pid")" >/dev/null 2>&1 || true
      rm -f "$PROMETHEUS_DIR/prometheus.pid"
    fi
    echo "prometheus stopped"
    ;;

  *)
    usage >&2
    exit 1
    ;;
esac
