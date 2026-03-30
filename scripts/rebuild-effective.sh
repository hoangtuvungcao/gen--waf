#!/usr/bin/env bash
set -euo pipefail

GENCTL_BIN="${GENCTL_BIN:-/opt/genwaf/bin/genctl}"
CONFIG_PATH="${CONFIG_PATH:-/etc/genwaf/genwaf.yaml}"
OUTPUT_PATH="${OUTPUT_PATH:-/var/lib/genwaf/effective.json}"

if [[ ! -x "$GENCTL_BIN" ]]; then
  echo "không tìm thấy binary genctl: $GENCTL_BIN" >&2
  exit 1
fi

"$GENCTL_BIN" validate -config "$CONFIG_PATH" >/dev/null
"$GENCTL_BIN" compile -config "$CONFIG_PATH" -output "$OUTPUT_PATH" >/dev/null
echo "đã dựng lại effective config: $OUTPUT_PATH"
