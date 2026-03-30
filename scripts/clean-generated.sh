#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

rm -rf build

if [[ -d runtime ]]; then
  find runtime -mindepth 1 ! -name '.gitkeep' -exec rm -rf {} +
fi

rm -f /tmp/genwaf-*.log /tmp/genwaf-*.out /tmp/genwaf-smoke-*.out

echo "cleaned generated files"
