#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

CORPUS_DIR="${1:-tests/http-parser-corpus}"
BACKEND_PORT="${BACKEND_PORT:-8082}"
GENDP_PORT="${GENDP_PORT:-18082}"

cleanup() {
  if [[ -n "${GENDP_PID:-}" ]]; then kill "${GENDP_PID}" >/dev/null 2>&1 || true; fi
  if [[ -n "${SAMPLE_PID:-}" ]]; then kill "${SAMPLE_PID}" >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT

echo "[http-corpus] using corpus dir: $CORPUS_DIR"
echo "[http-corpus] building binaries"
go build ./...
cmake -S cpp -B build >/dev/null
cmake --build build >/dev/null

fuser -k "${BACKEND_PORT}/tcp" >/dev/null 2>&1 || true
fuser -k "${GENDP_PORT}/tcp" >/dev/null 2>&1 || true

echo "[http-corpus] starting sample backend"
go run ./cmd/sampleweb -listen ":${BACKEND_PORT}" -name http-corpus >/tmp/genwaf-http-corpus-sample.log 2>&1 &
SAMPLE_PID=$!
sleep 1

echo "[http-corpus] compiling effective config"
go run ./cmd/genctl compile -config configs/profiles/01-single-domain-single-backend.yaml -output runtime/effective.json >/dev/null

echo "[http-corpus] starting gendp"
./build/gendp --config runtime/effective.json --port "${GENDP_PORT}" >/tmp/genwaf-http-corpus-gendp.log 2>&1 &
GENDP_PID=$!
sleep 1

python3 - "$CORPUS_DIR" "$GENDP_PORT" <<'PY'
import pathlib
import socket
import sys

corpus_dir = pathlib.Path(sys.argv[1])
port = int(sys.argv[2])

def run_case(case_path: pathlib.Path, expected_status: int) -> None:
    payload = case_path.read_bytes()
    if b"\r\n" not in payload:
        payload = payload.replace(b"\n", b"\r\n")
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        sock.sendall(payload)
        chunks = []
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
    response = b"".join(chunks).decode("utf-8", "replace")
    if not response.startswith("HTTP/1.1 "):
        raise SystemExit(f"{case_path.name}: missing HTTP response: {response!r}")
    try:
        status = int(response.split(" ", 2)[1])
    except Exception as exc:
        raise SystemExit(f"{case_path.name}: could not parse status from response {response!r}: {exc}") from exc
    if status != expected_status:
        raise SystemExit(f"{case_path.name}: expected {expected_status}, got {status}\n{response}")

valid_dir = corpus_dir / "valid"
invalid_dir = corpus_dir / "invalid"
for case_path in sorted(valid_dir.glob("*.http")):
    expected = int(case_path.name.split("-", 1)[0])
    run_case(case_path, expected)
for case_path in sorted(invalid_dir.glob("*.http")):
    expected = int(case_path.name.split("-", 1)[0])
    run_case(case_path, expected)
PY

echo "[http-corpus] all parser corpus cases passed"
