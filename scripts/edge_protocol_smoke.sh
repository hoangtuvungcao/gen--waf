#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

BACKEND_PORT="${BACKEND_PORT:-8081}"
GENDP_PORT="${GENDP_PORT:-18080}"
EDGE_PORT="${EDGE_PORT:-18443}"
CERT_DIR="${CERT_DIR:-runtime/dev-edge-certs}"
CERT_FILE="${CERT_FILE:-$CERT_DIR/cert.pem}"
KEY_FILE="${KEY_FILE:-$CERT_DIR/key.pem}"

cleanup() {
  if [[ -n "${EDGE_PID:-}" ]]; then kill "${EDGE_PID}" >/dev/null 2>&1 || true; fi
  if [[ -n "${GENDP_PID:-}" ]]; then kill "${GENDP_PID}" >/dev/null 2>&1 || true; fi
  if [[ -n "${SAMPLE_PID:-}" ]]; then kill "${SAMPLE_PID}" >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT

mkdir -p "$CERT_DIR" runtime

echo "[edge-smoke] building Go and C++ targets"
go build ./...
cmake -S cpp -B build >/dev/null
cmake --build build >/dev/null

if [[ ! -f "$CERT_FILE" || ! -f "$KEY_FILE" ]]; then
  echo "[edge-smoke] generating self-signed cert"
  openssl req -x509 -newkey rsa:2048 -sha256 -nodes \
    -keyout "$KEY_FILE" \
    -out "$CERT_FILE" \
    -days 2 \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1
fi

fuser -k "${BACKEND_PORT}/tcp" >/dev/null 2>&1 || true
fuser -k "${GENDP_PORT}/tcp" >/dev/null 2>&1 || true
fuser -k "${EDGE_PORT}/tcp" >/dev/null 2>&1 || true
fuser -k "${EDGE_PORT}/udp" >/dev/null 2>&1 || true

echo "[edge-smoke] starting sample backend"
go run ./cmd/sampleweb -listen ":${BACKEND_PORT}" -name edge-smoke >/tmp/genwaf-edge-sample.log 2>&1 &
SAMPLE_PID=$!
sleep 1

echo "[edge-smoke] compiling effective config"
go run ./cmd/genctl compile -config configs/profiles/01-single-domain-single-backend.yaml -output runtime/effective.json >/dev/null

echo "[edge-smoke] starting gendp"
./build/gendp --config runtime/effective.json --port "${GENDP_PORT}" >/tmp/genwaf-edge-gendp.log 2>&1 &
GENDP_PID=$!
sleep 1

echo "[edge-smoke] starting genedge"
go run ./cmd/genedge \
  -listen ":${EDGE_PORT}" \
  -upstream "http://127.0.0.1:${GENDP_PORT}" \
  -cert "$CERT_FILE" \
  -key "$KEY_FILE" >/tmp/genwaf-edge-gateway.log 2>&1 &
EDGE_PID=$!
sleep 2

echo "[edge-smoke] verifying HTTP/1.1 + HTTP/2 + HTTP/3"
CLIENT_SOURCE="$(mktemp runtime/edge-protocol-client-XXXXXX.go)"
trap 'rm -f "$CLIENT_SOURCE"; cleanup' EXIT
cat <<'EOF' > "$CLIENT_SOURCE"
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
)

func main() {
	must(runHTTP11())
	must(runHTTP2())
	must(runHTTP3())
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newRequest() (*http.Request, error) {
	req, err := http.NewRequest(http.MethodGet, "https://127.0.0.1:18443/", nil)
	if err != nil {
		return nil, err
	}
	req.Host = "test.bacsycay.click"
	return req, nil
}

func verify(resp *http.Response, expected string) error {
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("%s read body: %w", expected, err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s unexpected status %d body=%s", expected, resp.StatusCode, string(body))
	}
	if got := resp.Header.Get("X-GenWAF-Edge-Protocol"); got != expected {
		return fmt.Errorf("%s expected X-GenWAF-Edge-Protocol=%s got %s", expected, expected, got)
	}
	if got := resp.Header.Get("Alt-Svc"); got == "" {
		return fmt.Errorf("%s expected Alt-Svc header", expected)
	}
	return nil
}

func runHTTP11() error {
	req, err := newRequest()
	if err != nil {
		return err
	}
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			ForceAttemptHTTP2: false,
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("http/1.1 request: %w", err)
	}
	return verify(resp, "http/1.1")
}

func runHTTP2() error {
	req, err := newRequest()
	if err != nil {
		return err
	}
	transport := &http2.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	resp, err := transport.RoundTrip(req)
	if err != nil {
		return fmt.Errorf("http/2 request: %w", err)
	}
	return verify(resp, "h2")
}

func runHTTP3() error {
	req, err := newRequest()
	if err != nil {
		return err
	}
	transport := &http3.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	defer transport.Close()
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: transport,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return fmt.Errorf("http/3 request: %w", err)
	}
	return verify(resp, "h3")
}
EOF
go run "$CLIENT_SOURCE"

echo "[edge-smoke] all protocol checks passed"
