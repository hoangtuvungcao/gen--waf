SHELL := /usr/bin/env bash

.PHONY: build build-go build-cpp validate test smoke clean

build: build-go build-cpp

build-go:
	go build ./...

build-cpp:
	cmake -S cpp -B build
	cmake --build build

validate:
	go run ./cmd/genctl validate -config configs/genwaf-production.yaml >/dev/null
	for f in configs/profiles/*.yaml; do \
		go run ./cmd/genctl validate -config "$$f" >/dev/null; \
	done

test: build validate
	./scripts/regression.sh

smoke: build
	./scripts/edge_protocol_smoke.sh

clean:
	./scripts/clean-generated.sh
