.PHONY: build test setup

build:
	go build -o bin/analyzer ./cmd/analyzer

test:
	go test ./...

setup:
	git config core.hooksPath .githooks
