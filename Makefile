.PHONY: generate build test setup

generate:
	go generate ./internal/ebpf/...

build: generate
	go build ./...

test:
	go test ./...

setup:
	git config core.hooksPath .githooks
