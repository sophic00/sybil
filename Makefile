.PHONY: generate build test

generate:
	go generate ./internal/ebpf/...

build: generate
	go build ./...

test:
	go test ./...
