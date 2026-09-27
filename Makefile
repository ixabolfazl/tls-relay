.PHONY: all build build-linux test clean fmt vet deps help

BINARY  := tls-relay
CMD     := ./cmd/relay
LDFLAGS := -trimpath -ldflags="-s -w"

## all: build the binary (default target)
all: build

## build: compile the binary for the current platform (standalone static binary)
build:
	CGO_ENABLED=0 go build $(LDFLAGS) -o $(BINARY) $(CMD)

## build-linux: cross-compile a static Linux/amd64 binary (standalone, no CGO or external dependencies)
build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY)-linux-amd64 $(CMD)

## build-linux-arm64: cross-compile a static Linux/arm64 binary
build-linux-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(BINARY)-linux-arm64 $(CMD)

## package: package linux release tarballs
package: build-linux build-linux-arm64
	@mkdir -p dist
	@cp $(BINARY)-linux-amd64 dist/$(BINARY) && cp config.yaml .env.example tls-relay.service tls-relay.sh dist/
	@tar -czvf tls-relay-linux-amd64.tar.gz -C dist $(BINARY) config.yaml .env.example tls-relay.service tls-relay.sh
	@cp $(BINARY)-linux-arm64 dist/$(BINARY)
	@tar -czvf tls-relay-linux-arm64.tar.gz -C dist $(BINARY) config.yaml .env.example tls-relay.service tls-relay.sh
	@rm -rf dist
	@sha256sum tls-relay-linux-amd64.tar.gz > tls-relay-linux-amd64.tar.gz.sha256
	@sha256sum tls-relay-linux-arm64.tar.gz > tls-relay-linux-arm64.tar.gz.sha256
	@echo "Packages created:"
	@ls -lh tls-relay-linux-*.tar.gz*

## test: run all unit tests
test:
	go test -v -race ./...

## fmt: format all Go source files
fmt:
	gofmt -w .

## vet: run go vet
vet:
	go vet ./...

## clean: remove build artifacts
clean:
	rm -f $(BINARY) $(BINARY)-linux

## deps: download and tidy dependencies
deps:
	go mod tidy

## help: show this help message
help:
	@grep -E '^## ' Makefile | sed 's/## /  /'
