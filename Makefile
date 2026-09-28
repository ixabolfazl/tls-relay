.PHONY: all build build-linux build-linux-arm64 package test clean fmt vet deps help css css-watch

BINARY  := tls-relay
CMD     := ./cmd/relay
LDFLAGS := -trimpath -ldflags="-s -w"

TAILWIND_VERSION := v3.4.17
TAILWIND_CLI     := .bin/tailwindcss

UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

ifeq ($(UNAME_S),Darwin)
  ifeq ($(UNAME_M),arm64)
    TAILWIND_ARCH := macos-arm64
  else
    TAILWIND_ARCH := macos-x64
  endif
else ifeq ($(UNAME_S),Linux)
  ifeq ($(UNAME_M),aarch64)
    TAILWIND_ARCH := linux-arm64
  else ifeq ($(UNAME_M),arm64)
    TAILWIND_ARCH := linux-arm64
  else
    TAILWIND_ARCH := linux-x64
  endif
else
  TAILWIND_ARCH := linux-x64
endif

## all: build the binary with compiled CSS (default target)
all: build

$(TAILWIND_CLI):
	@mkdir -p .bin
	@echo "Downloading Tailwind CSS standalone CLI $(TAILWIND_VERSION) for $(TAILWIND_ARCH)..."
	@curl -sL -o $(TAILWIND_CLI) "https://github.com/tailwindlabs/tailwindcss/releases/download/$(TAILWIND_VERSION)/tailwindcss-$(TAILWIND_ARCH)"
	@chmod +x $(TAILWIND_CLI)

## css: compile and minify Tailwind CSS into static/css/app.css
css: $(TAILWIND_CLI)
	@mkdir -p internal/panel/static/css
	$(TAILWIND_CLI) -c tailwind.config.js -i internal/panel/static/css/input.css -o internal/panel/static/css/app.css --minify

## css-watch: watch input CSS and static files, compiling on change
css-watch: $(TAILWIND_CLI)
	@mkdir -p internal/panel/static/css
	$(TAILWIND_CLI) -c tailwind.config.js -i internal/panel/static/css/input.css -o internal/panel/static/css/app.css --watch

## build: compile the binary for the current platform (standalone static binary)
build: css
	CGO_ENABLED=0 go build $(LDFLAGS) -o $(BINARY) $(CMD)

## build-linux: cross-compile a static Linux/amd64 binary (standalone, no CGO or external dependencies)
build-linux: css
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY)-linux-amd64 $(CMD)

## build-linux-arm64: cross-compile a static Linux/arm64 binary
build-linux-arm64: css
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(BINARY)-linux-arm64 $(CMD)

## package: package linux release tarballs
package: css build-linux build-linux-arm64
	@mkdir -p dist
	@cp $(BINARY)-linux-amd64 dist/$(BINARY) && cp config.yaml tls-relay.service tls-relay.sh dist/
	@tar -czvf tls-relay-linux-amd64.tar.gz -C dist $(BINARY) config.yaml tls-relay.service tls-relay.sh
	@cp $(BINARY)-linux-arm64 dist/$(BINARY)
	@tar -czvf tls-relay-linux-arm64.tar.gz -C dist $(BINARY) config.yaml tls-relay.service tls-relay.sh
	@rm -rf dist
	@sha256sum tls-relay-linux-amd64.tar.gz > tls-relay-linux-amd64.tar.gz.sha256
	@sha256sum tls-relay-linux-arm64.tar.gz > tls-relay-linux-arm64.tar.gz.sha256
	@echo "Packages created:"
	@ls -lh tls-relay-linux-*.tar.gz*

## test: run all unit tests (ensures CSS is compiled first)
test: css
	go test -v -race ./...

## fmt: format all Go source files
fmt:
	gofmt -w .

## vet: run go vet
vet:
	go vet ./...

## clean: remove build artifacts
clean:
	rm -f $(BINARY) $(BINARY)-linux-amd64 $(BINARY)-linux-arm64 $(BINARY)-linux-*.tar.gz* internal/panel/static/css/app.css

## deps: download and tidy dependencies
deps:
	go mod tidy

## help: show this help message
help:
	@grep -E '^## ' Makefile | sed 's/## /  /'
