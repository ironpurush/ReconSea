BINARY     := reconsea
MODULE     := github.com/IronPurush/reconsea
CMD        := ./cmd/reconsea
BUILD_DIR  := build
VERSION    := $(shell git describe --tags --always --dirty 2>/dev/null || echo "1.0.0")
COMMIT     := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE       := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS    := -s -w \
              -X $(MODULE)/pkg/types.Version=$(VERSION) \
              -X $(MODULE)/pkg/types.Commit=$(COMMIT) \
              -X $(MODULE)/pkg/types.BuildDate=$(DATE)
GO         := go
GOFLAGS    := -trimpath

.PHONY: all build clean test lint fmt vet install uninstall cross release deps tidy

## Default target
all: tidy build

## Download dependencies
deps:
	$(GO) mod download

## Tidy module
tidy:
	$(GO) mod tidy

## Build for current platform
build:
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY) $(CMD)
	@echo "  ✔  Built $(BUILD_DIR)/$(BINARY)"

## Install to /usr/local/bin
install: build
	@install -m 0755 $(BUILD_DIR)/$(BINARY) /usr/local/bin/$(BINARY)
	@echo "  ✔  Installed to /usr/local/bin/$(BINARY)"

## Remove from /usr/local/bin
uninstall:
	@rm -f /usr/local/bin/$(BINARY)
	@echo "  ✔  Removed /usr/local/bin/$(BINARY)"

## Run tests
test:
	$(GO) test ./... -v -race -timeout 60s

## Run tests with coverage
coverage:
	$(GO) test ./... -coverprofile=coverage.out
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "  ✔  Coverage report: coverage.html"

## Format code
fmt:
	$(GO) fmt ./...
	@echo "  ✔  Formatted"

## Vet
vet:
	$(GO) vet ./...

## Lint (requires golangci-lint)
lint:
	@which golangci-lint > /dev/null 2>&1 || \
		(curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $$(go env GOPATH)/bin)
	golangci-lint run ./...

## Cross-compile for Linux, macOS, Windows
cross:
	@mkdir -p $(BUILD_DIR)
	GOOS=linux   GOARCH=amd64  $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY)-linux-amd64   $(CMD)
	GOOS=linux   GOARCH=arm64  $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY)-linux-arm64   $(CMD)
	GOOS=darwin  GOARCH=amd64  $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY)-darwin-amd64  $(CMD)
	GOOS=darwin  GOARCH=arm64  $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY)-darwin-arm64  $(CMD)
	GOOS=windows GOARCH=amd64  $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY)-windows-amd64.exe $(CMD)
	@echo "  ✔  Cross-compiled all targets to $(BUILD_DIR)/"

## Package release archives
release: cross
	@mkdir -p $(BUILD_DIR)/release
	cd $(BUILD_DIR) && \
		tar czf release/$(BINARY)-linux-amd64-$(VERSION).tar.gz   $(BINARY)-linux-amd64   && \
		tar czf release/$(BINARY)-linux-arm64-$(VERSION).tar.gz   $(BINARY)-linux-arm64   && \
		tar czf release/$(BINARY)-darwin-amd64-$(VERSION).tar.gz  $(BINARY)-darwin-amd64  && \
		tar czf release/$(BINARY)-darwin-arm64-$(VERSION).tar.gz  $(BINARY)-darwin-arm64  && \
		zip -q release/$(BINARY)-windows-amd64-$(VERSION).zip     $(BINARY)-windows-amd64.exe
	@echo "  ✔  Release archives in $(BUILD_DIR)/release/"

## Remove build artifacts
clean:
	@rm -rf $(BUILD_DIR) coverage.out coverage.html
	@echo "  ✔  Cleaned"

## Show help
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## /  /'
