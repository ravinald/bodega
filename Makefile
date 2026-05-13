BINARY     := bodega
CMD_PKG    := ./cmd/bodega
BUILD_DIR  := ./dist
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || date -u '+%Y%m%d-%H%M%S')
LDFLAGS    := -ldflags "-X main.version=$(VERSION)"
GOFLAGS    :=

GO_VERSION := 1.24.2
GO_INSTALL := /usr/local/go/bin/go

# ---- Install paths ---------------------------------------------------------
# `make install` writes to $(DESTDIR)$(BINDIR). Defaults are auto-detected
# from the host OS so `make install` does the right thing without flags:
#
#   macOS Apple Silicon (Homebrew present)  -> /opt/homebrew/bin
#   macOS Intel / Linux / *BSD              -> /usr/local/bin
#
# Override either knob to install elsewhere:
#
#   make install PREFIX=$$(go env GOPATH)   # -> $$GOPATH/bin (no sudo)
#   make install PREFIX=$$HOME/.local        # -> ~/.local/bin (no sudo)
#   make install BINDIR=/opt/bodega/bin      # -> /opt/bodega/bin
#   make install DESTDIR=/tmp/stage          # -> /tmp/stage$(BINDIR) (packagers)
#
# sudo is invoked only when the target directory isn't writable by the
# current user — least-privilege by default.
UNAME_S := $(shell uname -s 2>/dev/null || echo unknown)
ifeq ($(UNAME_S),Darwin)
  ifneq ($(wildcard /opt/homebrew/bin),)
    DEFAULT_PREFIX := /opt/homebrew
  else
    DEFAULT_PREFIX := /usr/local
  endif
else
  DEFAULT_PREFIX := /usr/local
endif

PREFIX  ?= $(DEFAULT_PREFIX)
BINDIR  ?= $(PREFIX)/bin
DESTDIR ?=

.PHONY: all depend build install uninstall test lint vet fmt clean tidy cross help

all: build

## depend: Install build dependencies (Go toolchain, golangci-lint)
depend:
	@echo "--- Installing build dependencies ---"
	@# Go toolchain
	@if command -v go >/dev/null 2>&1 && go version | grep -q "go$(GO_VERSION)"; then \
		echo "  go $(GO_VERSION): already installed"; \
	else \
		echo "  go $(GO_VERSION): installing..."; \
		curl -fSL --progress-bar "https://go.dev/dl/go$(GO_VERSION).linux-amd64.tar.gz" -o /tmp/go.tar.gz; \
		sudo rm -rf /usr/local/go; \
		sudo tar -C /usr/local -xzf /tmp/go.tar.gz; \
		rm -f /tmp/go.tar.gz; \
		echo "  go $(GO_VERSION): installed to /usr/local/go"; \
		printf '%s\n' \
			'export GOROOT=/usr/local/go' \
			'export GOPATH=$$HOME/go' \
			'export PATH=/usr/local/go/bin:$$GOPATH/bin:$$PATH' \
			| sudo tee /etc/profile.d/golang.sh >/dev/null; \
		echo "  go: wrote /etc/profile.d/golang.sh (GOROOT, GOPATH, PATH)"; \
		export GOROOT=/usr/local/go; \
		export GOPATH=$$HOME/go; \
		export PATH=/usr/local/go/bin:$$GOPATH/bin:$$PATH; \
	fi
	@# golangci-lint
	@if command -v golangci-lint >/dev/null 2>&1; then \
		echo "  golangci-lint: $$(golangci-lint --version 2>&1 | head -1)"; \
	else \
		echo "  golangci-lint: installing..."; \
		curl -fsSL https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh | sh -s -- -b $$(go env GOPATH)/bin; \
		echo "  golangci-lint: installed"; \
	fi
	@echo "--- Dependencies ready ---"
	@if ! command -v go >/dev/null 2>&1 || ! go version 2>/dev/null | grep -q "go$(GO_VERSION)"; then \
		echo ""; \
		echo "NOTE: Run this in your current shell to pick up the new Go:"; \
		echo ""; \
		echo "  export PATH=/usr/local/go/bin:\$$PATH"; \
		echo ""; \
	fi

## build: Compile the bodega binary to ./dist/bodega
build:
	@mkdir -p $(BUILD_DIR)
	go build $(GOFLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY) $(CMD_PKG)
	@echo "Built: $(BUILD_DIR)/$(BINARY) (version: $(VERSION))"

## cross: Cross-compile for linux/amd64 (run on macOS workstation)
cross:
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 go build $(GOFLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-linux-amd64 $(CMD_PKG)
	@echo "Built: $(BUILD_DIR)/$(BINARY)-linux-amd64 (version: $(VERSION))"

## install: Install bodega to $(BINDIR) (sudo only if needed; override PREFIX/BINDIR)
install: build
	@target_dir="$(DESTDIR)$(BINDIR)"; \
	target="$$target_dir/$(BINARY)"; \
	if [ ! -d "$$target_dir" ]; then \
		if mkdir -p "$$target_dir" 2>/dev/null; then :; \
		else \
			echo "Creating $$target_dir requires elevated privileges; using sudo..."; \
			sudo mkdir -p "$$target_dir"; \
		fi; \
	fi; \
	if [ -w "$$target_dir" ]; then \
		install -m 0755 "$(BUILD_DIR)/$(BINARY)" "$$target"; \
	else \
		echo "Writing to $$target_dir requires elevated privileges; using sudo..."; \
		sudo install -m 0755 "$(BUILD_DIR)/$(BINARY)" "$$target"; \
	fi; \
	echo "Installed: $$target (version: $(VERSION))"; \
	case ":$$PATH:" in \
		*":$(BINDIR):"*) ;; \
		*) printf '\nNOTE: %s is not on your $$PATH.\n  Add to your shell profile:\n    export PATH="%s:$$PATH"\n\n' "$(BINDIR)" "$(BINDIR)" ;; \
	esac

## uninstall: Remove bodega from $(BINDIR)
uninstall:
	@target="$(DESTDIR)$(BINDIR)/$(BINARY)"; \
	if [ ! -e "$$target" ]; then \
		echo "Not installed at $$target"; \
		exit 0; \
	fi; \
	if [ -w "$$(dirname "$$target")" ]; then \
		rm -f "$$target"; \
	else \
		echo "Removing $$target requires elevated privileges; using sudo..."; \
		sudo rm -f "$$target"; \
	fi; \
	echo "Removed: $$target"

## test: Run all tests with race detector
test:
	go test -race -count=1 ./...

## test-verbose: Run all tests with verbose output
test-verbose:
	go test -race -count=1 -v ./...

## bench: Run benchmarks
bench:
	go test -bench=. -benchmem ./...

## vet: Run go vet
vet:
	go vet ./...

## fmt: Format all Go source files (goimports if available, else gofmt)
fmt:
	@if command -v goimports >/dev/null 2>&1; then \
		goimports -w .; \
	else \
		gofmt -w .; \
	fi

## lint: Run golangci-lint (requires golangci-lint in PATH)
lint:
	golangci-lint run ./...

## tidy: Tidy and verify the module graph
tidy:
	go mod tidy
	go mod verify

## clean: Remove build artifacts
clean:
	rm -rf $(BUILD_DIR)
	go clean -testcache

## help: Show this help
help:
	@echo "Available targets:"
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## /  /'
