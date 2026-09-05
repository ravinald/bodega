BINARY     := bodega
CMD_PKG    := ./cmd/bodega
BUILD_DIR  := ./dist
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || date -u '+%Y%m%d-%H%M%S')
COMMIT     ?= $(shell git rev-parse HEAD 2>/dev/null || echo none)
BUILD_DATE ?= $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS    := -ldflags "-s -w \
                -X main.version=$(VERSION) \
                -X main.commit=$(COMMIT) \
                -X main.buildDate=$(BUILD_DATE)"
GOFLAGS    := -trimpath

GO_VERSION := $(shell awk '/^go / {print $$2; exit}' go.mod)
GO_INSTALL := /usr/local/go/bin/go

# The CI jobs the release build gates on, and the one list `check` and ci.yml
# are both read against. `make ci-drift` fails when the two disagree, so a job
# added to CI cannot reach main without also reaching the drover gate — which
# is how gofmt drift shipped through a green gate once already.
CI_GATE_JOBS := vet lint fmt tidy test

# Each CI job paired with the `check` leg that runs it. The names differ by
# convention (fmt > fmt-check), so without the pairing a job sits in
# CI_GATE_JOBS and in ci.yml with nothing running it and the gate still passes.
#
# Written out rather than derived: deriving `check`'s prerequisites from
# CI_GATE_JOBS runs them in that list's order, which puts lint ahead of
# fmt-check and costs the cheapest-first ordering CHECK_LEGS holds.
CI_GATE_TARGETS := vet=vet lint=lint fmt=fmt-check tidy=tidy-check test=test

# The legs `check` runs, in order. `check` has no prerequisites outside this
# list, so it is what ran, and `ci-drift` reads CI_GATE_TARGETS against it.
CHECK_LEGS := ci-drift fmt-check tidy-check vet build lint test

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

.PHONY: all depend build install uninstall test lint vet fmt fmt-check clean tidy tidy-check ci-drift check cross help

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

## fmt-check: Fail if gofmt or goimports would rewrite a file (CI's fmt job)
fmt-check:
	@out=$$(gofmt -l .); \
	if [ -n "$$out" ]; then \
		echo "gofmt drift in:"; echo "$$out"; \
		echo "run 'make fmt'"; \
		exit 1; \
	fi
	@if ! command -v goimports >/dev/null 2>&1; then \
		echo "goimports is not on PATH; CI runs it, so skipping here would make the gate weaker than the merge."; \
		echo "install it: go install golang.org/x/tools/cmd/goimports@latest"; \
		exit 1; \
	fi
	@out=$$(goimports -l .); \
	if [ -n "$$out" ]; then \
		echo "goimports drift in:"; echo "$$out"; \
		echo "run 'make fmt'"; \
		exit 1; \
	fi

## lint: Run golangci-lint (requires golangci-lint in PATH)
lint:
	golangci-lint run ./...

## tidy: Tidy and verify the module graph
tidy:
	go mod tidy
	go mod verify

## tidy-check: Fail if go mod tidy would change go.mod or go.sum (CI's tidy job)
#
# go mod tidy has no dry-run, so this runs it against a saved copy and puts the
# originals back either way. CI can afford to leave a rewritten go.mod behind on
# a throwaway runner; a developer running the gate cannot.
tidy-check:
	@tmp=$$(mktemp -d); cp go.mod go.sum "$$tmp/"; \
	rc=0; \
	if ! go mod tidy; then \
		echo "go mod tidy failed; skipped the drift comparison, which reads clean whenever tidy did not run"; \
		rc=1; \
	elif ! cmp -s go.mod "$$tmp/go.mod" || ! cmp -s go.sum "$$tmp/go.sum"; then \
		echo "go.mod / go.sum out of sync; run 'make tidy'"; \
		diff -u "$$tmp/go.mod" go.mod || true; \
		diff -u "$$tmp/go.sum" go.sum || true; \
		rc=1; \
	fi; \
	cp "$$tmp/go.mod" "$$tmp/go.sum" .; rm -rf "$$tmp"; \
	if [ $$rc -eq 0 ] && ! go mod verify; then \
		echo "go mod verify failed; a module in the cache no longer matches go.sum"; \
		rc=1; \
	fi; \
	exit $$rc

## ci-drift: Fail if the drover gate and ci.yml no longer gate on the same jobs
#
# The two lists that must not diverge: the jobs ci.yml's build stage needs, and
# CI_GATE_JOBS, which is what `make check` runs a leg for. Adding a job to CI
# without adding it here fails the gate on the very branch that added it.
ci-drift:
	@ci=$$(sed -n 's/^ *needs: *\[\(.*\)\].*$$/\1/p' .github/workflows/ci.yml | tr -d ' ' | tr ',' '\n' | sort | tr '\n' ' '); \
	mine=$$(printf '%s\n' $(CI_GATE_JOBS) | sort | tr '\n' ' '); \
	if [ "$$ci" != "$$mine" ]; then \
		echo ".github/workflows/ci.yml gates on: $$ci"; \
		echo "Makefile CI_GATE_JOBS:            $$mine"; \
		echo "a job in one and not the other is a green gate that CI rejects; reconcile both"; \
		exit 1; \
	fi
	@# CI_GATE_JOBS names CI jobs, `check` runs make targets, and the two name
	@# sets are joined by CI_GATE_TARGETS alone. CHECK_LEGS is `check`'s own
	@# prerequisite list, so checking the mapping against it is checking what
	@# ran rather than what a second list claims ran.
	@for job in $(CI_GATE_JOBS); do \
		target=$$(printf '%s\n' $(CI_GATE_TARGETS) | sed -n "s/^$$job=//p"); \
		if [ -z "$$target" ]; then \
			echo "CI gate job '$$job' has no CI_GATE_TARGETS entry; add '$$job=<make target>'"; \
			exit 1; \
		fi; \
		case " $(CHECK_LEGS) " in \
			*" $$target "*) ;; \
			*) echo "CI gate job '$$job' maps to '$$target', which is not a leg of 'check': $(CHECK_LEGS)"; \
			   exit 1;; \
		esac; \
	done
	@for pair in $(CI_GATE_TARGETS); do \
		case " $(CI_GATE_JOBS) " in \
			*" $${pair%%=*} "*) ;; \
			*) echo "CI_GATE_TARGETS maps '$${pair%%=*}', which is not a CI gate job: $(CI_GATE_JOBS)"; \
			   exit 1;; \
		esac; \
	done
	@# The gate config is not in the repository, so this half runs only where
	@# the gate does. Skipping it in CI costs nothing: CI is the side that
	@# cannot silently under-report.
	@if [ -f .drover.toml ] && ! grep -q '^default *= *"make check"' .drover.toml; then \
		echo ".drover.toml [gates] default no longer calls 'make check', so the gate can drift from CI again"; \
		exit 1; \
	fi

## check: The full merge gate — every job CI blocks on, in one target
#
# Cheapest legs first: a gofmt slip should cost two seconds, not a full race
# test run. The drover gate calls this and nothing else, so `[gates] default`
# and the CI job list stay one edit apart.
check: $(CHECK_LEGS)
	@echo "check: $(words $(CHECK_LEGS)) legs passed locally: $(CHECK_LEGS)"

## clean: Remove build artifacts
clean:
	rm -rf $(BUILD_DIR)
	go clean -testcache

## help: Show this help
help:
	@echo "Available targets:"
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## /  /'
