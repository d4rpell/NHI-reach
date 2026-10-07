GO      ?= go
BIN_DIR := bin
BINARY  := $(BIN_DIR)/nhi-reach

VERSION      ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT       ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE         ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
CATALOG_HASH ?= $(shell command -v sha256sum >/dev/null 2>&1 && sha256sum internal/hops/catalog.yaml | cut -d ' ' -f1 || echo unknown)

LDFLAGS := -s -w \
	-X github.com/d4rpell/nhi-reach/internal/version.Version=$(VERSION) \
	-X github.com/d4rpell/nhi-reach/internal/version.Commit=$(COMMIT) \
	-X github.com/d4rpell/nhi-reach/internal/version.Date=$(DATE) \
	-X github.com/d4rpell/nhi-reach/internal/version.CatalogHash=$(CATALOG_HASH)

.PHONY: all build test vet lint vuln fmt clean

all: build

build: $(BIN_DIR)
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/nhi-reach

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

test:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

lint:
	golangci-lint run

# Pinned: an unversioned @latest broke this job once when a release raised its
# own toolchain requirement. The go.mod minimum is go 1.25, so the toolchain the
# directive pins runs the scan.
vuln:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@v1.1.4 ./...

fmt:
	$(GO) fmt ./...

clean:
	@case "$(BIN_DIR)" in ""|.|..|*/*) echo "refusing to clean BIN_DIR='$(BIN_DIR)'" >&2; exit 1;; esac
	rm -rf -- "$(BIN_DIR)"
