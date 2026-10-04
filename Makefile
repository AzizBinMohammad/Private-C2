# Private-C2 Makefile
# -------------------
# Targets for building, testing, linting and deploying the framework.

SHELL       := /bin/bash
GO          := go
GOFLAGS     ?=
BIN_DIR     := bin
SERVER_BIN  := $(BIN_DIR)/private-c2-server
CLIENT_BIN  := $(BIN_DIR)/private-c2-client
BUILDER_BIN := $(BIN_DIR)/private-c2-builder

IMPLANT_SRC := ./implant
IMPLANT_BIN := $(BIN_DIR)/implant

DOCKER_TAG  ?= private-c2:latest

.PHONY: all build server client builder test test-integration lint proto docker clean cross-compile help

all: build

# ---- Build ---------------------------------------------------------------

build: server client builder  ## Build all binaries

server:  ## Build the server binary
	@mkdir -p $(BIN_DIR)
	$(GO) build $(GOFLAGS) -trimpath -ldflags="-s -w" -o $(SERVER_BIN) ./cmd/server

client:  ## Build the client binary
	@mkdir -p $(BIN_DIR)
	$(GO) build $(GOFLAGS) -trimpath -ldflags="-s -w" -o $(CLIENT_BIN) ./cmd/client

builder:  ## Build the builder binary
	@mkdir -p $(BIN_DIR)
	$(GO) build $(GOFLAGS) -trimpath -ldflags="-s -w" -o $(BUILDER_BIN) ./cmd/builder

# ---- Test -----------------------------------------------------------------

test:  ## Run all unit tests
	$(GO) test ./pkg/... ./server/... ./client/... -count=1 -race -timeout 120s

test-integration:  ## Run integration tests (requires full stack)
	cd tests && $(GO) test -tags integration -count=1 -race -timeout 300s ./integration/...

# ---- Lint -----------------------------------------------------------------

lint:  ## Run go vet; use golangci-lint if available
	$(GO) vet ./pkg/... ./server/... ./client/...
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./pkg/... ./server/... ./client/...; \
	else \
		echo "golangci-lint not found, skipping (go vet passed)"; \
	fi

# ---- Proto ----------------------------------------------------------------

proto:  ## (Placeholder) Regenerate protobuf / gRPC code
	@echo "TODO: run protoc with proto/v1/*.proto"
	@echo "Install: go install google.golang.org/protobuf/cmd/protoc-gen-go@latest"
	@echo "         go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest"

# ---- Docker ---------------------------------------------------------------

docker:  ## Build the Docker image
	docker build -t $(DOCKER_TAG) .

# ---- Cross-compile --------------------------------------------------------

cross-compile:  ## Build implant for linux/amd64, windows/amd64, darwin/arm64
	@mkdir -p $(BIN_DIR)/cross
	GOOS=linux   GOARCH=amd64 CGO_ENABLED=0 $(GO) build $(GOFLAGS) -trimpath -ldflags="-s -w" \
		-o $(BIN_DIR)/cross/implant-linux-amd64 $(IMPLANT_SRC)
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 $(GO) build $(GOFLAGS) -trimpath -ldflags="-s -w" \
		-o $(BIN_DIR)/cross/implant-windows-amd64.exe $(IMPLANT_SRC)
	GOOS=darwin  GOARCH=arm64 CGO_ENABLED=0 $(GO) build $(GOFLAGS) -trimpath -ldflags="-s -w" \
		-o $(BIN_DIR)/cross/implant-darwin-arm64 $(IMPLANT_SRC)

# ---- Clean ----------------------------------------------------------------

clean:  ## Remove build artefacts
	rm -rf $(BIN_DIR)
	$(GO) clean -cache -testcache

# ---- Help -----------------------------------------------------------------

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
