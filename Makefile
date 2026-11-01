# Common tasks. Run `make help` to list them.
BIN := bin/komando
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/sgnd/komando/internal/cli.Version=$(VERSION)

.PHONY: help build install test e2e lint clean

help: ## Show this help
	@grep -E '^[a-z]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-8s %s\n", $$1, $$2}'

build: ## Build ./bin/komando
	go build -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/komando

install: ## Install komando into $GOPATH/bin
	go install -ldflags "$(LDFLAGS)" ./cmd/komando

test: ## Fast unit tests
	go test ./...

e2e: ## End-to-end tests against Docker SSH servers
	test/e2e/run.sh

lint: ## gofmt + go vet
	@test -z "$$(gofmt -l .)" || (gofmt -l . && exit 1)
	go vet ./...

clean: ## Remove build output
	rm -rf bin
