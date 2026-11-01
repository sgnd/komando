# Common tasks. Run `make help` to list them.
BIN := bin/komando
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/sgnd/komando/internal/cli.Version=$(VERSION)

PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64

.PHONY: help build install test e2e e2e-openvpn lint dist clean

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

e2e-openvpn: ## OpenVPN-in-a-container test against a throwaway OpenVPN server
	test/e2e/openvpn/run.sh

lint: ## gofmt + go vet
	@test -z "$$(gofmt -l .)" || (gofmt -l . && exit 1)
	go vet ./...

dist: ## Build release archives + checksums into ./dist
	rm -rf dist && mkdir -p dist
	@for p in $(PLATFORMS); do \
	  os=$${p%/*}; arch=$${p#*/}; name=komando_$${os}_$${arch}; \
	  echo "  $$name"; mkdir -p dist/$$name && \
	  CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$$name/komando ./cmd/komando && \
	  cp LICENSE README.md dist/$$name/ && \
	  tar -czf dist/$$name.tar.gz -C dist/$$name . && rm -rf dist/$$name || exit 1; \
	done
	cd dist && (sha256sum *.tar.gz 2>/dev/null || shasum -a 256 *.tar.gz) > checksums.txt

clean: ## Remove build output
	rm -rf bin dist
