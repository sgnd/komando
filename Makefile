# Common tasks. Run `make help` to list them.
BIN := bin/komando
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/sgnd/komando/internal/cli.Version=$(VERSION)

STATICCHECK := v0.8.2
GOVULNCHECK := v1.9.0

PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64

.PHONY: help build install test cover security fuzz e2e e2e-openvpn e2e-vpnclients e2e-ipsec lint licenses dist clean

help: ## Show this help
	@grep -E '^[a-z0-9-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-15s %s\n", $$1, $$2}'

build: ## Build ./bin/komando
	go build -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/komando

install: ## Install komando into $GOPATH/bin
	go install -ldflags "$(LDFLAGS)" ./cmd/komando

test: ## Fast unit tests
	go test ./...

cover: ## Unit tests, and each package's coverage against its floor (test/coverage-floor.txt)
	test/coverage.sh

e2e: ## End-to-end tests against Docker SSH servers
	test/e2e/run.sh

e2e-openvpn: ## komando's own OpenVPN client against throwaway OpenVPN 2.6 servers (UDP, TCP, tls-auth, tls-crypt, login)
	test/e2e/openvpn/run.sh

e2e-ipsec: ## komando's own L2TP/IPsec, Cisco IPsec (XAUTH) and IKEv2 clients against strongSwan and xl2tpd, in Docker
	test/e2e/ipsec/run.sh

e2e-vpnclients: ## built-in AnyConnect (ocserv) and Tailscale (Headscale) against real servers, in Docker
	test/e2e/vpnclients/run.sh

security: ## Known vulnerabilities in the code and its modules (govulncheck)
	go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK) ./...

fuzz: ## Fuzz the parsers that see untrusted text, 30s each
	go test ./internal/out -run '^$$' -fuzz '^FuzzMaskJSON$$' -fuzztime 30s
	go test ./internal/out -run '^$$' -fuzz '^FuzzMaskSecrets$$' -fuzztime 30s
	go test ./internal/policy -run '^$$' -fuzz '^FuzzCheck$$' -fuzztime 30s
	go test ./internal/cli -run '^$$' -fuzz '^FuzzGuard$$' -fuzztime 30s
	go test ./internal/cli -run '^$$' -fuzz '^FuzzHiddenPattern$$' -fuzztime 30s
	go test ./internal/cli -run '^$$' -fuzz '^FuzzCleanText$$' -fuzztime 30s
	go test ./internal/cli -run '^$$' -fuzz '^FuzzCanonicalOVPN$$' -fuzztime 30s
	go test ./internal/openvpn -run '^$$' -fuzz '^FuzzParse$$' -fuzztime 30s
	go test ./internal/openvpn -run '^$$' -fuzz '^FuzzPackets$$' -fuzztime 30s
	go test ./internal/cloud -run '^$$' -fuzz '^FuzzSSMMessage$$' -fuzztime 30s
	go test ./internal/cloud -run '^$$' -fuzz '^FuzzBitwardenCipherString$$' -fuzztime 30s
	go test ./internal/dbx -run '^$$' -fuzz '^FuzzSQLScanner$$' -fuzztime 30s

lint: ## gofmt + go vet + staticcheck
	@test -z "$$(gofmt -l .)" || (gofmt -l . && exit 1)
	go vet ./...
	go run honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK) ./...

licenses: ## Write dist/THIRD_PARTY_LICENSES (licenses of everything built into komando)
	scripts/third-party-licenses.sh dist/THIRD_PARTY_LICENSES

dist: ## Build release archives + checksums into ./dist
	rm -rf dist && mkdir -p dist
	scripts/third-party-licenses.sh dist/THIRD_PARTY_LICENSES
	@for p in $(PLATFORMS); do \
	  os=$${p%/*}; arch=$${p#*/}; name=komando_$${os}_$${arch}; \
	  echo "  $$name"; mkdir -p dist/$$name && \
	  CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$$name/komando ./cmd/komando && \
	  cp LICENSE README.md dist/THIRD_PARTY_LICENSES dist/$$name/ && \
	  tar -czf dist/$$name.tar.gz -C dist/$$name . && rm -rf dist/$$name || exit 1; \
	done
	rm dist/THIRD_PARTY_LICENSES
	cd dist && (sha256sum *.tar.gz 2>/dev/null || shasum -a 256 *.tar.gz) > checksums.txt

clean: ## Remove build output
	rm -rf bin dist
