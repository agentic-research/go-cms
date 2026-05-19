# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOMOD=$(GOCMD) mod
GOFMT=$(GOCMD) fmt
GOVET=$(GOCMD) vet

# Build targets
.PHONY: all build test fmt lint clean docker-test docker-build docker-shell help \
        long-fuzz overnight-fuzz mutation-test govulncheck

# Fuzz settings — override on the command line, e.g.
#   make long-fuzz FUZZTIME=1h
FUZZTIME ?= 10m

all: test build

help:
	@echo "go-cms Makefile targets:"
	@echo ""
	@echo "  make build           - Build the cms-test-tool binary"
	@echo "  make test            - Run all tests with race detector and coverage"
	@echo "  make fmt             - Format all Go code"
	@echo "  make lint            - Run golangci-lint"
	@echo "  make clean           - Remove build artifacts and test files"
	@echo ""
	@echo "Audit-level test targets:"
	@echo "  make long-fuzz       - Run every fuzz target for FUZZTIME each"
	@echo "                         (default 10m; override with FUZZTIME=30m or 1h)"
	@echo "  make overnight-fuzz  - long-fuzz with FUZZTIME=1h per target (~12h total)"
	@echo "  make mutation-test   - Run gremlins mutation testing on pkg/cms"
	@echo "  make govulncheck     - Surface stdlib/dependency CVEs"
	@echo ""
	@echo "Docker-based OpenSSL testing:"
	@echo "  make docker-build    - Build Docker test image"
	@echo "  make docker-test     - Run OpenSSL interop tests in Docker"
	@echo "  make docker-shell    - Get a shell in Docker for debugging"
	@echo ""
	@echo "Default target: make all (test + build)"

build:
	mkdir -p bin
	$(GOBUILD) -o bin/cms-test-tool ./cmd/cms-test-tool

test:
	$(GOTEST) -v -race -cover ./...

fmt:
	$(GOFMT) ./...

lint:
	golangci-lint run

clean:
	rm -rf bin/
	rm -f *.pem *.der *.txt coverage.out

# Docker-based OpenSSL testing
docker-build:
	docker build --no-cache -f scripts/testing/docker/Dockerfile -t go-cms-test .

docker-test:
	docker build --no-cache -f scripts/testing/docker/Dockerfile -t go-cms-test .
	@echo "Running OpenSSL 3.x interoperability tests..."
	docker run --rm go-cms-test

docker-shell: docker-build
	docker run --rm -it go-cms-test bash

# Long-running fuzz suite. Each target gets FUZZTIME of CPU time. Anchored
# regexes prevent multi-match (e.g. FuzzVerify vs FuzzVerifyAcceptsOnlyCanonicalForm).
long-fuzz:
	@echo "Running every fuzz target for $(FUZZTIME) each."
	@echo "Total wall time ≈ $(FUZZTIME) × (number of fuzz targets)."
	@for target in \
	    FuzzVerify \
	    FuzzParseASN1Length \
	    FuzzExtractSetContent \
	    FuzzUnwrapContext0 \
	    FuzzConstantTimeCompareBigInt \
	    FuzzSignVerifyRoundtrip \
	    FuzzSignDataWithoutAttributesRoundtrip \
	    FuzzSignDataWithSignerRoundtrip \
	    FuzzCase2SignDeterminism \
	    FuzzInsertByte \
	    FuzzDeleteByte \
	    FuzzAppendTrailingData \
	    FuzzCertBagSubstitution \
	    FuzzVerifyAcceptsOnlyCanonicalForm \
	    FuzzReplaceOIDBytes \
	    FuzzDeclaredLengthOverflow \
	    ; do \
	    echo "=== $$target ($(FUZZTIME)) ==="; \
	    $(GOTEST) -fuzz="^$$target$$" -fuzztime=$(FUZZTIME) ./pkg/cms || exit 1; \
	done
	@echo ""
	@echo "Long fuzz complete. Any crashes are now under pkg/cms/testdata/fuzz/."

# Overnight fuzz: 1 hour per target. Roughly 16 hours wall time for the
# current target list. Run on a dedicated machine; not part of CI.
overnight-fuzz:
	@$(MAKE) long-fuzz FUZZTIME=1h

# Mutation testing — verifies that the test suite would actually fail if
# someone introduced a logic bug. Surviving mutants point at test gaps.
mutation-test:
	@which gremlins >/dev/null 2>&1 || $(GOCMD) install github.com/go-gremlins/gremlins/cmd/gremlins@latest
	@echo "Running gremlins on pkg/cms (this can take several minutes)."
	@cd pkg/cms && GOWORK=off gremlins unleash --timeout-coefficient 5

# govulncheck — surface stdlib and dependency CVEs reachable from our
# call graph. Mirrors the CI check.
govulncheck:
	@which govulncheck >/dev/null 2>&1 || $(GOCMD) install golang.org/x/vuln/cmd/govulncheck@latest
	govulncheck ./...

.DEFAULT_GOAL := help
