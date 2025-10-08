# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOMOD=$(GOCMD) mod
GOFMT=$(GOCMD) fmt
GOVET=$(GOCMD) vet

# Build targets
.PHONY: all build test fmt lint clean docker-test docker-build docker-shell help

all: test build

help:
	@echo "go-cms Makefile targets:"
	@echo ""
	@echo "  make build         - Build the cms-test-tool binary"
	@echo "  make test          - Run all tests with race detector and coverage"
	@echo "  make fmt           - Format all Go code"
	@echo "  make lint          - Run golangci-lint"
	@echo "  make clean         - Remove build artifacts and test files"
	@echo ""
	@echo "Docker-based OpenSSL testing:"
	@echo "  make docker-build  - Build Docker test image"
	@echo "  make docker-test   - Run OpenSSL interop tests in Docker"
	@echo "  make docker-shell  - Get a shell in Docker for debugging"
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

.DEFAULT_GOAL := help
