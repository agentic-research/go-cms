# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOMOD=$(GOCMD) mod
GOFMT=$(GOCMD) fmt
GOVET=$(GOCMD) vet

# Build targets
.PHONY: all build test fmt lint clean docker-test docker-build

all: test build

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
	docker build -f scripts/testing/docker/Dockerfile -t go-cms-test .

docker-test: docker-build
	docker run --rm go-cms-test

docker-shell: docker-build
	docker run --rm -it go-cms-test bash

.DEFAULT_GOAL := all
