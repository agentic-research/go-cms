FROM golang:1.25.1-bookworm

# Install OpenSSL 3.x
RUN apt-get update && apt-get install -y \
    openssl \
    && rm -rf /var/lib/apt/lists/*

# Verify OpenSSL version
RUN openssl version

WORKDIR /app

# Copy go module files
COPY go.mod go.sum* ./
RUN go mod download || true

# Copy source code
COPY . .

# Build the test tool
RUN go build -o bin/cms-test-tool ./cmd/cms-test-tool

# Make scripts executable
RUN chmod +x ./scripts/testing/*.sh

# Default command runs the OpenSSL tests
CMD ["bash", "-c", "./scripts/testing/test_cms_headers.sh && ./scripts/testing/test_openssl_verify.sh"]
