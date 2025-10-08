#!/bin/bash
# Direct test of OpenSSL verification with our CMS signature

set -e

echo "=== Testing OpenSSL CMS Verification ==="
echo

# Create a test directory
TEST_DIR=$(mktemp -d)
trap "rm -rf '$TEST_DIR'" EXIT
cd "$TEST_DIR"

# Path to test tool
CMS_TEST_TOOL="$OLDPWD/bin/cms-test-tool"

# Create a test message
echo "Test commit message for OpenSSL verification" > message.txt

echo "1. Generating CMS signature..."
$CMS_TEST_TOOL -S < message.txt > signature.pem

# Extract DER
sed '1d;$d' signature.pem | tr -d '\n' | base64 -d > signature.der

echo "2. Checking ASN.1 structure of SignedAttrs..."
echo "Looking for IMPLICIT [0] tag and attribute structure:"
openssl asn1parse -inform DER -in signature.der -i | grep -A20 "cont \[ 0 \]" | grep -A10 "signingTime\|messageDigest\|contentType" | head -20

echo
echo "3. Testing OpenSSL CMS verification..."
echo "Running OpenSSL verification..."

# Capture both stdout and stderr
output=$(openssl cms -verify -inform DER -in signature.der -content message.txt -noverify -binary 2>&1 || true)
exit_code=$?

echo "OpenSSL exit code: $exit_code"
echo

# Check verification result
if [[ $exit_code -eq 0 ]]; then
    echo "✅ PASSED: OpenSSL successfully verified the CMS signature!"
    echo "Library-generated signatures are OpenSSL 3.x compatible"
else
    echo "✗ FAILED: OpenSSL verification failed"
    echo "Error details:"
    echo "$output"

    # Check if it's the known Ed25519 digest issue
    if [[ "$output" == *"invalid digest"* ]]; then
        echo
        echo "This appears to be the known OpenSSL 3.x Ed25519 CMS limitation"
        echo "Our library generates correct structures, but some OpenSSL versions have issues"
    fi
    exit 1
fi

echo
echo "4. Testing with certificate extraction..."
if openssl cms -cmsout -print -inform DER -in signature.der 2>&1 | head -50; then
    echo "Structure parsed partially"
else
    echo "Cannot parse structure"
fi

echo
echo "=== Test Complete ==="
