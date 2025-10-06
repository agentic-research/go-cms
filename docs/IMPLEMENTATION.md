# CMS/PKCS#7 Implementation for Ed25519

> **⚠️ SECURITY NOTE**
> **This library has not received an independent security review.**
> Use at your own risk in production environments.

## Overview

This document describes a pure Go implementation of CMS (Cryptographic Message Syntax) / PKCS#7 signing with Ed25519 support. While existing maintained Go CMS libraries (mozilla/pkcs7, digitorus/pkcs7, cloudflare/cfssl) target RSA/ECDSA, this library provides Ed25519 signing and verification capabilities.

## Background

### The Problem

Existing Go CMS/PKCS#7 libraries lack Ed25519 signing support:
- **Mozilla pkcs7**: Only supports RSA and ECDSA
- **Cloudflare CFSSL**: Read-only PKCS#7, no signature creation
- **GitHub smimesign**: SHA256-RSA only
- **YapealAG/adapted-digitorus-pkcs7**: Has ed25519 types but no documented CMS Ed25519 support

Applications requiring CMS-formatted Ed25519 signatures (e.g., Git X.509 commits) need this capability.

### The Solution

A minimal but complete pure Go CMS signing library supporting:
- Ed25519 signatures (RFC 8419, RFC 8410)
- Detached signatures
- ASN.1 DER encoding
- OpenSSL-compatible output
- No CGO dependencies

## Technical Implementation

### ASN.1 Structure

The CMS SignedData structure follows RFC 5652:

```asn1
ContentInfo ::= SEQUENCE {
  contentType    OBJECT IDENTIFIER (id-signedData),
  content   [0]  EXPLICIT SignedData
}

SignedData ::= SEQUENCE {
  version          INTEGER,
  digestAlgorithms SET OF AlgorithmIdentifier,
  encapContentInfo EncapsulatedContentInfo,
  certificates [0] IMPLICIT CertificateSet OPTIONAL,
  signerInfos      SET OF SignerInfo
}

SignerInfo ::= SEQUENCE {
  version                INTEGER,
  sid                    SignerIdentifier,
  digestAlgorithm        AlgorithmIdentifier,
  signedAttrs       [0]  IMPLICIT SignedAttributes OPTIONAL,
  signatureAlgorithm     AlgorithmIdentifier,
  signature              OCTET STRING
}
```

### Critical Implementation Details

#### 1. IMPLICIT vs EXPLICIT Encoding

The most challenging aspect was correctly implementing the IMPLICIT [0] tag for SignedAttributes:

- **What we sign**: SET OF Attributes with SET tag (0x31)
- **What we store**: [0] IMPLICIT with attributes directly (tag 0xA0)

```go
// Sign with SET tag
func encodeAttributesAsSet(attrs []attribute) ([]byte, error) {
    // Returns: 31 <length> <sorted-attributes>
}

// Store with IMPLICIT [0] tag
func encodeSignedAttributesImplicit(attrs []attribute) ([]byte, error) {
    // Returns: A0 <length> <sorted-attributes-without-set-tag>
}
```

#### 2. Canonical DER Ordering

Attributes must be sorted for deterministic signatures:

```go
sort.Slice(encodedAttrs, func(i, j int) bool {
    return bytes.Compare(encodedAttrs[i], encodedAttrs[j]) < 0
})
```

#### 3. OpenSSL Compatibility

Key requirements for OpenSSL verification:
- Use `-binary` flag to prevent S/MIME canonicalization
- Include Subject Key Identifier extension
- Proper OID for Ed25519: 1.3.101.112

### OpenSSL Verification

To verify CMS signatures with OpenSSL (using detached signature format):

```bash
# Given: signature.der (CMS signature) and message.txt (original content)

# Verify with OpenSSL
openssl cms -verify \
    -inform DER \
    -in signature.der \
    -content message.txt \
    -certfile cert.pem \
    -noverify \
    -binary

# The -binary flag prevents S/MIME canonicalization
# The -noverify flag skips certificate chain validation (useful for self-signed certs)
```

## Test Coverage

The implementation includes comprehensive tests:

1. **ASN.1 Encoding Tests**
   - SET vs SEQUENCE validation
   - IMPLICIT [0] encoding verification
   - Canonical ordering checks

2. **RFC 8032 Test Vectors**
   - Ed25519 signature correctness

3. **Interoperability Tests**
   - OpenSSL CMS verification
   - Round-trip signing and verification

4. **Fuzz Testing**
   - Verifier robustness against malformed inputs

## Performance

| Operation | Time |
|-----------|------|
| Key Generation | ~1ms |
| Certificate Creation | ~5ms |
| CMS Signature | ~3ms |
| **Total** | **< 10ms** |

## Security Considerations

1. **Input Validation**: Strict size limits prevent memory exhaustion (1MB CMS max, 64KB cert max)
2. **Algorithm Restrictions**: Only SHA-256 digest and Ed25519 signatures accepted
3. **Canonical Encoding**: DER encoding enforced throughout
4. **No Malleability**: Ed25519 canonical S values per RFC 8032

## Known Limitations

1. **SHA-256 Digest Algorithm**: RFC 8419 recommends SHA-512 for Ed25519 in CMS. However, this implementation uses SHA-256 for OpenSSL compatibility. Ed25519 is a "pure" signature scheme that internally uses SHA-512. Specifying SHA-512 as the digest algorithm causes double-hashing, which breaks OpenSSL verification.
2. **Self-Signed Certificates**: Examples use self-signed certificates; production deployments should use proper CA infrastructure
3. **No Revocation**: CRL/OCSP not implemented
4. **Ed25519 Only**: Currently supports Ed25519 signatures only (no RSA, ECDSA, or Ed448)

## Future Improvements

1. **SHA-512 Support**: Add configurable digest algorithm
2. **Certificate Chain**: Support intermediate CAs
3. **Streaming**: Support large file signing without loading into memory
4. **Hardware Security**: HSM/TPM integration for key protection

## References

- [RFC 5652](https://www.rfc-editor.org/rfc/rfc5652): Cryptographic Message Syntax
- [RFC 8419](https://www.rfc-editor.org/rfc/rfc8419): EdDSA in CMS
- [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032): Edwards-Curve Digital Signature Algorithm

## Code Organization

- **Signing**: [`pkg/cms/signer.go`](../pkg/cms/signer.go)
- **Verification**: [`pkg/cms/verifier.go`](../pkg/cms/verifier.go)
- **Tests**: [`pkg/cms/signer_test.go`](../pkg/cms/signer_test.go), [`pkg/cms/verifier_test.go`](../pkg/cms/verifier_test.go)
- **Fuzz Tests**: [`pkg/cms/fuzz_test.go`](../pkg/cms/fuzz_test.go)
