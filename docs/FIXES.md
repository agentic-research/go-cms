# Security Fixes Required

## Blockers (MUST fix before production)

### ✅ 1. content-type Attribute Enforcement [COMPLETED]
**Location:** `pkg/cms/verifier.go:452-459` (parseSignedAttributes)
**RFC:** 5652 Section 5.3 - MUST include content-type when SignedAttrs present
**Status:** FIXED in verifier.go:452-474
- ✅ Parse content-type from SignedAttrs
- ✅ Verify it matches EncapContentInfo.ContentType
- ✅ Reject if missing or mismatched
- ✅ Test: TestVerifyRejectMissingContentType
- ✅ Test: TestVerifyRejectMismatchedContentType

### ✅ 2. Default EKU = CodeSigning [COMPLETED]
**Location:** `pkg/cms/verifier.go:380-386` (verifyCertificateChain)
**Status:** FIXED in verifier.go:380-386
- ✅ Default to `[]ExtKeyUsage{ExtKeyUsageCodeSigning}`
- ✅ Allow override via VerifyOptions.KeyUsages
- ✅ Fail closed policy
- ✅ Test: TestVerifyRejectTLSCertWithDefaultEKU
- ✅ Test: TestVerifyAcceptTLSCertWithOverride

### ✅ 3. Duplicate Attributes Rejection [COMPLETED]
**Location:** `pkg/cms/verifier.go:447-450` (parseSignedAttributes)
**Status:** FIXED in verifier.go:447-474
- ✅ Track seen OIDs in a set
- ✅ Reject second occurrence of message-digest or content-type
- ✅ Test: TestVerifyRejectDuplicateMessageDigest
- ✅ Test: TestVerifyRejectDuplicateContentType

### ✅ 4. DER SET Ordering [COMPLETED]
**Location:** `pkg/cms/verifier.go:429-445` (parseSignedAttributes)
**Status:** FIXED in verifier.go:429-445
- ✅ Verify SET OF attributes are in byte-ascending order (DER canonical)
- ✅ Already reject indefinite length
- ✅ Compare raw bytes instead of re-encoding (avoids IMPLICIT tag brittleness)
- ✅ Test: TestVerifyRejectNonCanonicalSetOrder

---

## High Priority (should fix)

### ✅ 5. Ed25519 Algorithm Parameters [COMPLETED]
**Location:** `pkg/cms/verifier.go:238-247` (parseSignerInfo)
**RFC:** 8410 - encode MUST be absent; verify MUST accept absent OR NULL
**Status:** FIXED in verifier.go:238-247
- ✅ Accept absent parameters
- ✅ Accept NULL (0x05 0x00)
- ✅ Reject garbage data
- ✅ Test: TestVerifyRejectEd25519GarbageParams
- ✅ Test: TestVerifyAcceptEd25519NullParams

### ✅ 6. Signer Digest Policy [COMPLETED]
**Location:** `pkg/cms/signer.go:82-89` (SignOptions)
**Status:** FIXED in signer.go:191-210
- ✅ Add `SignOptions.DigestAlgorithm` (default SHA-256)
- ✅ Support {SHA256, SHA384, SHA512}
- ✅ Test: TestSignDataWithSHA512
- ✅ Test: TestSignDataWithSHA384

### ✅ 7. Chain Inclusion Option [COMPLETED]
**Location:** `pkg/cms/signer.go:91-96` (SignOptions)
**Status:** FIXED in signer.go:493-497
- ✅ Add `SignOptions.IntermediateCerts []*x509.Certificate`
- ✅ Append to Certificates field in buildCMS
- ✅ Test: TestSignDataWithIntermediateCerts

### ✅ 8. Signer Key Validation [COMPLETED]
**Location:** `pkg/cms/signer.go:172-189` (SignDataWithOptions)
**Status:** FIXED in signer.go:172-195
- ✅ Verify privkey matches cert.PublicKey (best-effort)
- ✅ Check DigitalSignature KeyUsage if present
- ✅ Test: TestSignDataRejectMismatchedKeys
- ✅ Test: TestSignDataRejectMissingDigitalSignatureKeyUsage

---

## Policy Defaults

```go
// VerifyOptions defaults (when fields are zero-value):
KeyUsages:        []ExtKeyUsage{ExtKeyUsageCodeSigning}  // overrideable
RevocationChecker: nil                                    // caller provides
SkipTimeValidation: false                                 // enforce NotBefore/NotAfter

// SignOptions defaults:
DigestAlgorithm:    crypto.SHA256    // allow SHA512; SHA384 opt-in
IncludeChain:       false             // via IntermediateCerts field
SkipTimeValidation: false             // (add this option)
```

---

## Test Requirements

**Valid (MUST accept):**
- ✅ Round-trip (Go signer → Go verifier)
- ❌ OpenSSL signer → Go verifier (NEEDED)
- ❌ Go signer → OpenSSL verifier (NEEDED)
- ✅ SignedAttrs with SHA-256
- ✅ SignedAttrs with SHA-512
- ✅ SignedAttrs with SHA-384
- ✅ No SignedAttrs (raw signing)

**Invalid (MUST reject):**
- ✅ Missing content-type attribute
- ✅ content-type mismatch with EncapContentInfo
- ✅ Duplicate message-digest
- ✅ Ed25519 with garbage params (accept NULL or absent)
- ✅ Non-canonical SET order
- ✅ TLS cert with default EKU policy

**Legend:** ✅ covered, ❌ needed

---

## Next 3 Commits

### ✅ Commit 1: Verifier strict mode [COMPLETED]
- ✅ content-type enforcement (verifier.go:452-474)
- ✅ Duplicate detection (verifier.go:447-450)
- ✅ SET order validation (verifier.go:429-445)
- ✅ Ed25519 params check (verifier.go:238-247)

### ✅ Commit 2: Verifier EKU defaults [COMPLETED]
- ✅ Default EKU = CodeSigning (verifier.go:380-386)
- ✅ Update VerifyOptions to fail closed
- ✅ Override capability via KeyUsages option

### ✅ Commit 3: Signer enhancements [COMPLETED]
- ✅ Digest policy option (SHA-256/SHA-384/SHA-512)
- ✅ Chain inclusion (IntermediateCerts)
- ✅ Key validation (privkey match + KeyUsage check)

---

## Non-Issues (explicitly NOT fixing)

- Full DER re-encode check (brittle with IMPLICIT tags)
- Shortest-length encoding (no concrete malleability case)
- Multi-signer support (demand-driven, future)
- Revocation checking (interface exists, caller's responsibility)

---
