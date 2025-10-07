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

### 2. Default EKU = CodeSigning
**Location:** `pkg/cms/verifier.go:369-371` (verifyCertificateChain)
**Fix:**
- Default to `[]ExtKeyUsage{ExtKeyUsageCodeSigning}`
- Allow override via VerifyOptions.KeyUsages
- Fail closed

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

### 6. Signer Digest Policy
**Location:** `pkg/cms/signer.go` (hardcoded SHA-256)
**Fix:**
- Add `SignOptions.DigestAlgorithm` (default SHA-256)
- Support {SHA256, SHA512}
- SHA-384 as opt-in flag (interop enhancement, not security)

### 7. Chain Inclusion Option
**Location:** `pkg/cms/signer.go` (currently only includes leaf)
**Fix:**
- Add `SignOptions.IntermediateCerts []*x509.Certificate`
- Append to Certificates field

### 8. Signer Key Validation
**Location:** `pkg/cms/signer.go:SignData`
**Fix:**
- Verify privkey matches cert.PublicKey
- Check DigitalSignature KeyUsage if present

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
- ❌ SignedAttrs with SHA-512
- ✅ No SignedAttrs (raw signing)

**Invalid (MUST reject):**
- ✅ Missing content-type attribute
- ✅ content-type mismatch with EncapContentInfo
- ✅ Duplicate message-digest
- ✅ Ed25519 with garbage params (accept NULL or absent)
- ✅ Non-canonical SET order
- ❌ TLS cert with default EKU policy

**Legend:** ✅ covered, ❌ needed

---

## Next 3 Commits

### ✅ Commit 1: Verifier strict mode [COMPLETED]
- ✅ content-type enforcement (verifier.go:452-474)
- ✅ Duplicate detection (verifier.go:447-450)
- ✅ SET order validation (verifier.go:429-445)
- ✅ Ed25519 params check (verifier.go:238-247)

### Commit 2: Verifier EKU defaults
- Default EKU = CodeSigning
- Update VerifyOptions to fail closed

### Commit 3: Signer enhancements
- Digest policy option
- Chain inclusion
- Key validation

---

## Non-Issues (explicitly NOT fixing)

- Full DER re-encode check (brittle with IMPLICIT tags)
- Shortest-length encoding (no concrete malleability case)
- Multi-signer support (demand-driven, future)
- Revocation checking (interface exists, caller's responsibility)

---

**Ready for diffs? Say which commit you want first.**
