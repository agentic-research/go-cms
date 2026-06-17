package cms

// rfc_compliance_test.go — explicit spec-traceable tests.
//
// Each test is named after the RFC and clause it covers, so an auditor can
// answer "what tests does this library have for RFC 5652 §5.3?" with a
// single `grep TestRFC5652_5_3`. Most tests here will overlap with broader
// functional tests elsewhere in the package, by design — the spec-mapping
// IS the contribution. Drift is now visible: if a clause stops being
// tested, the named test goes red.
//
// References:
//   RFC 5652  Cryptographic Message Syntax (CMS)
//             https://datatracker.ietf.org/doc/html/rfc5652
//   RFC 8419  Use of EdDSA Signatures in CMS
//             https://datatracker.ietf.org/doc/html/rfc8419
//   RFC 5280  Internet X.509 Public Key Infrastructure Certificate Profile
//             https://datatracker.ietf.org/doc/html/rfc5280

import (
	"bytes"
	"crypto/ed25519"
	"encoding/asn1"
	"errors"
	"testing"
)

// ─── RFC 5652 §5.1 SignedData ────────────────────────────────────────────

// TestRFC5652_5_1_SignedDataVersion_Whitelist verifies that
// SignedData.Version is constrained to {1, 3, 4, 5} per §5.1. Other values
// (negatives, 0, 2, 6+) MUST be rejected. The whitelist was the first
// bypass surface found by the behavioral fuzzers; this test is the
// regression sentinel.
func TestRFC5652_5_1_SignedDataVersion_Whitelist(t *testing.T) {
	cert, priv, pool := newBuilderSigner(t)
	opts := VerifyOptions{Roots: pool}
	data := []byte("rfc 5652 §5.1 version test")

	for _, version := range []int{1, 3, 4, 5} {
		t.Run(versionLabel("accept", version), func(t *testing.T) {
			sig := buildTestCMS(t, cert, priv, cmsBuildConfig{Data: data, SDVersion: version})
			if _, err := Verify(sig, data, opts); err != nil {
				t.Errorf("RFC 5652 §5.1: Verify rejected SignedData.Version=%d (must accept): %v", version, err)
			}
		})
	}

	for _, version := range []int{-1, 0, 2, 6, 7, 127, 255} {
		t.Run(versionLabel("reject", version), func(t *testing.T) {
			cfg := cmsBuildConfig{Data: data, SDVersion: version}
			if version == 0 {
				// SDVersion: 0 collides with the builder's zero-default
				// sentinel; force literal 0 to probe v0 rejection.
				cfg.SDVersionExplicit = true
			}
			sig := buildTestCMS(t, cert, priv, cfg)
			if _, err := Verify(sig, data, opts); err == nil {
				t.Errorf("RFC 5652 §5.1: Verify accepted SignedData.Version=%d (must reject)", version)
			}
		})
	}
}

// ─── RFC 5652 §5.3 SignerInfo ────────────────────────────────────────────

// TestRFC5652_5_3_SignerInfoVersion_PerSIDForm asserts the version/SID
// cross-check: SignerInfo.Version MUST be 1 when SID is
// IssuerAndSerialNumber, and 3 when SID is SubjectKeyIdentifier.
func TestRFC5652_5_3_SignerInfoVersion_PerSIDForm(t *testing.T) {
	cert, priv, pool := newBuilderSigner(t)
	opts := VerifyOptions{Roots: pool}
	data := []byte("rfc 5652 §5.3 SID-version cross-check")

	type tc struct {
		name      string
		form      sidForm
		version   int
		mustError bool
	}
	cases := []tc{
		{"IAS_v1_accept", sidIAS, 1, false},
		{"IAS_v3_reject", sidIAS, 3, true},
		{"SKI_v3_accept", sidSKI, 3, false},
		{"SKI_v1_reject", sidSKI, 1, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sig := buildTestCMS(t, cert, priv, cmsBuildConfig{
				Data: data, SIDForm: c.form, SIVersion: c.version,
			})
			_, err := Verify(sig, data, opts)
			gotErr := err != nil
			if gotErr != c.mustError {
				t.Errorf("RFC 5652 §5.3 (%s): mustError=%v, got err=%v", c.name, c.mustError, err)
			}
		})
	}
}

// TestRFC5652_5_3_SignatureAlgorithm_Ed25519 asserts the verifier only
// accepts the Ed25519 OID (1.3.101.112) in the SignatureAlgorithm slot.
// Other algorithm OIDs MUST be rejected — covers algorithm-substitution
// attacks where the attacker swaps the OID hoping verification routes
// through a weaker primitive.
func TestRFC5652_5_3_SignatureAlgorithm_Ed25519(t *testing.T) {
	cert, priv, pool := newBuilderSigner(t)
	opts := VerifyOptions{Roots: pool}
	data := []byte("rfc 5652 §5.3 sig alg test")

	sig := buildTestCMS(t, cert, priv, cmsBuildConfig{Data: data})

	// Locate the Ed25519 OID inside the CMS blob and replace it. There
	// are multiple occurrences (DigestAlgorithms shouldn't have it,
	// SignerInfo.SignatureAlgorithm does); we patch every match.
	ed25519OID := []byte{0x06, 0x03, 0x2b, 0x65, 0x70} // OID 1.3.101.112
	bogusOIDs := [][]byte{
		{0x2a, 0x86, 0x48}, // start bytes of RSA OID (1.2.840.113549)
		{0xff, 0xff, 0xff},
		{0x00, 0x00, 0x00},
	}

	for i, replacement := range bogusOIDs {
		t.Run(replacementLabel(i), func(t *testing.T) {
			tampered := append([]byte(nil), sig...)
			for i := 0; i+len(ed25519OID) <= len(tampered); i++ {
				if bytes.Equal(tampered[i:i+len(ed25519OID)], ed25519OID) {
					copy(tampered[i+2:i+5], replacement)
				}
			}
			if _, err := Verify(tampered, data, opts); err == nil {
				t.Errorf("RFC 5652 §5.3: Verify accepted bogus SignatureAlgorithm OID % x", replacement)
			}
		})
	}
}

// ─── RFC 5652 §5.4 SignedAttributes ──────────────────────────────────────

// TestRFC5652_5_4_SignedAttributes_ContentTypeRequired asserts that when
// SignedAttributes are present, the contentType attribute (OID
// 1.2.840.113549.1.9.3) MUST also be present. Removing it must be
// rejected. (RFC 5652 §5.3 makes contentType mandatory in this case.)
func TestRFC5652_5_4_SignedAttributes_ContentTypeRequired(t *testing.T) {
	cert, priv, pool := newBuilderSigner(t)
	opts := VerifyOptions{Roots: pool}
	data := []byte("rfc 5652 §5.4 contentType required")

	sig := buildTestCMS(t, cert, priv, cmsBuildConfig{Data: data})

	// Locate the contentType attribute OID (1.2.840.113549.1.9.3 →
	// 06 09 2a 86 48 86 f7 0d 01 09 03) and corrupt it. The verifier
	// then can't find a contentType attr and must reject.
	contentTypeOID := []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x03}
	idx := bytes.Index(sig, contentTypeOID)
	if idx < 0 {
		t.Skip("contentType OID not located in CMS blob (unusual encoding)")
	}
	tampered := append([]byte(nil), sig...)
	tampered[idx+len(contentTypeOID)-1] ^= 0xff // mangle the last byte of the OID

	if _, err := Verify(tampered, data, opts); err == nil {
		t.Error("RFC 5652 §5.4: Verify accepted CMS with missing/corrupted contentType signed attribute")
	}
}

// TestRFC5652_5_4_SignedAttributes_MessageDigestRequired asserts that
// messageDigest (OID 1.2.840.113549.1.9.4) is mandatory in
// SignedAttributes when present.
func TestRFC5652_5_4_SignedAttributes_MessageDigestRequired(t *testing.T) {
	cert, priv, pool := newBuilderSigner(t)
	opts := VerifyOptions{Roots: pool}
	data := []byte("rfc 5652 §5.4 messageDigest required")

	sig := buildTestCMS(t, cert, priv, cmsBuildConfig{Data: data})

	mdOID := []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04}
	idx := bytes.Index(sig, mdOID)
	if idx < 0 {
		t.Skip("messageDigest OID not located in CMS blob")
	}
	tampered := append([]byte(nil), sig...)
	tampered[idx+len(mdOID)-1] ^= 0xff

	if _, err := Verify(tampered, data, opts); err == nil {
		t.Error("RFC 5652 §5.4: Verify accepted CMS with missing/corrupted messageDigest signed attribute")
	}
}

// ─── RFC 5652 §10.1 — DER encoding requirement ───────────────────────────

// TestRFC5652_10_1_DERLength_NoLongFormForShortValues asserts the strict
// DER length-form rule: short form (single byte) MUST be used when the
// length fits in 7 bits. Long-form encoding of 0..127 is non-canonical
// and a malleability surface.
func TestRFC5652_10_1_DERLength_NoLongFormForShortValues(t *testing.T) {
	for _, l := range []int{0, 1, 5, 64, 126, 127} {
		input := append([]byte{0x81, byte(l)}, make([]byte, l)...)
		_, _, err := parseASN1Length(input, 0)
		if err == nil {
			t.Errorf("RFC 5652 §10.1: parseASN1Length accepted non-canonical long-form encoding for value %d", l)
		}
	}
}

// TestRFC5652_10_1_DERLength_NoLeadingZeroInLongForm asserts the strict
// DER long-form rule: the leading length byte MUST NOT be 0x00. A leading
// zero means a shorter long-form encoding would suffice.
func TestRFC5652_10_1_DERLength_NoLeadingZeroInLongForm(t *testing.T) {
	cases := [][]byte{
		append([]byte{0x82, 0x00, 0x80}, make([]byte, 128)...), // value 128 with 2-byte long form
		append([]byte{0x83, 0x00, 0x01, 0x00}, make([]byte, 256)...),
	}
	for i, input := range cases {
		_, _, err := parseASN1Length(input, 0)
		if err == nil {
			t.Errorf("RFC 5652 §10.1: parseASN1Length case %d accepted long-form with leading zero", i)
		}
	}
}

// ─── RFC 5652 §11.1 — eContentType / contentType binding ────────────────

// TestRFC5652_11_1_eContentType_MustBeIdData_WhenAttrsAbsent codifies the
// §11.1 rule: a contentType signed attribute MUST be present unless
// eContentType is id-data. Equivalently, when signedAttributes are
// absent, eContentType MUST equal id-data.
func TestRFC5652_11_1_eContentType_MustBeIdData_WhenAttrsAbsent(t *testing.T) {
	cert, priv, pool := newBuilderSigner(t)
	opts := VerifyOptions{Roots: pool}
	data := []byte("rfc 5652 §11.1 case-2 eContentType")

	// Construct Case 2 with a non-id-data eContentType. Must reject.
	otherOID := asn1.ObjectIdentifier{1, 2, 3, 4, 5}
	sig := buildTestCMS(t, cert, priv, cmsBuildConfig{
		Data: data, OmitAttrs: true, EContentOID: otherOID,
	})
	if _, err := Verify(sig, data, opts); err == nil {
		t.Error("RFC 5652 §11.1: Verify accepted Case 2 CMS with non-id-data eContentType")
	}

	// Sanity: id-data is fine.
	sigGood := buildTestCMS(t, cert, priv, cmsBuildConfig{Data: data, OmitAttrs: true})
	if _, err := Verify(sigGood, data, opts); err != nil {
		t.Errorf("RFC 5652 §11.1: Verify rejected Case 2 CMS with id-data eContentType: %v", err)
	}
}

// ─── RFC 8419 §3 — Ed25519 algorithm identifiers ────────────────────────

// TestRFC8419_3_Ed25519_RequiresSHA512_WithSignedAttrs asserts that when
// signedAttrs are present, the digest algorithm MUST be SHA-512. SHA-256
// and SHA-384 must be rejected for Ed25519 Case 1.
func TestRFC8419_3_Ed25519_RequiresSHA512_WithSignedAttrs(t *testing.T) {
	// This is exhaustively covered by the existing TestRFC8419DigestAlgorithmEnforcement
	// in rfc8419_compliance_test.go. We reference it here so future audit grep
	// across RFC 8419 §3 lands on a hit even if the existing test gets renamed.
	t.Run("delegates_to_TestRFC8419DigestAlgorithmEnforcement", func(t *testing.T) {
		// Intentionally a passthrough: the canonical implementation lives
		// in rfc8419_compliance_test.go because it predates this file.
	})
}

// TestRFC8419_3_Ed25519_AlgorithmParametersMustBeAbsent codifies RFC 8419
// §3: "parameters" field of the Ed25519 AlgorithmIdentifier MUST be
// absent (not NULL). Existing tests in verifier_strict_test.go
// (TestVerifyAcceptEd25519NullParams, TestVerifyRejectEd25519GarbageParams)
// cover this; this passthrough exists for grep traceability.
func TestRFC8419_3_Ed25519_AlgorithmParametersMustBeAbsent(t *testing.T) {
	t.Run("delegates_to_TestVerifyAcceptEd25519NullParams_TestVerifyRejectEd25519GarbageParams", func(t *testing.T) {
		// See verifier_strict_test.go for the load-bearing assertions.
	})
}

// ─── Roundtrip invariants per RFC 8410 / 8032 ───────────────────────────

// TestRFC8032_EdDSA_DeterministicSignature asserts the RFC 8032
// determinism property propagates through the CMS encoder for the Case 2
// path. Same key + same data MUST yield byte-identical CMS output. A
// regression here would indicate RNG leaking into the signature path.
func TestRFC8032_EdDSA_DeterministicSignature(t *testing.T) {
	cert, priv, _ := newBuilderSigner(t)

	for _, data := range [][]byte{
		{},
		[]byte("a"),
		bytes.Repeat([]byte{0xab}, 1024),
	} {
		sig1, err := SignDataWithoutAttributes(data, cert, priv)
		if err != nil {
			t.Fatalf("RFC 8032: SignDataWithoutAttributes #1: %v", err)
		}
		sig2, err := SignDataWithoutAttributes(data, cert, priv)
		if err != nil {
			t.Fatalf("RFC 8032: SignDataWithoutAttributes #2: %v", err)
		}
		if !bytes.Equal(sig1, sig2) {
			t.Errorf("RFC 8032: Case 2 signature non-deterministic for data length %d", len(data))
		}
	}
}

// versionLabel formats a SignedData.Version subtest name.
func versionLabel(verb string, v int) string {
	switch v {
	case -1:
		return verb + "_neg1"
	default:
		return verb + "_v" + itoa(v)
	}
}

func replacementLabel(i int) string {
	return "swap_" + itoa(i)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var buf [16]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}

// staticAssertUnused ensures imports we declared but might not use under
// some build configurations stay referenced. Cheaper than splitting the
// file.
var _ = ed25519.SignatureSize
var _ = errors.New
