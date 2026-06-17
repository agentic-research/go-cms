package cms

import (
	"bytes"
	"testing"
)

// These tests exercise SignerInfo paths that the production signer
// (SignData / SignDataWithoutAttributes / SignDataWithSigner) cannot
// emit — chiefly the SubjectKeyIdentifier (SKI) form of SignerIdentifier
// per RFC 5652 Case B. Mutation-testing baseline before this file
// showed ~60 mutants in matchesSID and the SignerInfo.Version
// cross-check were NOT COVERED, because no test reached that branch.
// All construction goes through buildTestCMS (cms_builder_test.go).

// TestBuilderHappyPath_IAS sanity-checks the harness: with all defaults
// (IAS-form, v1, id-data eContent) the verifier must accept it. If this
// fails, the builder itself is wrong and every other test in this file
// is meaningless.
func TestBuilderHappyPath_IAS(t *testing.T) {
	cert, priv, pool := newBuilderSigner(t)
	data := []byte("happy-path IAS")

	sig := buildTestCMS(t, cert, priv, cmsBuildConfig{Data: data})
	certs, err := Verify(sig, data, VerifyOptions{Roots: pool})
	if err != nil {
		t.Fatalf("Verify rejected builder default IAS-form CMS: %v", err)
	}
	if !bytes.Equal(certs[0].Raw, cert.Raw) {
		t.Fatalf("Verify returned wrong cert")
	}
}

// TestBuilderHappyPath_SKI is the load-bearing test for the SKI branch:
// build a CMS with [0] IMPLICIT OCTET STRING SignerIdentifier carrying
// the cert's SubjectKeyId, and confirm Verify accepts it. This exercises
// the entire matchesSID SKI path (lines 1011-1022) which the production
// signer never reaches.
func TestBuilderHappyPath_SKI(t *testing.T) {
	cert, priv, pool := newBuilderSigner(t)
	data := []byte("happy-path SKI")

	sig := buildTestCMS(t, cert, priv, cmsBuildConfig{
		Data:    data,
		SIDForm: sidSKI,
	})
	certs, err := Verify(sig, data, VerifyOptions{Roots: pool})
	if err != nil {
		t.Fatalf("Verify rejected SKI-form CMS: %v", err)
	}
	if !bytes.Equal(certs[0].Raw, cert.Raw) {
		t.Fatalf("Verify returned wrong cert for SKI form")
	}
}

// TestSKI_VersionMustBe3 confirms the SignerInfo.Version cross-check
// rejects SKI+v1 (per RFC 5652 §5.3). This kills the
// CONDITIONALS_NEGATION mutants at verifier.go:216:* that survived
// before because no SKI test existed.
func TestSKI_VersionMustBe3(t *testing.T) {
	cert, priv, pool := newBuilderSigner(t)
	data := []byte("ski v1 mismatch")

	sig := buildTestCMS(t, cert, priv, cmsBuildConfig{
		Data:      data,
		SIDForm:   sidSKI,
		SIVersion: 1, // explicit wrong version
	})
	if _, err := Verify(sig, data, VerifyOptions{Roots: pool}); err == nil {
		t.Fatal("Verify accepted SKI-form SignerInfo with Version=1; RFC 5652 §5.3 requires 3")
	}
}

// TestIAS_VersionMustBe1 is the symmetric check for the IAS path.
// Already covered by an existing rfc8419 test, but we restate it via the
// builder so it's exercised through the same code path as the SKI
// variants, ensuring no SID/version cross-check regressions sneak in.
func TestIAS_VersionMustBe1(t *testing.T) {
	cert, priv, pool := newBuilderSigner(t)
	data := []byte("ias v3 mismatch")

	sig := buildTestCMS(t, cert, priv, cmsBuildConfig{
		Data:      data,
		SIDForm:   sidIAS,
		SIVersion: 3, // explicit wrong version
	})
	if _, err := Verify(sig, data, VerifyOptions{Roots: pool}); err == nil {
		t.Fatal("Verify accepted IAS-form SignerInfo with Version=3; RFC 5652 §5.3 requires 1")
	}
}

// TestSKI_KeyIdMismatchRejects fills the SKI bytes with 0xff (corrupt)
// so the value cannot match the cert's actual SubjectKeyId. matchesSID
// must reject. Kills the boundary mutants at verifier.go:1019 that
// compare the SKI lengths and the body comparison.
func TestSKI_KeyIdMismatchRejects(t *testing.T) {
	cert, priv, pool := newBuilderSigner(t)
	data := []byte("ski corrupted id")

	sig := buildTestCMS(t, cert, priv, cmsBuildConfig{
		Data:       data,
		SIDForm:    sidSKI,
		CorruptSKI: true,
	})
	if _, err := Verify(sig, data, VerifyOptions{Roots: pool}); err == nil {
		t.Fatal("Verify accepted SKI-form SignerInfo whose key id does not match the cert")
	}
}

// TestSKI_TamperResistance: an SKI-form valid signature must reject any
// single-byte tamper of the detached data, mirroring the IAS-form
// roundtrip invariant. Ensures the SKI path doesn't accidentally skip
// signature verification.
func TestSKI_TamperResistance(t *testing.T) {
	cert, priv, pool := newBuilderSigner(t)
	data := []byte("ski tamper test")

	sig := buildTestCMS(t, cert, priv, cmsBuildConfig{
		Data:    data,
		SIDForm: sidSKI,
	})

	tampered := append([]byte(nil), data...)
	tampered[0] ^= 0xff
	if _, err := Verify(sig, tampered, VerifyOptions{Roots: pool}); err == nil {
		t.Fatal("Verify accepted SKI-form CMS against tampered data")
	}
}

// TestSKI_RejectsExplicitWrapping proves the verifier rejects the
// non-canonical "EXPLICIT [0]" encoding of SubjectKeyIdentifier
// (A0 <len> 04 <ski-len> <ski>). RFC 5652's ASN.1 module uses IMPLICIT
// TAGS by default, so the canonical encoding is 80 <len> <ski>;
// accepting both would be a malleability surface (same logical SID with
// two different DER byte sequences) and would break content-addressing
// guarantees built on CMS-blob hashes.
//
// Before the matchesSID fix in this branch, the verifier ONLY accepted
// the EXPLICIT form — meaning it rejected canonical SKI emitted by
// OpenSSL and github.com/github/ietf-cms.
func TestSKI_RejectsExplicitWrapping(t *testing.T) {
	cert, priv, pool := newBuilderSigner(t)
	data := []byte("ski rejects explicit")

	sig := buildTestCMS(t, cert, priv, cmsBuildConfig{
		Data:           data,
		SIDForm:        sidSKI,
		SKIUseExplicit: true,
	})
	if _, err := Verify(sig, data, VerifyOptions{Roots: pool}); err == nil {
		t.Fatal("Verify accepted non-canonical EXPLICIT [0] SubjectKeyIdentifier; should reject per RFC 5652 IMPLICIT TAGS")
	}
}

// TestSKI_Case2 builds an SKI-form Case 2 (no signed attributes) CMS
// and verifies it. Exercises the intersection of two code paths the
// production signer cannot emit together: SKI SID plus the Case 2
// signature contract.
func TestSKI_Case2(t *testing.T) {
	cert, priv, pool := newBuilderSigner(t)
	data := []byte("ski case 2")

	sig := buildTestCMS(t, cert, priv, cmsBuildConfig{
		Data:      data,
		SIDForm:   sidSKI,
		OmitAttrs: true,
	})
	if _, err := Verify(sig, data, VerifyOptions{Roots: pool}); err != nil {
		t.Fatalf("Verify rejected SKI-form Case 2 CMS: %v", err)
	}
}
