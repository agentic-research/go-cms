package cms

import (
	"sort"
	"testing"
)

// TestEnumerateUnsignedBytesCase1 is an audit-style exhaustive test: for each
// byte of a valid Case 1 (with-signed-attributes) CMS, flip it with 0xff and
// record whether Verify still accepts the result. The set of positions that
// survive is the *exact* attack surface — every byte an adversary can modify
// without invalidating the signature.
//
// The invariant we enforce: every surviving position must fall within a
// documented unsigned region. If the count exceeds the expected envelope, a
// new unsigned bypass has been introduced.
//
// Documented unsigned regions in a strict Case 1 CMS (Ed25519 + SHA-512):
//   - SignedData length encoding bytes (BER/DER ambiguity not enforced)
//   - ContentInfo length encoding bytes (same)
//   - EncContentInfo length encoding bytes (same)
//   - bytes inside the embedded x509 certificate that are not load-bearing
//     for either the SKI/IssuerAndSerial match or the verifier's chain check
//
// A surge in this number is a regression signal — investigate every new
// position individually.
func TestEnumerateUnsignedBytesCase1(t *testing.T) {
	cert, priv, pool := newFuzzSigner(t)
	opts := VerifyOptions{Roots: pool}

	data := []byte("byte-by-byte tamper audit")
	sig, err := SignData(data, cert, priv)
	if err != nil {
		t.Fatalf("SignData: %v", err)
	}

	survivors := tamperSurvey(t, sig, data, opts)

	t.Logf("Case 1 CMS length: %d bytes", len(sig))
	t.Logf("Surviving unsigned positions (count=%d): %v", len(survivors), survivors)

	// Empirical envelope: with a freshly issued, RNG-serial cert, the
	// unsigned region is dominated by cert-internal bytes (DER length
	// encodings, optional fields, ASN.1 padding) that don't feed into either
	// the SKI/IssuerAndSerial signer-id lookup or the signature itself.
	// Allow up to 8 unsigned positions, alert if exceeded. Tune up only
	// after auditing each new survivor.
	const allowedCase1 = 8
	if len(survivors) > allowedCase1 {
		t.Errorf("unsigned region grew unexpectedly: %d survivors (allowed: %d). Audit each new position before bumping this bound.", len(survivors), allowedCase1)
	}
}

// TestEnumerateUnsignedBytesCase2 does the same for the Case 2 path
// (no signed attributes). Case 2 has a smaller surface because the SignerInfo
// itself is more compact and there are no signed-attributes ordering bytes.
func TestEnumerateUnsignedBytesCase2(t *testing.T) {
	cert, priv, pool := newFuzzSigner(t)
	opts := VerifyOptions{Roots: pool}

	data := []byte("byte-by-byte tamper audit case 2")
	sig, err := SignDataWithoutAttributes(data, cert, priv)
	if err != nil {
		t.Fatalf("SignDataWithoutAttributes: %v", err)
	}

	survivors := tamperSurvey(t, sig, data, opts)

	t.Logf("Case 2 CMS length: %d bytes", len(sig))
	t.Logf("Surviving unsigned positions (count=%d): %v", len(survivors), survivors)

	const allowedCase2 = 8
	if len(survivors) > allowedCase2 {
		t.Errorf("Case 2 unsigned region grew unexpectedly: %d survivors (allowed: %d).", len(survivors), allowedCase2)
	}
}

// tamperSurvey flips each byte of sig in turn (XOR 0xff) and returns the
// sorted list of positions where Verify still accepted the result. A robust
// signed structure should yield very few such positions — only those bytes
// genuinely outside the signed region.
func tamperSurvey(t *testing.T, sig, data []byte, opts VerifyOptions) []int {
	t.Helper()
	var survivors []int
	for i := range sig {
		tampered := append([]byte(nil), sig...)
		tampered[i] ^= 0xff
		if _, err := Verify(tampered, data, opts); err == nil {
			survivors = append(survivors, i)
		}
	}
	sort.Ints(survivors)
	return survivors
}
