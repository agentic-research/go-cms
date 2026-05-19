package cms

import (
	"bytes"
	"testing"
)

// FuzzInsertByte asserts that inserting a single arbitrary byte at any
// position of a valid CMS structure breaks verification. Insertion shifts
// every subsequent byte by one, which should invalidate the ASN.1 length
// chain top-to-bottom; any insertion the verifier still accepts is either a
// length-encoding bypass or a code path that doesn't actually consult the
// inserted region.
func FuzzInsertByte(f *testing.F) {
	f.Add([]byte("seed"), uint(0), byte(0x00))
	f.Add([]byte("seed"), uint(10), byte(0xff))

	cert, priv, pool := newFuzzSigner(f)
	opts := VerifyOptions{Roots: pool}

	f.Fuzz(func(t *testing.T, data []byte, insertIdx uint, insertVal byte) {
		if len(data) > fuzzMaxInputSize {
			t.Skip("oversize input")
		}
		sig, err := SignData(data, cert, priv)
		if err != nil {
			t.Fatalf("SignData: %v", err)
		}

		idx := int(insertIdx % uint(len(sig)+1))
		tampered := make([]byte, 0, len(sig)+1)
		tampered = append(tampered, sig[:idx]...)
		tampered = append(tampered, insertVal)
		tampered = append(tampered, sig[idx:]...)

		if _, err := Verify(tampered, data, opts); err == nil {
			t.Fatalf("Verify accepted CMS with extra byte inserted at offset %d (val=0x%02x)", idx, insertVal)
		}
	})
}

// FuzzDeleteByte asserts that deleting any single byte breaks verification.
// Deletion shifts the trailing bytes and shortens the structure — every
// length field on the outer chain should fail to match.
func FuzzDeleteByte(f *testing.F) {
	f.Add([]byte("seed"), uint(0))
	f.Add([]byte("seed"), uint(50))

	cert, priv, pool := newFuzzSigner(f)
	opts := VerifyOptions{Roots: pool}

	f.Fuzz(func(t *testing.T, data []byte, deleteIdx uint) {
		if len(data) > fuzzMaxInputSize {
			t.Skip("oversize input")
		}
		sig, err := SignData(data, cert, priv)
		if err != nil {
			t.Fatalf("SignData: %v", err)
		}

		idx := int(deleteIdx % uint(len(sig)))
		tampered := make([]byte, 0, len(sig)-1)
		tampered = append(tampered, sig[:idx]...)
		tampered = append(tampered, sig[idx+1:]...)

		if _, err := Verify(tampered, data, opts); err == nil {
			t.Fatalf("Verify accepted CMS with byte deleted at offset %d", idx)
		}
	})
}

// FuzzAppendTrailingData asserts that any non-empty data appended after a
// valid CMS structure must be rejected. The outer ContentInfo parse should
// detect trailing data; if it doesn't, that's a parser laxity bypass.
func FuzzAppendTrailingData(f *testing.F) {
	f.Add([]byte("seed"), []byte{0x00})
	f.Add([]byte("seed"), []byte{0xff, 0xff, 0xff})

	cert, priv, pool := newFuzzSigner(f)
	opts := VerifyOptions{Roots: pool}

	f.Fuzz(func(t *testing.T, data []byte, trailer []byte) {
		if len(data) > fuzzMaxInputSize || len(trailer) > 4096 {
			t.Skip("oversize input")
		}
		if len(trailer) == 0 {
			t.Skip("empty trailer is no-op")
		}
		sig, err := SignData(data, cert, priv)
		if err != nil {
			t.Fatalf("SignData: %v", err)
		}
		tampered := append([]byte(nil), sig...)
		tampered = append(tampered, trailer...)

		if _, err := Verify(tampered, data, opts); err == nil {
			t.Fatalf("Verify accepted CMS with %d trailing bytes appended", len(trailer))
		}
	})
}

// FuzzCertBagSubstitution generates two unrelated signing pairs (A, B), signs
// data with A, then replaces every occurrence of A's cert DER inside the CMS
// blob with B's cert DER (sizes match because both certs are produced with
// the same template). Verification must reject — the signature was produced
// by A's key, so B's public key cannot verify it.
//
// This is the canonical "wrong cert in cert bag" attack. A bug here would be
// catastrophic: a valid signature from any trusted key would attest to any
// chosen cert/identity.
func FuzzCertBagSubstitution(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("a"))
	f.Add([]byte("substitution attack data"))

	certA, keyA, _ := newFuzzSigner(f)
	certB, _, _ := newFuzzSigner(f)

	// Build a trust pool containing only A — substitution must still fail
	// whether or not B is trusted.
	poolA := newPool(certA)
	poolAB := newPool(certA, certB)

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > fuzzMaxInputSize {
			t.Skip("oversize input")
		}
		sig, err := SignData(data, certA, keyA)
		if err != nil {
			t.Fatalf("SignData: %v", err)
		}

		// Substitute A's cert with B's cert in the CMS blob (same length
		// because both came from CreateCertificate with the same template;
		// if sizes happen to differ, skip this iteration — we cannot do a
		// naive in-place swap without recomputing all ASN.1 lengths).
		if len(certA.Raw) != len(certB.Raw) {
			t.Skip("cert size mismatch — naive substitution requires equal-length DER")
		}

		idx := bytes.Index(sig, certA.Raw)
		if idx < 0 {
			t.Skip("could not locate cert A's DER inside CMS (unusual encoding)")
		}
		substituted := append([]byte(nil), sig...)
		copy(substituted[idx:idx+len(certB.Raw)], certB.Raw)

		// With either trust pool, substitution must fail.
		for _, opts := range []VerifyOptions{{Roots: poolA}, {Roots: poolAB}} {
			if _, err := Verify(substituted, data, opts); err == nil {
				t.Fatalf("Verify accepted CMS after cert substitution A→B (poolHasB=%v)", opts.Roots == poolAB)
			}
		}
	})
}

// FuzzVerifyAcceptsOnlyCanonicalForm asserts that, holding the data and
// trust root constant, the verifier yields *only* accept-or-reject outcomes
// — never panics, never crashes — across heavily mutated inputs derived
// from a valid signature. This is a stronger statement than FuzzVerify's
// "doesn't panic on arbitrary input": we start from a valid CMS and confirm
// that random mutations either get rejected cleanly or accepted with the
// correct cert bound to the result.
func FuzzVerifyAcceptsOnlyCanonicalForm(f *testing.F) {
	f.Add([]byte("hello"), uint(0), uint(50), byte(0xa5))

	cert, priv, pool := newFuzzSigner(f)
	opts := VerifyOptions{Roots: pool}
	data := []byte("canonical-form invariant data")
	good, err := SignData(data, cert, priv)
	if err != nil {
		f.Fatalf("setup: SignData: %v", err)
	}

	f.Fuzz(func(t *testing.T, _ []byte, idx1, idx2 uint, val byte) {
		// Two-byte tamper at fuzz-controlled positions. The invariant: if
		// Verify returns no error, the returned cert chain MUST start with
		// the original signer cert. Otherwise we have accepted a forgery.
		tampered := append([]byte(nil), good...)
		p1 := int(idx1 % uint(len(tampered)))
		p2 := int(idx2 % uint(len(tampered)))
		tampered[p1] ^= val
		tampered[p2] ^= val

		certs, err := Verify(tampered, data, opts)
		if err != nil {
			return // rejection is acceptable
		}
		// Accepted — must be byte-identical to the cert we signed with.
		if len(certs) == 0 {
			t.Fatalf("Verify accepted but returned no certs (positions %d,%d)", p1, p2)
		}
		if !bytes.Equal(certs[0].Raw, cert.Raw) {
			t.Fatalf("Verify accepted with substituted cert (positions %d,%d)", p1, p2)
		}
	})
}
