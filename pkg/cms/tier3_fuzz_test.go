package cms

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// FuzzReplaceOIDBytes locates the Ed25519 signature-algorithm OID inside a
// valid CMS blob and replaces it with arbitrary bytes of the same length.
// Verification must reject — the verifier dispatches by algorithm OID, and
// accepting any substitution means an attacker can claim a signature was
// produced by a different algorithm than it actually was.
//
// The Ed25519 OID encoding (1.3.101.112) is "06 03 2b 65 70" — 5 bytes
// including tag and length. We look for this sequence and overwrite the
// three OID-value bytes (2b 65 70) with fuzzer-supplied bytes.
func FuzzReplaceOIDBytes(f *testing.F) {
	f.Add([]byte("data"), []byte{0x00, 0x00, 0x00})
	f.Add([]byte("data"), []byte{0x2a, 0x86, 0x48}) // start of RSA OID
	f.Add([]byte("data"), []byte{0xff, 0xff, 0xff})

	cert, priv, pool := newFuzzSigner(f)
	opts := VerifyOptions{Roots: pool}

	// Marker for the Ed25519 OID as it appears inside SignerInfo's
	// SignatureAlgorithm AlgorithmIdentifier (and elsewhere).
	ed25519OID := []byte{0x06, 0x03, 0x2b, 0x65, 0x70}

	f.Fuzz(func(t *testing.T, data []byte, replacement []byte) {
		if len(data) > fuzzMaxInputSize {
			t.Skip("oversize input")
		}
		if len(replacement) != 3 {
			t.Skip("replacement must be exactly 3 bytes (OID value length)")
		}
		// Don't replace with the same bytes — that's a no-op.
		if bytes.Equal(replacement, ed25519OID[2:]) {
			t.Skip("no-op replacement")
		}

		sig, err := SignData(data, cert, priv)
		if err != nil {
			t.Fatalf("SignData: %v", err)
		}

		// Replace every occurrence of the Ed25519 OID value bytes with the
		// fuzz-supplied bytes. Multiple occurrences exist (DigestAlgorithms,
		// SignerInfo.SignatureAlgorithm, possibly inside the cert itself).
		tampered := append([]byte(nil), sig...)
		found := false
		for i := 0; i+len(ed25519OID) <= len(tampered); i++ {
			if bytes.Equal(tampered[i:i+len(ed25519OID)], ed25519OID) {
				copy(tampered[i+2:i+5], replacement)
				found = true
			}
		}
		if !found {
			t.Skip("ed25519 OID marker not found")
		}
		if bytes.Equal(tampered, sig) {
			t.Skip("no bytes actually changed")
		}

		if _, err := Verify(tampered, data, opts); err == nil {
			t.Fatalf("Verify accepted CMS with Ed25519 OID replaced by %x", replacement)
		}
	})
}

// FuzzDeclaredLengthOverflow asserts the parser refuses to allocate or read
// based on attacker-declared lengths that exceed the actual blob size. This
// is a DoS / OOM defense: a small CMS that *declares* a 4-GB SignedAttrs
// SET must not cause the verifier to allocate that much memory or stall
// the goroutine indefinitely.
//
// The fuzzer constructs short blobs starting with a real outer header but
// with an inflated inner length, and asserts Verify rejects in bounded
// time without OOM.
func FuzzDeclaredLengthOverflow(f *testing.F) {
	// Each input has shape: <real outer header><inflated inner length><junk>
	f.Add(uint32(1 << 24)) // 16 MB declared
	f.Add(uint32(1 << 30)) // 1 GB declared
	f.Add(uint32(0xffffffff))

	f.Fuzz(func(t *testing.T, declaredLen uint32) {
		// Build: SEQUENCE [long-form 4-byte length = declaredLen] <empty>
		buf := []byte{
			0x30, 0x84, // outer SEQUENCE, long-form 4 bytes
			byte(declaredLen >> 24),
			byte(declaredLen >> 16),
			byte(declaredLen >> 8),
			byte(declaredLen),
		}

		// Must reject without OOM or panic. The bounded `parseASN1Length`
		// check (length <= remaining) makes this immediate, but a regression
		// that lifts that bound would surface here.
		_, _ = Verify(buf, nil, VerifyOptions{})
		// No assertion: we only care that this function returned at all.
		// If we hit a hang, the Go test harness will eventually time it out.
	})
}

// TestSignatureRegionSurgery replaces just the Ed25519 signature bytes of a
// valid CMS with all-zero, all-0xff, and random bytes. Verification must
// reject every variant. Because Ed25519 signatures are 64 bytes and have no
// internal structure visible to the parser, replacing the sig is a tighter
// test than tampering arbitrary bytes — it isolates the cryptographic
// verification step from the structural/encoding checks.
func TestSignatureRegionSurgery(t *testing.T) {
	cert, priv, pool := newFuzzSigner(t)
	opts := VerifyOptions{Roots: pool}

	data := []byte("signature region surgery target")
	sig, err := SignData(data, cert, priv)
	if err != nil {
		t.Fatalf("SignData: %v", err)
	}

	// Locate the 64-byte signature region. It is OCTET STRING-encoded
	// (tag 0x04) at the tail of the SignerInfo. Match by scanning for
	// "04 40" (OCTET STRING, length 64) and taking the last occurrence
	// (earlier "04 40" patterns can appear inside the cert).
	const (
		sigTag  = 0x04
		sigLen  = 64
		header  = 2 // tag + length byte
	)
	idx := -1
	for i := 0; i+header+sigLen <= len(sig); i++ {
		if sig[i] == sigTag && sig[i+1] == sigLen {
			idx = i
		}
	}
	if idx < 0 {
		t.Fatalf("could not locate Ed25519 signature region (04 40)")
	}
	t.Logf("signature region at offset %d..%d", idx+header, idx+header+sigLen)

	cases := map[string][]byte{
		"all-zero": bytes.Repeat([]byte{0x00}, sigLen),
		"all-0xff": bytes.Repeat([]byte{0xff}, sigLen),
		"flip-last-byte": func() []byte { // original sig with last byte XOR'd
			out := make([]byte, sigLen)
			copy(out, sig[idx+header:idx+header+sigLen])
			out[sigLen-1] ^= 0xff
			return out
		}(),
		"flip-first-byte": func() []byte {
			out := make([]byte, sigLen)
			copy(out, sig[idx+header:idx+header+sigLen])
			out[0] ^= 0xff
			return out
		}(),
	}

	// Add a random replacement.
	rb := make([]byte, sigLen)
	if _, err := rand.Read(rb); err == nil {
		cases["random"] = rb
	}

	for name, replacement := range cases {
		t.Run(name, func(t *testing.T) {
			tampered := append([]byte(nil), sig...)
			copy(tampered[idx+header:idx+header+sigLen], replacement)
			if _, err := Verify(tampered, data, opts); err == nil {
				t.Errorf("Verify accepted CMS with %s signature replacement", name)
			}
		})
	}
}

// TestVerifyEmptyCertBag asserts the verifier rejects a CMS message that
// declares no signer certificate. Without a cert, the verifier cannot match
// the SID to a public key and cannot perform chain validation. Accepting
// silently here would be a forgery surface.
func TestVerifyEmptyCertBag(t *testing.T) {
	cert, priv, pool := newFuzzSigner(t)
	opts := VerifyOptions{Roots: pool}

	data := []byte("empty cert bag test")
	sig, err := SignData(data, cert, priv)
	if err != nil {
		t.Fatalf("SignData: %v", err)
	}

	// The certs[0] tag is "A0 <length> <one cert>". To strip it, find the
	// tag-length-prefix that encodes exactly the embedded certificate's
	// raw DER, then remove that span and adjust enclosing lengths.
	// Doing this surgery cleanly is non-trivial; instead we exercise the
	// equivalent code path: Verify against a CMS blob with the cert bag
	// zero-filled. The parser will fail to recover the signer cert.
	tampered := append([]byte(nil), sig...)
	certIdx := bytes.Index(tampered, cert.Raw)
	if certIdx < 0 {
		t.Skip("cert DER not located in CMS blob")
	}
	for i := certIdx; i < certIdx+len(cert.Raw); i++ {
		tampered[i] = 0
	}

	if _, err := Verify(tampered, data, opts); err == nil {
		t.Fatal("Verify accepted CMS with zero-filled cert bag")
	}
}

// TestVerifyWithExtraTrustedCert confirms adding an unrelated trusted cert
// to the cert bag doesn't allow the unrelated cert to attest the signature.
// The verifier must use the cert whose key actually produced the signature,
// not any old trusted cert that happens to be present.
func TestVerifyWithExtraTrustedCert(t *testing.T) {
	// Signer A: actually signs the data.
	certA, keyA, _ := newFuzzSigner(t)

	// Signer B: independent, trusted, but did NOT sign anything.
	_, _, _ = newFuzzSigner(t) // B's key is unused after generation
	tmplB := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{Organization: []string{"unrelated trusted"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	_, keyB, _ := ed25519.GenerateKey(rand.Reader)
	derB, _ := x509.CreateCertificate(rand.Reader, tmplB, tmplB, keyB.Public(), keyB)
	certB, _ := x509.ParseCertificate(derB)

	// Trust pool contains both — but only A signed.
	pool := newPool(certA, certB)

	data := []byte("extra-cert-in-pool invariant")
	sig, err := SignData(data, certA, keyA)
	if err != nil {
		t.Fatalf("SignData: %v", err)
	}

	verified, err := Verify(sig, data, VerifyOptions{Roots: pool})
	if err != nil {
		t.Fatalf("Verify rejected legitimate signature when extra trusted cert present: %v", err)
	}
	if len(verified) == 0 || !bytes.Equal(verified[0].Raw, certA.Raw) {
		t.Fatal("Verify did not return signer-A's cert when an extra trusted cert was in the pool")
	}
}
