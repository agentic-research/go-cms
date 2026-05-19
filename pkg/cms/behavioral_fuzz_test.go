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

const fuzzMaxInputSize = 1 << 20 // 1 MiB per input

// newFuzzSigner builds an ephemeral self-signed Ed25519 certificate and a
// trust pool for the behavioral fuzzers. The cert is built once per fuzz
// function and reused across iterations, isolating the fuzzer to data
// variation only.
func newFuzzSigner(tb testing.TB) (*x509.Certificate, ed25519.PrivateKey, *x509.CertPool) {
	tb.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		tb.Fatalf("ed25519.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{Organization: []string{"go-cms behavioral fuzz"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	if err != nil {
		tb.Fatalf("x509.CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		tb.Fatalf("x509.ParseCertificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return cert, priv, pool
}

// newPool builds a CertPool containing the given certs. Helper for fuzzers
// that need to express different trust topologies.
func newPool(certs ...*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, c := range certs {
		pool.AddCert(c)
	}
	return pool
}

// FuzzSignVerifyRoundtrip asserts the behavioral contract of the primary
// signing entry point (SignData / Case 1, with signed attributes):
//
//   - For any input, signing then verifying must succeed.
//   - Verifying with tampered detached data must fail.
//   - Tampering any byte of the signature blob must cause verification to fail.
//
// This is the load-bearing behavioral fuzzer: bugs in SignedAttributes
// encoding, digest computation, or signature placement would surface here
// even when unit-test happy paths still pass.
func FuzzSignVerifyRoundtrip(f *testing.F) {
	f.Add([]byte(""), uint(0))
	f.Add([]byte("a"), uint(0))
	f.Add([]byte("Hello, CMS!"), uint(7))
	f.Add(bytes.Repeat([]byte{0xff}, 1024), uint(500))
	f.Add([]byte{0x00, 0x01, 0x02, 0x03}, uint(2))
	f.Add([]byte{0x30, 0x82, 0x01, 0x00}, uint(0)) // ASN.1-shaped data

	cert, priv, pool := newFuzzSigner(f)
	opts := VerifyOptions{Roots: pool}

	f.Fuzz(func(t *testing.T, data []byte, tamperIdx uint) {
		if len(data) > fuzzMaxInputSize {
			t.Skip("oversize input")
		}

		sig, err := SignData(data, cert, priv)
		if err != nil {
			t.Fatalf("SignData failed for %d-byte input: %v", len(data), err)
		}

		if _, err := Verify(sig, data, opts); err != nil {
			t.Fatalf("Verify rejected its own roundtrip output (%d-byte input): %v", len(data), err)
		}

		// Tampering the detached data must always be rejected (when there's
		// data to tamper).
		if len(data) > 0 {
			td := append([]byte(nil), data...)
			td[tamperIdx%uint(len(data))] ^= 0x80
			if !bytes.Equal(td, data) {
				if _, err := Verify(sig, td, opts); err == nil {
					t.Fatalf("Verify accepted tampered data: original=%x tampered=%x", data, td)
				}
			}
		}

		// Tampering any byte of the signature blob must also be rejected.
		ts := append([]byte(nil), sig...)
		ts[tamperIdx%uint(len(ts))] ^= 0x80
		if _, err := Verify(ts, data, opts); err == nil {
			t.Fatalf("Verify accepted tampered signature blob (flipped byte %d)", tamperIdx%uint(len(ts)))
		}
	})
}

// FuzzSignDataWithoutAttributesRoundtrip exercises the Case 2 path
// (RFC 5652 §5.4 case 2: SignerInfo with no signedAttrs). The signature is
// computed directly over the content rather than over a DER-encoded
// SignedAttributes set — a distinct code path with its own bug surface.
// This fuzzer would have caught the Case 2 verifier bug fixed in PR #9.
func FuzzSignDataWithoutAttributesRoundtrip(f *testing.F) {
	f.Add([]byte(""), uint(0))
	f.Add([]byte("a"), uint(0))
	f.Add(bytes.Repeat([]byte{0xff}, 1024), uint(0))
	f.Add([]byte{0x00, 0x01, 0x02, 0x03}, uint(1))

	cert, priv, pool := newFuzzSigner(f)
	opts := VerifyOptions{Roots: pool}

	f.Fuzz(func(t *testing.T, data []byte, tamperIdx uint) {
		if len(data) > fuzzMaxInputSize {
			t.Skip("oversize input")
		}

		sig, err := SignDataWithoutAttributes(data, cert, priv)
		if err != nil {
			t.Fatalf("SignDataWithoutAttributes failed: %v", err)
		}

		if _, err := Verify(sig, data, opts); err != nil {
			t.Fatalf("Verify rejected Case 2 roundtrip output: %v", err)
		}

		if len(data) > 0 {
			td := append([]byte(nil), data...)
			td[tamperIdx%uint(len(data))] ^= 0x80
			if !bytes.Equal(td, data) {
				if _, err := Verify(sig, td, opts); err == nil {
					t.Fatalf("Case 2 Verify accepted tampered data")
				}
			}
		}

		ts := append([]byte(nil), sig...)
		ts[tamperIdx%uint(len(ts))] ^= 0x80
		if _, err := Verify(ts, data, opts); err == nil {
			t.Fatalf("Case 2 Verify accepted tampered signature blob")
		}
	})
}

// FuzzSignDataWithSignerRoundtrip exercises the crypto.Signer abstraction
// added in PR #6 (SignDataWithSigner). The contract: any bug introduced by
// the abstraction layer that diverges from the direct SignData path would
// surface as either a sign failure, verify failure, or — worst case —
// silent acceptance of mismatched data. ed25519.PrivateKey satisfies
// crypto.Signer natively.
func FuzzSignDataWithSignerRoundtrip(f *testing.F) {
	f.Add([]byte(""), uint(0))
	f.Add([]byte("a"), uint(0))
	f.Add(bytes.Repeat([]byte{0xff}, 1024), uint(0))

	cert, priv, pool := newFuzzSigner(f)
	opts := VerifyOptions{Roots: pool}

	f.Fuzz(func(t *testing.T, data []byte, tamperIdx uint) {
		if len(data) > fuzzMaxInputSize {
			t.Skip("oversize input")
		}

		sig, err := SignDataWithSigner(data, cert, priv)
		if err != nil {
			t.Fatalf("SignDataWithSigner failed: %v", err)
		}

		if _, err := Verify(sig, data, opts); err != nil {
			t.Fatalf("Verify rejected crypto.Signer roundtrip output: %v", err)
		}

		if len(data) > 0 {
			td := append([]byte(nil), data...)
			td[tamperIdx%uint(len(data))] ^= 0x80
			if !bytes.Equal(td, data) {
				if _, err := Verify(sig, td, opts); err == nil {
					t.Fatalf("crypto.Signer Verify accepted tampered data")
				}
			}
		}
	})
}

// FuzzCase2SignDeterminism asserts that for the Case 2 path (no signed
// attributes) the full CMS output is byte-identical across repeated calls
// with the same data + key. Ed25519 is a deterministic signature scheme;
// any non-determinism here would imply RNG leaking into the CMS encoder,
// which is both a malleability concern (multiple distinct valid signatures
// for the same input) and a potential side-channel.
//
// Case 1 (with signed attributes) is intentionally excluded because the
// signing-time attribute changes per call.
func FuzzCase2SignDeterminism(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("a"))
	f.Add([]byte("deterministic ed25519 over CMS"))
	f.Add(bytes.Repeat([]byte{0xab}, 256))

	cert, priv, _ := newFuzzSigner(f)

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > fuzzMaxInputSize {
			t.Skip("oversize input")
		}

		sig1, err := SignDataWithoutAttributes(data, cert, priv)
		if err != nil {
			t.Fatalf("SignDataWithoutAttributes #1 failed: %v", err)
		}
		sig2, err := SignDataWithoutAttributes(data, cert, priv)
		if err != nil {
			t.Fatalf("SignDataWithoutAttributes #2 failed: %v", err)
		}
		if !bytes.Equal(sig1, sig2) {
			t.Fatalf("Case 2 non-deterministic for same data+key (len=%d):\n  sig1=%x\n  sig2=%x",
				len(data), sig1, sig2)
		}
	})
}
