package cms

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

// TestCase2VerifierBug demonstrates the bug in the verifier's Case 2 implementation.
// The verifier incorrectly passes SHA-512(data) to ed25519.Verify instead of raw data.
// Since ed25519.Verify internally computes SHA-512, this results in verifying:
// SHA-512(SHA-512(data)) instead of SHA-512(data), causing verification to fail.
func TestCase2VerifierBug(t *testing.T) {
	// Create a self-signed certificate for testing
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Case 2"},
			CommonName:   "case2@test.example",
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate,
		privateKey.Public(), privateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}
	cert, _ := x509.ParseCertificate(certDER)

	// Test data
	testData := []byte("Test data for Case 2 - signing without signed attributes")

	// === CORRECT CASE 2 IMPLEMENTATION ===
	// For Ed25519 (PureEdDSA), sign the raw data directly
	correctSignature := ed25519.Sign(privateKey, testData)

	// === INCORRECT IMPLEMENTATION (what a buggy signer might do) ===
	// Pre-hash the data before signing (double-hashing bug)
	hashedData := sha512.Sum512(testData)
	incorrectSignature := ed25519.Sign(privateKey, hashedData[:])

	// Now test both signatures with manual CMS construction

	t.Run("CorrectCase2Signature", func(t *testing.T) {
		// Build CMS with the CORRECT signature (raw data signed)
		cmsBytes := buildCase2CMS(t, cert, correctSignature, oidSHA512)

		// Create root pool
		rootPool := x509.NewCertPool()
		rootPool.AddCert(cert) // Self-signed

		// This SHOULD succeed with a correct verifier
		// But will FAIL with the current buggy verifier
		_, err := Verify(cmsBytes, testData, VerifyOptions{
			Roots: rootPool,
		})

		// Expected: This should succeed, but due to the verifier bug it will fail
		if err == nil {
			t.Log("✓ Verifier correctly handled Case 2 (raw data signature)")
		} else {
			t.Errorf("✗ VERIFIER BUG CONFIRMED: Failed to verify correct Case 2 signature: %v", err)
			t.Log("The verifier is incorrectly passing SHA-512(data) to ed25519.Verify")
			t.Log("instead of raw data, causing double-hashing")
		}
	})

	t.Run("IncorrectCase2Signature_MatchesCurrentBuggyVerifier", func(t *testing.T) {
		// Build CMS with the INCORRECT signature (pre-hashed data)
		cmsBytes := buildCase2CMS(t, cert, incorrectSignature, oidSHA512)

		// Create root pool
		rootPool := x509.NewCertPool()
		rootPool.AddCert(cert)

		// This SHOULD fail with a correct verifier
		// But might SUCCEED with the current buggy verifier
		_, err := Verify(cmsBytes, testData, VerifyOptions{
			Roots: rootPool,
		})

		if err != nil {
			t.Log("✓ Correctly rejected incorrect Case 2 signature (pre-hashed)")
		} else {
			t.Error("✗ VERIFIER BUG: Accepted an incorrect double-hashed signature!")
			t.Log("This means the verifier is doing: ed25519.Verify(key, SHA-512(data), sig)")
			t.Log("And the signature was created with: ed25519.Sign(key, SHA-512(data))")
		}
	})
}

// TestCase2SignerMissing demonstrates that the signer doesn't support Case 2.
// The signer ALWAYS creates signed attributes, never allowing direct signing.
func TestCase2SignerMissing(t *testing.T) {
	// Create test certificate and key
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Signer"},
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate,
		privateKey.Public(), privateKey)
	cert, _ := x509.ParseCertificate(certDER)

	testData := []byte("Test data")

	// Sign with the current implementation
	signature, err := SignData(testData, cert, privateKey)
	if err != nil {
		t.Fatalf("Failed to sign data: %v", err)
	}

	// Parse the signature to check for signed attributes
	var ci contentInfo
	rest, err := asn1.Unmarshal(signature, &ci)
	if err != nil || len(rest) > 0 {
		t.Fatalf("Failed to parse ContentInfo: %v", err)
	}

	var sd signedData
	rest, err = asn1.Unmarshal(ci.Content.Bytes, &sd)
	if err != nil || len(rest) > 0 {
		t.Fatalf("Failed to parse SignedData: %v", err)
	}

	if len(sd.SignerInfos) != 1 {
		t.Fatalf("Expected 1 SignerInfo, got %d", len(sd.SignerInfos))
	}

	si := sd.SignerInfos[0]

	// Check if signed attributes are present
	if len(si.SignedAttrs.FullBytes) == 0 {
		t.Error("SignedAttrs are absent - Case 2 is supported")
	} else {
		t.Log("✓ Confirmed: Signer always creates signed attributes (Case 1 only)")
		t.Log("✗ Case 2 (direct signing without attributes) is NOT supported")

		// Verify the attributes are properly formatted
		if si.SignedAttrs.FullBytes[0] != 0xA0 {
			t.Errorf("SignedAttrs should start with IMPLICIT [0] tag (0xA0), got 0x%02X",
				si.SignedAttrs.FullBytes[0])
		}
	}
}

// TestCase2WithDifferentHashAlgorithms tests Case 2 with various hash algorithms.
// This demonstrates that the bug affects all hash algorithms, not just SHA-512.
func TestCase2WithDifferentHashAlgorithms(t *testing.T) {
	// Create test certificate
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Hash Algorithm Test"},
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate,
		privateKey.Public(), privateKey)
	cert, _ := x509.ParseCertificate(certDER)

	testData := []byte("Test data for different hash algorithms")

	tests := []struct {
		name        string
		digestOID   asn1.ObjectIdentifier
		hashFunc    func([]byte) []byte
		description string
	}{
		{
			name:      "SHA-256",
			digestOID: oidSHA256,
			hashFunc: func(data []byte) []byte {
				h := sha256.Sum256(data)
				return h[:]
			},
			description: "Most common, recommended for Ed25519 CMS compatibility",
		},
		{
			name:      "SHA-512",
			digestOID: oidSHA512,
			hashFunc: func(data []byte) []byte {
				h := sha512.Sum512(data)
				return h[:]
			},
			description: "RFC 8419 recommendation, but causes issues with some implementations",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// For PureEdDSA, always sign the raw data
			// The digest algorithm in CMS is only for the message-digest attribute
			signature := ed25519.Sign(privateKey, testData)

			// Build Case 2 CMS with specified digest algorithm
			cmsBytes := buildCase2CMS(t, cert, signature, tc.digestOID)

			// Create root pool
			rootPool := x509.NewCertPool()
			rootPool.AddCert(cert)

			// Try to verify
			_, err := Verify(cmsBytes, testData, VerifyOptions{
				Roots: rootPool,
			})

			if err == nil {
				t.Logf("✓ Verification succeeded with %s (%s)", tc.name, tc.description)
			} else {
				t.Errorf("✗ Verification failed with %s: %v", tc.name, err)
				t.Logf("  This confirms the Case 2 bug affects %s", tc.name)
			}
		})
	}
}

// TestCase2RoundTripAfterFix is a test that will pass once both signer and verifier are fixed.
// Currently it's expected to fail.
func TestCase2RoundTripAfterFix(t *testing.T) {
	t.Skip("Skipping until Case 2 support is implemented in both signer and verifier")

	// This test demonstrates what SHOULD work after the fix
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Fixed Implementation Test"},
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate,
		privateKey.Public(), privateKey)
	cert, _ := x509.ParseCertificate(certDER)

	testData := []byte("Test data for round-trip after fix")

	// After fix: SignDataWithoutAttributes would be a new function
	// that creates Case 2 signatures (without signed attributes)
	// signature, err := SignDataWithoutAttributes(testData, cert, privateKey)

	// For now, manually create the correct Case 2 signature
	correctSignature := ed25519.Sign(privateKey, testData)
	cmsBytes := buildCase2CMS(t, cert, correctSignature, oidSHA256)

	// Verify
	rootPool := x509.NewCertPool()
	rootPool.AddCert(cert)

	verifiedCert, err := Verify(cmsBytes, testData, VerifyOptions{
		Roots: rootPool,
	})

	if err != nil {
		t.Fatalf("Verification failed after fix: %v", err)
	}

	if !bytes.Equal(verifiedCert[0].Raw, cert.Raw) {
		t.Error("Verified certificate doesn't match signer certificate")
	}

	t.Log("✓ Case 2 round-trip successful (after fix)")
}

// buildCase2CMS is a helper function to manually construct a Case 2 CMS structure
// (SignedData without SignedAttributes)
func buildCase2CMS(t *testing.T, cert *x509.Certificate, signature []byte, digestOID asn1.ObjectIdentifier) []byte {
	// Build SignerInfo WITHOUT SignedAttrs
	sidBytes, err := asn1.Marshal(issuerAndSerialNumber{
		Issuer:       cert.Issuer.ToRDNSequence(),
		SerialNumber: cert.SerialNumber,
	})
	if err != nil {
		t.Fatalf("Failed to marshal SID: %v", err)
	}
	var sidRaw asn1.RawValue
	_, _ = asn1.Unmarshal(sidBytes, &sidRaw)

	si := signerInfo{
		Version:         1,
		SID:             sidRaw,
		DigestAlgorithm: pkix.AlgorithmIdentifier{Algorithm: digestOID},
		// SignedAttrs is intentionally omitted (Case 2)
		SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidEd25519},
		Signature:          signature,
	}

	// Build SignedData
	sd := signedData{
		Version:          1,
		DigestAlgorithms: []pkix.AlgorithmIdentifier{{Algorithm: digestOID}},
		EncapContentInfo: encapsulatedContentInfo{
			ContentType: oidData,
			// Content omitted for detached signature
		},
		SignerInfos: []signerInfo{si},
	}

	// Add certificate using IMPLICIT [0] tag
	certHeader := []byte{0xA0} // IMPLICIT [0] tag
	if len(cert.Raw) < 128 {
		certHeader = append(certHeader, byte(len(cert.Raw)))
	} else if len(cert.Raw) < 256 {
		certHeader = append(certHeader, 0x81, byte(len(cert.Raw)))
	} else {
		certHeader = append(certHeader, 0x82, byte(len(cert.Raw)>>8), byte(len(cert.Raw)))
	}
	sd.Certificates = asn1.RawValue{
		FullBytes: append(certHeader, cert.Raw...),
	}

	// Marshal SignedData
	signedDataBytes, err := asn1.Marshal(sd)
	if err != nil {
		t.Fatalf("Failed to marshal SignedData: %v", err)
	}

	// Build ContentInfo
	ci := contentInfo{
		ContentType: oidSignedData,
		Content: asn1.RawValue{
			Class:      2,
			Tag:        0,
			IsCompound: true,
			Bytes:      signedDataBytes,
		},
	}

	// Marshal complete CMS
	cmsBytes, err := asn1.Marshal(ci)
	if err != nil {
		t.Fatalf("Failed to marshal ContentInfo: %v", err)
	}

	return cmsBytes
}

// TestCase2ManualVerification demonstrates what SHOULD happen in Case 2
// by manually performing the correct verification steps
func TestCase2ManualVerification(t *testing.T) {
	// Create test certificate and key
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)

	testData := []byte("Manual verification test data")

	// === CORRECT CASE 2: Sign raw data ===
	correctSignature := ed25519.Sign(privateKey, testData)

	// Manual verification (what the verifier SHOULD do)
	t.Run("ManualCorrectVerification", func(t *testing.T) {
		// For Case 2 without signed attributes:
		// Pass raw data to ed25519.Verify (which will hash internally)
		valid := ed25519.Verify(publicKey, testData, correctSignature)
		if !valid {
			t.Fatal("Manual verification failed - this should never happen")
		}
		t.Log("✓ Manual verification succeeded with raw data")
	})

	// What the buggy verifier is doing
	t.Run("BuggyVerifierSimulation", func(t *testing.T) {
		// Buggy: Pre-hash the data
		hashedData := sha512.Sum512(testData)

		// Then pass the hash to ed25519.Verify (causing double-hashing)
		valid := ed25519.Verify(publicKey, hashedData[:], correctSignature)
		if valid {
			t.Error("Buggy verification succeeded - this shouldn't happen")
		} else {
			t.Log("✓ Confirmed: Pre-hashing causes verification failure")
			t.Log("  The verifier is doing: ed25519.Verify(key, SHA-512(data), sig)")
			t.Log("  But it should do: ed25519.Verify(key, data, sig)")
		}
	})
}
