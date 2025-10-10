package cms

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

// TestCase2RoundTrip tests the complete Case 2 implementation (signer and verifier)
func TestCase2RoundTrip(t *testing.T) {
	// Create test certificate and key
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Case 2 Round Trip Test"},
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

	testData := []byte("Test data for Case 2 round-trip verification")

	// Sign using the new Case 2 function
	signature, err := SignDataWithoutAttributes(testData, cert, privateKey)
	if err != nil {
		t.Fatalf("Failed to sign data without attributes: %v", err)
	}

	// Parse signature to verify it has no signed attributes
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

	// Verify no signed attributes are present
	if len(si.SignedAttrs.FullBytes) != 0 {
		t.Errorf("Expected no signed attributes, but found %d bytes", len(si.SignedAttrs.FullBytes))
	}

	// Create root pool
	rootPool := x509.NewCertPool()
	rootPool.AddCert(cert) // Self-signed

	// Verify the Case 2 signature
	verifiedCert, err := Verify(signature, testData, VerifyOptions{
		Roots: rootPool,
	})
	if err != nil {
		t.Fatalf("Failed to verify Case 2 signature: %v", err)
	}

	// Check that we got the right certificate back
	if !bytes.Equal(verifiedCert[0].Raw, cert.Raw) {
		t.Error("Verified certificate does not match signer certificate")
	}

	t.Log("✓ Case 2 round-trip successful: sign without attributes -> verify")
}

// TestCase2VsCase1Comparison compares Case 1 and Case 2 signatures
func TestCase2VsCase1Comparison(t *testing.T) {
	// Create test certificate and key
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Case Comparison Test"},
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate,
		privateKey.Public(), privateKey)
	cert, _ := x509.ParseCertificate(certDER)

	testData := []byte("Comparison test data")

	// Create Case 1 signature (with attributes)
	case1Sig, err := SignData(testData, cert, privateKey)
	if err != nil {
		t.Fatalf("Failed to create Case 1 signature: %v", err)
	}

	// Create Case 2 signature (without attributes)
	case2Sig, err := SignDataWithoutAttributes(testData, cert, privateKey)
	if err != nil {
		t.Fatalf("Failed to create Case 2 signature: %v", err)
	}

	// Compare sizes
	t.Logf("Case 1 size (with attributes): %d bytes", len(case1Sig))
	t.Logf("Case 2 size (without attributes): %d bytes", len(case2Sig))
	t.Logf("Size reduction: %d bytes (%.1f%%)",
		len(case1Sig)-len(case2Sig),
		float64(len(case1Sig)-len(case2Sig))/float64(len(case1Sig))*100)

	// Both should verify successfully
	rootPool := x509.NewCertPool()
	rootPool.AddCert(cert)
	opts := VerifyOptions{Roots: rootPool}

	if _, err := Verify(case1Sig, testData, opts); err != nil {
		t.Errorf("Case 1 verification failed: %v", err)
	} else {
		t.Log("✓ Case 1 (with attributes) verified successfully")
	}

	if _, err := Verify(case2Sig, testData, opts); err != nil {
		t.Errorf("Case 2 verification failed: %v", err)
	} else {
		t.Log("✓ Case 2 (without attributes) verified successfully")
	}
}

// TestCase2InvalidData tests that Case 2 signatures properly fail with wrong data
func TestCase2InvalidData(t *testing.T) {
	// Create test certificate and key
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Invalid Data Test"},
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate,
		privateKey.Public(), privateKey)
	cert, _ := x509.ParseCertificate(certDER)

	originalData := []byte("Original data")
	tamperedData := []byte("Tampered data")

	// Sign original data
	signature, err := SignDataWithoutAttributes(originalData, cert, privateKey)
	if err != nil {
		t.Fatalf("Failed to sign data: %v", err)
	}

	// Try to verify with tampered data
	rootPool := x509.NewCertPool()
	rootPool.AddCert(cert)

	_, err = Verify(signature, tamperedData, VerifyOptions{
		Roots: rootPool,
	})

	if err == nil {
		t.Fatal("Verification should have failed with tampered data")
	}

	// Check for signature error
	var sigErr *SignatureError
	if !asError(err, &sigErr) {
		t.Errorf("Expected SignatureError, got %T", err)
	} else {
		t.Log("✓ Correctly rejected tampered data with SignatureError")
	}
}
