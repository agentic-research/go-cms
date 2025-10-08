package cms

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// TestSignDataWithSHA512 tests signing with SHA-512 digest algorithm
func TestSignDataWithSHA512(t *testing.T) {
	_, privKey, _ := ed25519.GenerateKey(rand.Reader)
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test Signer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, cert, cert, privKey.Public(), privKey)
	cert, _ = x509.ParseCertificate(certDER)

	data := []byte("test data")

	// Sign with SHA-512
	sig, err := SignDataWithOptions(data, cert, privKey, SignOptions{
		DigestAlgorithm: crypto.SHA512,
	})

	if err != nil {
		t.Fatalf("Failed to sign with SHA-512: %v", err)
	}

	// Verify the signature
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	_, err = Verify(sig, data, VerifyOptions{Roots: roots})
	if err != nil {
		t.Errorf("Failed to verify SHA-512 signature: %v", err)
	}
}

// TestSignDataWithSHA384 tests signing with SHA-384 digest algorithm
func TestSignDataWithSHA384(t *testing.T) {
	_, privKey, _ := ed25519.GenerateKey(rand.Reader)
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test Signer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, cert, cert, privKey.Public(), privKey)
	cert, _ = x509.ParseCertificate(certDER)

	data := []byte("test data")

	// Sign with SHA-384
	sig, err := SignDataWithOptions(data, cert, privKey, SignOptions{
		DigestAlgorithm: crypto.SHA384,
	})

	if err != nil {
		t.Fatalf("Failed to sign with SHA-384: %v", err)
	}

	// Verify the signature
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	_, err = Verify(sig, data, VerifyOptions{Roots: roots})
	if err != nil {
		t.Errorf("Failed to verify SHA-384 signature: %v", err)
	}
}

// TestSignDataRejectMismatchedKeys tests that mismatched private key is rejected
func TestSignDataRejectMismatchedKeys(t *testing.T) {
	_, privKey1, _ := ed25519.GenerateKey(rand.Reader)
	_, privKey2, _ := ed25519.GenerateKey(rand.Reader) // Different key

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test Signer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, cert, cert, privKey1.Public(), privKey1)
	cert, _ = x509.ParseCertificate(certDER)

	data := []byte("test data")

	// Try to sign with wrong private key
	_, err := SignData(data, cert, privKey2)
	if err == nil {
		t.Fatal("Expected error for mismatched private key, got nil")
	}

	if _, ok := err.(*KeyError); !ok {
		t.Errorf("Expected KeyError, got: %T", err)
	}
}

// TestSignDataRejectMissingDigitalSignatureKeyUsage tests KeyUsage validation
func TestSignDataRejectMissingDigitalSignatureKeyUsage(t *testing.T) {
	_, privKey, _ := ed25519.GenerateKey(rand.Reader)

	// Create cert WITHOUT DigitalSignature KeyUsage
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test Signer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment, // Wrong usage
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, cert, cert, privKey.Public(), privKey)
	cert, _ = x509.ParseCertificate(certDER)

	data := []byte("test data")

	_, err := SignData(data, cert, privKey)
	if err == nil {
		t.Fatal("Expected error for missing DigitalSignature KeyUsage, got nil")
	}

	if _, ok := err.(*ValidationError); !ok {
		t.Errorf("Expected ValidationError, got: %T", err)
	}
}

// TestSignDataWithIntermediateCerts tests chain inclusion
func TestSignDataWithIntermediateCerts(t *testing.T) {
	// Create intermediate CA
	_, intermediateKey, _ := ed25519.GenerateKey(rand.Reader)
	intermediateCert := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Intermediate CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	intermediateDER, _ := x509.CreateCertificate(rand.Reader, intermediateCert, intermediateCert,
		intermediateKey.Public(), intermediateKey)
	intermediateCert, _ = x509.ParseCertificate(intermediateDER)

	// Create end-entity cert
	_, privKey, _ := ed25519.GenerateKey(rand.Reader)
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test Signer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, cert, cert, privKey.Public(), privKey)
	cert, _ = x509.ParseCertificate(certDER)

	data := []byte("test data")

	// Sign with intermediate cert included
	sig, err := SignDataWithOptions(data, cert, privKey, SignOptions{
		IntermediateCerts: []*x509.Certificate{intermediateCert},
	})

	if err != nil {
		t.Fatalf("Failed to sign with intermediate certs: %v", err)
	}

	// Parse and verify the CMS contains both certificates
	// (This is a basic check - full verification would need proper chain)
	if len(sig) < 500 { // Should be larger with 2 certs
		t.Error("CMS signature unexpectedly small - intermediate cert may not be included")
	}
}
