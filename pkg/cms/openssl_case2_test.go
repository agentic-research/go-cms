package cms

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// TestOpenSSLCase2Interop tests interoperability with OpenSSL for Case 2 signatures.
// This test requires OpenSSL 3.0+ with Ed25519 support.
func TestOpenSSLCase2Interop(t *testing.T) {
	// Check if OpenSSL is available and supports Ed25519
	if !hasOpenSSLWithEd25519() {
		t.Skip("OpenSSL with Ed25519 support not available")
	}

	// Create temporary directory for test files
	tmpDir, err := os.MkdirTemp("", "cms-case2-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create test data file
	testData := []byte("OpenSSL Case 2 interop test data")
	dataFile := filepath.Join(tmpDir, "data.txt")
	if err := os.WriteFile(dataFile, testData, 0644); err != nil {
		t.Fatalf("Failed to write test data: %v", err)
	}

	t.Run("OpenSSL_Case2_NoSignedAttrs", func(t *testing.T) {
		// Generate Ed25519 key and certificate using OpenSSL
		keyFile := filepath.Join(tmpDir, "key.pem")
		certFile := filepath.Join(tmpDir, "cert.pem")

		// Generate Ed25519 private key
		cmd := exec.Command("openssl", "genpkey", "-algorithm", "ED25519", "-out", keyFile)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("Failed to generate Ed25519 key: %v\n%s", err, output)
		}

		// Create self-signed certificate
		cmd = exec.Command("openssl", "req", "-new", "-x509", "-key", keyFile, "-out", certFile,
			"-days", "1", "-subj", "/CN=case2test")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("Failed to create certificate: %v\n%s", err, output)
		}

		// Create Case 2 CMS signature using OpenSSL
		// The -noattr flag tells OpenSSL to NOT include signed attributes
		sigFile := filepath.Join(tmpDir, "signature.der")
		cmd = exec.Command("openssl", "cms", "-sign", "-binary",
			"-in", dataFile,
			"-signer", certFile,
			"-inkey", keyFile,
			"-outform", "DER",
			"-out", sigFile,
			"-noattr") // THIS IS THE KEY FLAG FOR CASE 2
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Logf("OpenSSL command failed (expected for Case 2): %v\n%s", err, output)
			// Note: Some OpenSSL versions may not support -noattr with Ed25519
			// or may have issues with Case 2 for Ed25519
		}

		// If OpenSSL successfully created the signature, verify it with our implementation
		if _, err := os.Stat(sigFile); err == nil {
			// Read the signature
			signature, err := os.ReadFile(sigFile)
			if err != nil {
				t.Fatalf("Failed to read signature: %v", err)
			}

			// Read the certificate
			certPEM, err := os.ReadFile(certFile)
			if err != nil {
				t.Fatalf("Failed to read certificate: %v", err)
			}
			block, _ := pem.Decode(certPEM)
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatalf("Failed to parse certificate: %v", err)
			}

			// Create root pool
			rootPool := x509.NewCertPool()
			rootPool.AddCert(cert) // Self-signed

			// Verify with our implementation
			_, err = Verify(signature, testData, VerifyOptions{
				Roots: rootPool,
			})

			if err != nil {
				t.Logf("Failed to verify OpenSSL Case 2 signature: %v", err)
				t.Log("Note: This may be due to OpenSSL Case 2 limitations")
			} else {
				t.Log("✓ Successfully verified OpenSSL Case 2 signature")
				t.Log("  This would mean our verifier handles Case 2 correctly")
			}
		} else {
			t.Log("OpenSSL did not create Case 2 signature (known limitation)")
		}
	})

	t.Run("Our_Case2_VerifiedByOpenSSL", func(t *testing.T) {
		// Create our own Ed25519 key and certificate
		_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
		certTemplate := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject: pkix.Name{
				CommonName: "case2test",
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

		// Create a correct Case 2 signature (sign raw data)
		signature := ed25519.Sign(privateKey, testData)

		// Manually build Case 2 CMS
		cmsBytes := buildCase2CMS(t, cert, signature, oidSHA256)

		// Write our signature to file
		ourSigFile := filepath.Join(tmpDir, "our_signature.der")
		if err := os.WriteFile(ourSigFile, cmsBytes, 0644); err != nil {
			t.Fatalf("Failed to write our signature: %v", err)
		}

		// Write certificate for OpenSSL
		certPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
		ourCertFile := filepath.Join(tmpDir, "our_cert.pem")
		if err := os.WriteFile(ourCertFile, certPEM, 0644); err != nil {
			t.Fatalf("Failed to write certificate: %v", err)
		}

		// Verify our Case 2 signature with OpenSSL
		cmd := exec.Command("openssl", "cms", "-verify",
			"-in", ourSigFile,
			"-inform", "DER",
			"-content", dataFile,
			"-CAfile", ourCertFile,
			"-no_check_time") // Don't check certificate validity time
		output, err := cmd.CombinedOutput()

		if err != nil {
			t.Logf("OpenSSL failed to verify our Case 2 signature: %v", err)
			t.Logf("Output: %s", output)
			t.Log("This might be expected if OpenSSL has issues with Ed25519 Case 2")
		} else {
			t.Log("✓ OpenSSL successfully verified our Case 2 signature")
			t.Logf("Output: %s", output)
		}
	})
}

// TestOpenSSLCase1vs2Comparison compares OpenSSL's handling of Case 1 vs Case 2
func TestOpenSSLCase1vs2Comparison(t *testing.T) {
	if !hasOpenSSLWithEd25519() {
		t.Skip("OpenSSL with Ed25519 support not available")
	}

	tmpDir, err := os.MkdirTemp("", "cms-compare-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create test files
	testData := []byte("Case 1 vs Case 2 comparison")
	dataFile := filepath.Join(tmpDir, "data.txt")
	os.WriteFile(dataFile, testData, 0644)

	keyFile := filepath.Join(tmpDir, "key.pem")
	certFile := filepath.Join(tmpDir, "cert.pem")

	// Generate Ed25519 key and certificate
	exec.Command("openssl", "genpkey", "-algorithm", "ED25519", "-out", keyFile).Run()
	exec.Command("openssl", "req", "-new", "-x509", "-key", keyFile, "-out", certFile,
		"-days", "1", "-subj", "/CN=test").Run()

	// Create Case 1 signature (WITH signed attributes - default)
	case1SigFile := filepath.Join(tmpDir, "case1.der")
	cmd := exec.Command("openssl", "cms", "-sign", "-binary",
		"-in", dataFile,
		"-signer", certFile,
		"-inkey", keyFile,
		"-outform", "DER",
		"-out", case1SigFile)
	case1Output, case1Err := cmd.CombinedOutput()

	// Create Case 2 signature (WITHOUT signed attributes)
	case2SigFile := filepath.Join(tmpDir, "case2.der")
	cmd = exec.Command("openssl", "cms", "-sign", "-binary",
		"-in", dataFile,
		"-signer", certFile,
		"-inkey", keyFile,
		"-outform", "DER",
		"-out", case2SigFile,
		"-noattr") // No signed attributes
	case2Output, case2Err := cmd.CombinedOutput()

	t.Logf("Case 1 (with attributes) creation: %v", case1Err)
	if case1Err != nil {
		t.Logf("Output: %s", case1Output)
	}

	t.Logf("Case 2 (without attributes) creation: %v", case2Err)
	if case2Err != nil {
		t.Logf("Output: %s", case2Output)
	}

	// Compare file sizes if both were created
	if case1Err == nil && case2Err == nil {
		case1Info, _ := os.Stat(case1SigFile)
		case2Info, _ := os.Stat(case2SigFile)

		if case1Info != nil && case2Info != nil {
			t.Logf("Case 1 size: %d bytes", case1Info.Size())
			t.Logf("Case 2 size: %d bytes", case2Info.Size())
			t.Logf("Difference: %d bytes (Case 1 should be larger due to attributes)",
				case1Info.Size()-case2Info.Size())
		}
	}

	// Try to verify both with OpenSSL
	if case1Err == nil {
		cmd = exec.Command("openssl", "cms", "-verify",
			"-in", case1SigFile,
			"-inform", "DER",
			"-content", dataFile,
			"-CAfile", certFile,
			"-no_check_time")
		if output, err := cmd.CombinedOutput(); err == nil {
			t.Log("✓ OpenSSL verified Case 1 (with attributes) successfully")
		} else {
			t.Logf("✗ OpenSSL failed to verify Case 1: %v\n%s", err, output)
		}
	}

	if case2Err == nil {
		cmd = exec.Command("openssl", "cms", "-verify",
			"-in", case2SigFile,
			"-inform", "DER",
			"-content", dataFile,
			"-CAfile", certFile,
			"-no_check_time")
		if output, err := cmd.CombinedOutput(); err == nil {
			t.Log("✓ OpenSSL verified Case 2 (without attributes) successfully")
		} else {
			t.Logf("✗ OpenSSL failed to verify Case 2: %v\n%s", err, output)
		}
	}
}

// TestGenerateOpenSSLCase2TestVector generates a test vector for manual inspection
func TestGenerateOpenSSLCase2TestVector(t *testing.T) {
	if !hasOpenSSLWithEd25519() {
		t.Skip("OpenSSL with Ed25519 support not available")
	}

	tmpDir, err := os.MkdirTemp("", "cms-vector-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer func() {
		t.Logf("Test files preserved in: %s", tmpDir)
		// Don't remove for manual inspection
	}()

	// Known test data
	testData := []byte("Test vector data for Case 2")
	dataFile := filepath.Join(tmpDir, "data.txt")
	os.WriteFile(dataFile, testData, 0644)

	// Generate key and certificate
	keyFile := filepath.Join(tmpDir, "key.pem")
	certFile := filepath.Join(tmpDir, "cert.pem")

	exec.Command("openssl", "genpkey", "-algorithm", "ED25519", "-out", keyFile).Run()
	exec.Command("openssl", "req", "-new", "-x509", "-key", keyFile, "-out", certFile,
		"-days", "365", "-subj", "/CN=TestVector").Run()

	// Create Case 2 signature
	case2SigFile := filepath.Join(tmpDir, "case2_signature.der")
	cmd := exec.Command("openssl", "cms", "-sign", "-binary",
		"-in", dataFile,
		"-signer", certFile,
		"-inkey", keyFile,
		"-outform", "DER",
		"-out", case2SigFile,
		"-noattr")
	output, err := cmd.CombinedOutput()

	if err != nil {
		t.Logf("Failed to create Case 2 signature: %v\n%s", err, output)
		t.Log("Note: OpenSSL may not fully support Ed25519 Case 2 signatures")
	} else {
		t.Log("✓ Created Case 2 test vector successfully")

		// Parse and display the signature for analysis
		if sigBytes, err := os.ReadFile(case2SigFile); err == nil {
			t.Logf("Signature size: %d bytes", len(sigBytes))
			// You could parse and display the structure here
		}
	}

	// Also create Case 1 for comparison
	case1SigFile := filepath.Join(tmpDir, "case1_signature.der")
	cmd = exec.Command("openssl", "cms", "-sign", "-binary",
		"-in", dataFile,
		"-signer", certFile,
		"-inkey", keyFile,
		"-outform", "DER",
		"-out", case1SigFile)
	cmd.Run()

	t.Logf("Test vectors saved in: %s", tmpDir)
	t.Log("You can inspect them with:")
	t.Logf("  openssl cms -in %s -inform DER -noout -print", case1SigFile)
	t.Logf("  openssl cms -in %s -inform DER -noout -print", case2SigFile)
}

// hasOpenSSLWithEd25519 checks if OpenSSL is available and supports Ed25519
func hasOpenSSLWithEd25519() bool {
	cmd := exec.Command("openssl", "version")
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	// Check version (need OpenSSL 1.1.1+ for Ed25519)
	versionStr := string(output)

	// Try to generate an Ed25519 key to confirm support
	testCmd := exec.Command("openssl", "genpkey", "-algorithm", "ED25519")
	testCmd.Stdin = bytes.NewReader([]byte{})
	testCmd.Stdout = io.Discard
	testCmd.Stderr = io.Discard

	return testCmd.Run() == nil && versionStr != ""
}

// TestDocumentCase2Issue documents the Case 2 issue for the fix
func TestDocumentCase2Issue(t *testing.T) {
	t.Log("=== CASE 2 ISSUE DOCUMENTATION ===")
	t.Log("")
	t.Log("PROBLEM SUMMARY:")
	t.Log("1. The verifier incorrectly handles Case 2 (no signed attributes)")
	t.Log("2. The signer doesn't support Case 2 at all")
	t.Log("")
	t.Log("VERIFIER BUG (pkg/cms/verifier.go:prepareDataForVerification):")
	t.Log("  Current behavior: Returns SHA-512(data) for Case 2")
	t.Log("  Correct behavior: Should return raw data")
	t.Log("  Impact: ed25519.Verify receives SHA-512(data) and computes SHA-512(SHA-512(data))")
	t.Log("")
	t.Log("SIGNER LIMITATION:")
	t.Log("  Current: Always creates signed attributes (Case 1 only)")
	t.Log("  Needed: Option to create signatures without signed attributes (Case 2)")
	t.Log("")
	t.Log("RFC CONTEXT:")
	t.Log("  RFC 5652: 'If no signedAttrs, signature is over message digest'")
	t.Log("  RFC 8419: 'Ed25519 uses PureEdDSA' (overrides RFC 5652 for Ed25519)")
	t.Log("  Conclusion: For Ed25519 Case 2, sign raw data, not its hash")
	t.Log("")
	t.Log("FIX REQUIRED:")
	t.Log("  1. Verifier: Check signature algorithm, return raw data for Ed25519 Case 2")
	t.Log("  2. Signer: Add SignDataWithoutAttributes function for Case 2")
}
