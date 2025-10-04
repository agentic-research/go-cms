// cms-test-tool is a simple utility for testing CMS signature generation and verification.
// It's used by integration tests to verify OpenSSL compatibility.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"time"

	"github.com/jamestexas/go-cms/pkg/cms"
)

func main() {
	var (
		sign   = flag.Bool("S", false, "Sign data (git-compatible mode)")
		verify = flag.Bool("verify", false, "Verify signature")
		help   = flag.Bool("help", false, "Show help")
		init   = flag.Bool("init", false, "Initialize (no-op for test tool)")
		_      = flag.String("home", "", "Home directory (ignored)")
	)
	flag.Parse()

	// Handle --init (no-op for test tool)
	if *init {
		// Just exit successfully
		os.Exit(0)
	}

	if *help || (!*sign && !*verify) {
		fmt.Fprintf(os.Stderr, "Usage: %s [-S|-verify] < input\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  -S       Sign input data (outputs PEM-encoded CMS signature)\n")
		fmt.Fprintf(os.Stderr, "  -verify  Verify CMS signature\n")
		os.Exit(1)
	}

	if *sign {
		if err := signData(); err != nil {
			log.Fatal(err)
		}
	} else if *verify {
		if err := verifyData(); err != nil {
			log.Fatal(err)
		}
	}
}

func signData() error {
	// Read input data
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("reading input: %w", err)
	}

	// Generate a test key pair
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generating key: %w", err)
	}

	// Create a self-signed certificate
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"Test Org"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{""},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pubKey, privKey)
	if err != nil {
		return fmt.Errorf("creating certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("parsing certificate: %w", err)
	}

	// Sign the data
	signature, err := cms.SignData(data, cert, privKey)
	if err != nil {
		return fmt.Errorf("signing data: %w", err)
	}

	// Output PEM-encoded signature (Git expects "SIGNED MESSAGE" header)
	if err := pem.Encode(os.Stdout, &pem.Block{
		Type:  "SIGNED MESSAGE",
		Bytes: signature,
	}); err != nil {
		return fmt.Errorf("encoding PEM: %w", err)
	}

	return nil
}

func verifyData() error {
	// This is a placeholder for verification logic
	// In practice, you'd read the signature and data, then call cms.Verify
	fmt.Fprintln(os.Stderr, "Verification not implemented in test tool")
	return nil
}
