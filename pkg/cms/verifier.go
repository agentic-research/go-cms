// Package cms implements CMS/PKCS#7 signature verification with Ed25519 support.
//
// This package provides RFC 5652 compliant verification of CMS/PKCS#7 signatures
// using Ed25519 keys, which is unique among Go CMS implementations.
//
// # Security Considerations
//
// Memory Security: For memory security considerations when handling private keys
// in verification contexts (e.g., when using HSMs or secure enclaves for signing),
// see the signer package documentation.
//
// Example usage:
//
//	// Read CMS signature and data
//	cmsData, _ := os.ReadFile("signature.p7s")
//	originalData, _ := os.ReadFile("document.txt")
//
//	// Setup verification options
//	opts := cms.VerifyOptions{
//		Roots: systemRootPool, // Optional: uses system roots if nil
//	}
//
//	// Verify the signature
//	chain, err := cms.Verify(cmsData, originalData, opts)
//	if err != nil {
//		log.Fatal("Verification failed:", err)
//	}
//
//	// The first certificate is the signer
//	signerCert := chain[0]
//	fmt.Printf("Signed by: %s\n", signerCert.Subject)
package cms

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"

	"github.com/jamestexas/go-cms/pkg/cms/internal"
)

// ASN.1 tag constants for better readability
const (
	tagSequence         = 0x30 // SEQUENCE tag
	tagSet              = 0x31 // SET tag
	tagContextSpecific0 = 0xA0 // CONTEXT SPECIFIC [0] tag
	tagOctetString      = 0x04 // OCTET STRING tag
	tagInteger          = 0x02 // INTEGER tag
	tagBitString        = 0x03 // BIT STRING tag
	tagSetTag           = 17   // SET tag value (for compound check)
	asn1ClassContext    = 2    // Context-specific class
)

// Object Identifiers for weak algorithms that should be rejected
var (
	oidMD5  = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 5}
	oidSHA1 = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	// oidSHA512, oidAttributeContentType, oidAttributeMessageDigest, oidData are defined in signer.go
)

// ASN.1 structures for CMS/PKCS#7 parsing
// These match the structures used internally in signer.go

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

type signedData struct {
	Version          int
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	EncapContentInfo encapsulatedContentInfo
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	SignerInfos      []signerInfo  `asn1:"set"`
}

type encapsulatedContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type signerInfo struct {
	Version            int
	SID                asn1.RawValue // Can be issuerAndSerialNumber or subjectKeyIdentifier
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttrs        asn1.RawValue `asn1:"optional,tag:0"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
}

type issuerAndSerialNumber struct {
	Issuer       pkix.RDNSequence
	SerialNumber *big.Int
}

// RevocationChecker provides an interface for checking certificate revocation status.
// Implementations can use CRL, OCSP, or other revocation mechanisms.
//
// Example implementation:
//
//	type MyRevocationChecker struct{}
//
//	func (c *MyRevocationChecker) CheckRevocation(cert *x509.Certificate) error {
//	    // Check CRL or OCSP
//	    if isRevoked(cert) {
//	        return fmt.Errorf("certificate %s is revoked", cert.SerialNumber)
//	    }
//	    return nil
//	}
type RevocationChecker interface {
	// CheckRevocation checks if a certificate has been revoked.
	// Returns an error if the certificate is revoked or if the check fails.
	// Returns nil if the certificate is valid and not revoked.
	CheckRevocation(cert *x509.Certificate) error
}

// VerifyOptions allows specifying verification parameters
type VerifyOptions struct {
	Roots              *x509.CertPool     // Trusted root certificates
	Intermediates      *x509.CertPool     // Intermediate certificates
	CurrentTime        time.Time          // Time for validation (default: time.Now())
	TimeFunc           func() time.Time   // Optional time source for testing (overrides CurrentTime)
	SkipTimeValidation bool               // Skip certificate expiry validation (for ephemeral certs in Git commits)
	KeyUsages          []x509.ExtKeyUsage // Required key usages
	RevocationChecker  RevocationChecker  // Optional revocation checker (CRL/OCSP)
	MaxSignatureSize   int64              // Maximum signature size in bytes (default: 10MB, prevents DoS)
}

// parseContentInfo parses and validates the outer ContentInfo structure
func parseContentInfo(cmsSignature []byte) (*contentInfo, error) {
	var ci contentInfo
	rest, err := asn1.Unmarshal(cmsSignature, &ci)
	if err != nil {
		return nil, NewValidationError("ContentInfo", "", "failed to parse", err)
	}
	if len(rest) > 0 {
		return nil, NewValidationError("ContentInfo", "", "trailing data after CMS structure", nil)
	}
	if !ci.ContentType.Equal(oidSignedData) {
		return nil, NewValidationError("ContentType", ci.ContentType.String(),
			"expected SignedData OID", nil)
	}
	return &ci, nil
}

// parseSignedData parses and validates the SignedData structure
func parseSignedData(ci *contentInfo) (*signedData, error) {
	// Parse SignedData from EXPLICIT [0] content
	if ci.Content.Tag != 0 || ci.Content.Class != asn1ClassContext || !ci.Content.IsCompound {
		return nil, NewValidationError("Content", "",
			"invalid EXPLICIT tag", nil)
	}

	var sd signedData
	rest, err := asn1.Unmarshal(ci.Content.Bytes, &sd)
	if err != nil {
		return nil, NewValidationError("SignedData", "", "failed to parse", err)
	}
	if len(rest) > 0 {
		return nil, NewValidationError("SignedData", "", "trailing data", nil)
	}

	// Check SignedData version (RFC 5652: should be 1 for issuerAndSerialNumber)
	if sd.Version != 1 {
		return nil, NewValidationError("SignedData.Version",
			fmt.Sprintf("%d", sd.Version), "expected version 1 (issuerAndSerialNumber)", nil)
	}

	return &sd, nil
}

// validateDigestAlgorithms checks all digest algorithms and ensures they're supported
func validateDigestAlgorithms(sd *signedData) error {
	for _, alg := range sd.DigestAlgorithms {
		if alg.Algorithm.Equal(oidMD5) {
			return NewValidationError("DigestAlgorithm",
				"MD5", "weak algorithm not supported", nil)
		}
		if alg.Algorithm.Equal(oidSHA1) {
			return NewValidationError("DigestAlgorithm",
				"SHA-1", "weak algorithm not supported", nil)
		}
		// SHA-256 and SHA-512 are supported (SHA-512 required for Ed25519)
		if !alg.Algorithm.Equal(oidSHA256) && !alg.Algorithm.Equal(oidSHA512) {
			return NewValidationError("DigestAlgorithm",
				alg.Algorithm.String(), "only SHA-256 and SHA-512 are supported", nil)
		}
	}
	return nil
}

// validateSignerInfo validates the SignerInfo structure and algorithms
func validateSignerInfo(sd *signedData) (*signerInfo, error) {
	if len(sd.SignerInfos) == 0 {
		return nil, NewValidationError("SignerInfos", "0", "expected exactly 1", nil)
	}
	if len(sd.SignerInfos) != 1 {
		return nil, NewValidationError("SignerInfos",
			fmt.Sprintf("%d", len(sd.SignerInfos)), "expected exactly 1", nil)
	}

	si := &sd.SignerInfos[0]

	// Verify digest algorithm is supported
	// For Ed25519, RFC 8419 requires SHA-512
	if !si.DigestAlgorithm.Algorithm.Equal(oidSHA256) && !si.DigestAlgorithm.Algorithm.Equal(oidSHA512) {
		return nil, NewValidationError("DigestAlgorithm",
			si.DigestAlgorithm.Algorithm.String(), "expected SHA-256 or SHA-512", nil)
	}

	// RFC 5652 Section 5.1: Verify signer's digest algorithm is in SignedData digest algorithms
	digestAlgFound := false
	for _, alg := range sd.DigestAlgorithms {
		if alg.Algorithm.Equal(si.DigestAlgorithm.Algorithm) {
			digestAlgFound = true
			break
		}
	}
	if !digestAlgFound {
		return nil, NewValidationError("DigestAlgorithm",
			si.DigestAlgorithm.Algorithm.String(),
			"signer's digest algorithm not in SignedData.DigestAlgorithms (RFC 5652 violation)", nil)
	}

	// Verify signature algorithm
	if !si.SignatureAlgorithm.Algorithm.Equal(oidEd25519) {
		return nil, NewValidationError("SignatureAlgorithm",
			si.SignatureAlgorithm.Algorithm.String(), "expected Ed25519", nil)
	}

	// RFC 8410: Ed25519 parameters SHOULD be absent, but MUST accept NULL
	// Reject any other values (e.g., garbage data)
	if len(si.SignatureAlgorithm.Parameters.FullBytes) > 0 {
		// Check if it's NULL (tag 0x05, length 0x00)
		if !bytes.Equal(si.SignatureAlgorithm.Parameters.FullBytes, []byte{0x05, 0x00}) {
			return nil, NewValidationError("SignatureAlgorithm.Parameters",
				fmt.Sprintf("%x", si.SignatureAlgorithm.Parameters.FullBytes),
				"Ed25519 parameters must be absent or NULL", nil)
		}
	}

	return si, nil
}

// extractCertificates extracts and parses certificates from the SignedData structure
func extractCertificates(sd *signedData, si *signerInfo) ([]*x509.Certificate, *x509.Certificate, error) {
	if len(sd.Certificates.FullBytes) == 0 {
		return nil, nil, NewValidationError("Certificates", "",
			"no certificates found", nil)
	}

	// The certificates field is an IMPLICIT [0] containing the certificate bytes
	if sd.Certificates.FullBytes[0] != tagContextSpecific0 {
		return nil, nil, NewValidationError("Certificates", "",
			"invalid IMPLICIT [0] tag", nil)
	}

	// Extract certificate bytes from IMPLICIT [0] field
	certBytes := unwrapContext0(sd.Certificates.FullBytes)
	if certBytes == nil {
		return nil, nil, NewValidationError("Certificates", "",
			"failed to extract certificate content", nil)
	}

	// Parse certificates using proper ASN.1 unmarshaling
	var allCerts []*x509.Certificate
	var signerCert *x509.Certificate

	// Check if this is a SET OF certificates (standard format)
	if len(certBytes) > 0 && certBytes[0] == tagSet {
		// Extract content from the SET wrapper
		setContent := extractSetContent(certBytes)
		if setContent == nil {
			return nil, nil, NewValidationError("Certificates", "",
				"failed to extract SET content", nil)
		}

		// Try to parse as multiple certificates in the SET
		remaining := setContent
		parseErrors := 0
		totalAttempts := 0

		for len(remaining) > 0 {
			totalAttempts++

			// Try to parse a certificate from the remaining bytes
			var rawCert asn1.RawValue
			rest, err := asn1.Unmarshal(remaining, &rawCert)
			if err != nil {
				// If ASN.1 parsing fails, try direct certificate parsing
				// (some implementations put a single certificate directly in the SET)
				parsedCert, err := x509.ParseCertificate(remaining)
				if err == nil {
					allCerts = append(allCerts, parsedCert)
					if matchesSID(si.SID, parsedCert) {
						signerCert = parsedCert
					}
				} else {
					parseErrors++
				}
				break
			}

			// Parse the certificate
			parsedCert, err := x509.ParseCertificate(rawCert.FullBytes)
			if err != nil {
				// Track parsing failure but continue to try other certificates
				parseErrors++
				remaining = rest
				continue
			}
			allCerts = append(allCerts, parsedCert)

			// Check if this certificate matches the SignerIdentifier
			if matchesSID(si.SID, parsedCert) {
				signerCert = parsedCert
			}

			remaining = rest
		}

		// Fail if ALL certificates are malformed (potential attack)
		if totalAttempts > 0 && parseErrors == totalAttempts {
			return nil, nil, NewValidationError("Certificates", "",
				fmt.Sprintf("all %d certificate(s) are malformed - potential attack", totalAttempts), nil)
		}

		if len(allCerts) == 0 {
			return nil, nil, NewValidationError("Certificates", "",
				"no valid certificates found in SET", nil)
		}
	} else {
		// Try to parse as a single certificate (backward compatibility with older signer.go)
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			return nil, nil, NewValidationError("Certificates", "",
				"failed to parse certificate", err)
		}
		allCerts = append(allCerts, cert)
		if matchesSID(si.SID, cert) {
			signerCert = cert
		}
	}

	if signerCert == nil {
		return nil, nil, NewValidationError("Certificate", "",
			"no certificate matches SignerIdentifier", nil)
	}

	return allCerts, signerCert, nil
}

// verifyCertificateChain validates the certificate chain using the provided options
func verifyCertificateChain(signerCert *x509.Certificate, allCerts []*x509.Certificate, opts VerifyOptions) ([][]*x509.Certificate, error) {
	// If opts.Roots is nil, the system's default roots will be used
	// Add any additional certificates from the CMS as intermediates
	verifyOpts := x509.VerifyOptions{
		Roots:         opts.Roots, // If nil, system roots will be used
		Intermediates: opts.Intermediates,
		CurrentTime:   opts.CurrentTime,
	}

	// Add non-signer certificates as potential intermediates
	if verifyOpts.Intermediates == nil {
		verifyOpts.Intermediates = x509.NewCertPool()
	}
	for _, c := range allCerts {
		if c != signerCert {
			verifyOpts.Intermediates.AddCert(c)
		}
	}
	// Default to CodeSigning EKU unless explicitly overridden
	// Fail closed: require code signing unless caller specifies otherwise
	if len(opts.KeyUsages) > 0 {
		verifyOpts.KeyUsages = opts.KeyUsages
	} else {
		verifyOpts.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
	}

	// Handle time validation
	if opts.SkipTimeValidation {
		// Use cert's NotBefore + 1 second to bypass expiry checks
		// This validates chain of trust without requiring cert to be unexpired
		verifyOpts.CurrentTime = signerCert.NotBefore.Add(1 * time.Second)
	} else if opts.TimeFunc != nil {
		verifyOpts.CurrentTime = opts.TimeFunc()
	} else if verifyOpts.CurrentTime.IsZero() {
		verifyOpts.CurrentTime = time.Now()
	}

	// Perform revocation checking if a checker is provided
	if opts.RevocationChecker != nil {
		// Check revocation for the signer certificate
		if err := opts.RevocationChecker.CheckRevocation(signerCert); err != nil {
			certInfo := fmt.Sprintf("subject=%s, serial=%s", signerCert.Subject, signerCert.SerialNumber)
			return nil, NewValidationError("certificate", certInfo,
				fmt.Sprintf("revocation check failed: %v", err), err)
		}
	}

	// Perform X.509 chain validation
	chains, err := signerCert.Verify(verifyOpts)
	if err != nil {
		// Include certificate details for debugging
		certInfo := fmt.Sprintf("subject=%s, serial=%s", signerCert.Subject, signerCert.SerialNumber)
		return nil, NewValidationError("certificate", certInfo,
			fmt.Sprintf("chain validation failed: %v", err), err)
	}

	// Check revocation for all certificates in the chain if a checker is provided
	if opts.RevocationChecker != nil {
		for _, chain := range chains {
			for _, cert := range chain {
				if err := opts.RevocationChecker.CheckRevocation(cert); err != nil {
					certInfo := fmt.Sprintf("subject=%s, serial=%s", cert.Subject, cert.SerialNumber)
					return nil, NewValidationError("certificate", certInfo,
						fmt.Sprintf("revocation check failed: %v", err), err)
				}
			}
		}
	}

	return chains, nil
}

// verifyMessageDigest verifies the message digest in signed attributes if present
func verifyMessageDigest(si *signerInfo, detachedData []byte, expectedContentType asn1.ObjectIdentifier) error {
	if len(si.SignedAttrs.FullBytes) == 0 {
		return nil // No signed attributes, nothing to verify
	}

	// Parse signed attributes
	attrs, err := parseSignedAttributes(si.SignedAttrs.FullBytes)
	if err != nil {
		return NewValidationError("SignedAttributes", "",
			"failed to parse", err)
	}

	// Validate DER SET ordering
	if err := validateAttributeSetOrder(si.SignedAttrs.FullBytes); err != nil {
		return err
	}

	// Track seen attributes to detect duplicates
	seen := make(map[string]bool)
	var messageDigest []byte
	var foundDigest, foundContentType bool
	var contentType asn1.ObjectIdentifier

	for _, attr := range attrs {
		// Check for duplicates
		oidKey := attr.Type.String()
		if seen[oidKey] {
			return NewValidationError("SignedAttributes", oidKey,
				"duplicate attribute", nil)
		}
		seen[oidKey] = true

		// Extract content-type
		if attr.Type.Equal(oidAttributeContentType) {
			if _, err := asn1.Unmarshal(attr.Value.Bytes, &contentType); err != nil {
				return NewValidationError("ContentType", "",
					"failed to parse", err)
			}
			foundContentType = true
		}

		// Extract message-digest
		if attr.Type.Equal(oidAttributeMessageDigest) {
			messageDigest, err = extractDigestFromAttribute(attr.Value)
			if err != nil {
				return NewValidationError("MessageDigest", "",
					"failed to extract", err)
			}
			foundDigest = true
		}
	}

	// RFC 5652 Section 5.3: content-type and message-digest are REQUIRED
	if !foundContentType {
		return NewValidationError("ContentType", "",
			"attribute not found in SignedAttributes (RFC 5652 Section 5.3)", nil)
	}

	if !foundDigest {
		return NewValidationError("MessageDigest", "",
			"attribute not found in SignedAttributes", nil)
	}

	// Verify content-type matches EncapContentInfo
	if !contentType.Equal(expectedContentType) {
		return NewValidationError("ContentType", contentType.String(),
			fmt.Sprintf("does not match EncapContentInfo.ContentType (%s)", expectedContentType.String()), nil)
	}

	// Calculate expected digest based on algorithm
	var expectedDigest []byte
	if si.DigestAlgorithm.Algorithm.Equal(oidSHA256) {
		h := sha256.Sum256(detachedData)
		expectedDigest = h[:]
	} else if si.DigestAlgorithm.Algorithm.Equal(oidSHA512) {
		h := sha512.Sum512(detachedData)
		expectedDigest = h[:]
	} else {
		return NewValidationError("DigestAlgorithm",
			si.DigestAlgorithm.Algorithm.String(), "unsupported algorithm", nil)
	}

	// Constant-time comparison for defense in depth
	if subtle.ConstantTimeCompare(messageDigest, expectedDigest) != 1 {
		return NewSignatureError(internal.SigTypeCMS,
			"message digest mismatch", nil)
	}

	return nil
}

// prepareDataForVerification prepares the data that needs to be verified based on whether signed attributes are present
func prepareDataForVerification(si *signerInfo, detachedData []byte) ([]byte, error) {
	if len(si.SignedAttrs.FullBytes) > 0 {
		// CRITICAL: Reconstruct the SET OF that was signed
		// SignedAttrs is stored as IMPLICIT [0]: A0 <len> <content>
		// But the signature was calculated over: 31 <len> <content>

		// Extract content from IMPLICIT [0] (skip tag and length)
		content := unwrapContext0(si.SignedAttrs.FullBytes)
		if content == nil {
			return nil, NewValidationError("SignedAttributes", "",
				"failed to extract content from IMPLICIT tag", nil)
		}

		// Re-wrap with SET OF tag (0x31) for verification
		return wrapAsSet(content), nil
	}

	// No SignedAttrs: signature is over content hash directly
	// Need to determine which hash algorithm was used
	if si.DigestAlgorithm.Algorithm.Equal(oidSHA256) {
		h := sha256.Sum256(detachedData)
		return h[:], nil
	} else if si.DigestAlgorithm.Algorithm.Equal(oidSHA512) {
		h := sha512.Sum512(detachedData)
		return h[:], nil
	} else {
		return nil, NewValidationError("DigestAlgorithm",
			si.DigestAlgorithm.Algorithm.String(), "unsupported algorithm", nil)
	}
}

// performSignatureVerification verifies the Ed25519 signature
func performSignatureVerification(signerCert *x509.Certificate, dataToVerify []byte, signature []byte) error {
	pubKey, ok := signerCert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return NewKeyError(internal.OpVerify, internal.KeyTypePublic,
			fmt.Errorf("expected Ed25519 key, got %T", signerCert.PublicKey))
	}

	if !ed25519.Verify(pubKey, dataToVerify, signature) {
		return NewSignatureError(internal.SigTypeCMS,
			"Ed25519 verification failed", nil)
	}

	return nil
}

// Verify parses and validates a detached CMS/PKCS#7 signature
//
// This function implements RFC 5652 (CMS) verification for Ed25519 signatures.
// It validates the signature structure, certificate chain, message digest,
// and cryptographic signature.
//
// Parameters:
//   - cmsSignature: DER-encoded CMS/PKCS#7 signature
//   - detachedData: The original data that was signed
//   - opts: Verification options including trusted roots
//
// Returns:
//   - The validated certificate chain (signer cert first, then intermediates)
//   - An error if verification fails at any step
func Verify(cmsSignature, detachedData []byte, opts VerifyOptions) ([]*x509.Certificate, error) {
	// Enforce maximum signature size to prevent DoS attacks
	maxSize := opts.MaxSignatureSize
	if maxSize == 0 {
		maxSize = internal.MaxSignatureSize // Default: 1MB
	}
	if int64(len(cmsSignature)) > maxSize {
		return nil, NewValidationError("signature size",
			fmt.Sprintf("%d bytes", len(cmsSignature)),
			fmt.Sprintf("exceeds maximum allowed size of %d bytes", maxSize), nil)
	}

	// Step 1: Parse ContentInfo
	ci, err := parseContentInfo(cmsSignature)
	if err != nil {
		return nil, err
	}

	// Step 2: Parse SignedData
	sd, err := parseSignedData(ci)
	if err != nil {
		return nil, err
	}

	// Step 3: Validate digest algorithms
	if err := validateDigestAlgorithms(sd); err != nil {
		return nil, err
	}

	// Step 4: Validate SignerInfo
	si, err := validateSignerInfo(sd)
	if err != nil {
		return nil, err
	}

	// Step 5: Extract and validate certificates
	allCerts, signerCert, err := extractCertificates(sd, si)
	if err != nil {
		return nil, err
	}

	// Step 6: Verify certificate chain
	chains, err := verifyCertificateChain(signerCert, allCerts, opts)
	if err != nil {
		return nil, err
	}

	// Step 7: Verify message digest (if SignedAttrs present)
	if err := verifyMessageDigest(si, detachedData, sd.EncapContentInfo.ContentType); err != nil {
		return nil, err
	}

	// Step 8: Prepare data for signature verification
	dataToVerify, err := prepareDataForVerification(si, detachedData)
	if err != nil {
		return nil, err
	}

	// Step 9: Verify Ed25519 signature
	if err := performSignatureVerification(signerCert, dataToVerify, si.Signature); err != nil {
		return nil, err
	}

	// Build the certificate chain with signer cert first
	var certChain []*x509.Certificate
	certChain = append(certChain, signerCert)

	// Add any chain certificates returned from Verify (if available)
	// Take the first chain if multiple are found
	if len(chains) > 0 && len(chains[0]) > 1 {
		// Skip the first cert as it's the signer cert we already added
		certChain = append(certChain, chains[0][1:]...)
	}

	return certChain, nil
}

// Helper Functions

// parseASN1Length parses ASN.1 DER/BER length encoding from data starting at offset
// Returns the length value and new position after length bytes, or error if invalid
// This function properly validates bounds to prevent panics from malformed input
func parseASN1Length(data []byte, offset int) (length int, newPos int, err error) {
	if offset >= len(data) {
		return 0, 0, fmt.Errorf("offset %d exceeds data length %d", offset, len(data))
	}

	pos := offset
	firstByte := data[pos]

	if firstByte < 0x80 {
		// Short form: length is in single byte (0-127)
		length = int(firstByte)
		newPos = pos + 1
	} else if firstByte == 0x80 {
		// Indefinite length - not supported in DER
		return 0, 0, fmt.Errorf("indefinite length encoding not supported")
	} else {
		// Long form: firstByte & 0x7f tells us number of length bytes
		numBytes := int(firstByte & 0x7f)
		if numBytes > 4 {
			// We don't support lengths requiring more than 4 bytes (>4GB)
			return 0, 0, fmt.Errorf("length encoding with %d bytes not supported", numBytes)
		}

		pos++
		if len(data) < pos+numBytes {
			return 0, 0, fmt.Errorf("insufficient data for %d-byte length: need %d, have %d",
				numBytes, pos+numBytes, len(data))
		}

		// Parse the length value with overflow protection
		length = 0
		for i := 0; i < numBytes; i++ {
			// Check for integer overflow on 32-bit systems
			// On 32-bit systems, int max is 2^31-1 (2147483647)
			prevLength := length
			length = (length << 8) | int(data[pos+i])

			// Detect overflow: if length wrapped around to negative or decreased
			if length < 0 || (prevLength > 0 && length < prevLength) {
				return 0, 0, fmt.Errorf("integer overflow in length encoding")
			}
		}
		newPos = pos + numBytes
	}

	// Critical: Validate length doesn't exceed remaining data
	if newPos+length > len(data) || newPos+length < 0 { // Check for overflow in addition
		return 0, 0, fmt.Errorf("length %d exceeds remaining data %d", length, len(data)-newPos)
	}

	return length, newPos, nil
}

// extractSetContent extracts content from a SET (tag 0x31)
// by skipping the tag and length bytes to get the raw content
func extractSetContent(data []byte) []byte {
	if len(data) < 2 {
		return nil
	}

	// Verify SET tag
	if data[0] != tagSet {
		return nil
	}

	// Parse length using shared function with proper bounds checking
	length, pos, err := parseASN1Length(data, 1)
	if err != nil {
		return nil
	}

	// Return the content bytes (already validated by parseASN1Length)
	return data[pos : pos+length]
}

// unwrapContext0 extracts content from a CONTEXT SPECIFIC [0] tagged field
// by skipping the tag and length bytes to get the raw content
func unwrapContext0(data []byte) []byte {
	if len(data) < 2 {
		return nil
	}

	// Verify IMPLICIT [0] tag
	if data[0] != tagContextSpecific0 {
		return nil
	}

	// Parse length using shared function with proper bounds checking
	length, pos, err := parseASN1Length(data, 1)
	if err != nil {
		return nil
	}

	// Return the content bytes (already validated by parseASN1Length)
	return data[pos : pos+length]
}

// wrapAsSet wraps content with a SET OF tag (0x31) and proper length encoding
func wrapAsSet(content []byte) []byte {
	header := internal.MarshalSetHeader(len(content))
	return append(header, content...)
}

// parseSignedAttributes parses IMPLICIT [0] SignedAttrs back into attribute structures
//
// IMPORTANT: The IMPLICIT [0] tag replaces the SET OF tag, so the content we extract
// is the concatenated attributes without the outer SET wrapper. We must parse them
// individually, not as a SET OF structure.
//
// The structure in the CMS is:
//
//	SignedAttrs [0] IMPLICIT SET OF Attribute
//
// Which becomes:
//
//	A0 <len> <attr1> <attr2> ...  (the SET tag 31 is replaced by A0)
//
// After unwrapping the IMPLICIT [0], we have just the concatenated attributes.
func parseSignedAttributes(signedAttrs []byte) ([]attribute, error) {
	// Extract content from IMPLICIT [0]
	content := unwrapContext0(signedAttrs)
	if content == nil {
		return nil, fmt.Errorf("failed to extract content from IMPLICIT [0]")
	}

	// Parse individual attributes from the concatenated content
	// Note: The content is NOT a SET anymore, it's just concatenated attributes
	var attrs []attribute
	remaining := content
	for len(remaining) > 0 {
		var attr attribute
		rest, err := asn1.Unmarshal(remaining, &attr)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal attribute: %w", err)
		}
		attrs = append(attrs, attr)
		remaining = rest
	}

	if len(attrs) == 0 {
		return nil, fmt.Errorf("no attributes found in SignedAttrs")
	}

	return attrs, nil
}

// validateAttributeSetOrder verifies that SignedAttributes are in DER canonical order
// RFC 5652 requires SET OF to be sorted by DER encoding
func validateAttributeSetOrder(signedAttrs []byte) error {
	// Extract content from IMPLICIT [0]
	content := unwrapContext0(signedAttrs)
	if content == nil {
		return NewValidationError("SignedAttributes", "",
			"failed to extract content from IMPLICIT [0]", nil)
	}

	// Parse attributes and track their DER encodings
	var attrs []attribute
	var encodings [][]byte
	remaining := content

	for len(remaining) > 0 {
		// Find the start of this attribute
		startPos := len(content) - len(remaining)

		var attr attribute
		rest, err := asn1.Unmarshal(remaining, &attr)
		if err != nil {
			return NewValidationError("SignedAttributes", "",
				"failed to unmarshal attribute", err)
		}

		// Extract the DER encoding of this attribute
		attrLen := len(remaining) - len(rest)
		encoding := content[startPos : startPos+attrLen]

		attrs = append(attrs, attr)
		encodings = append(encodings, encoding)
		remaining = rest
	}

	// Verify SET OF ordering (lexicographic byte order)
	for i := 1; i < len(encodings); i++ {
		if compareBytes(encodings[i-1], encodings[i]) >= 0 {
			return NewValidationError("SignedAttributes", "",
				"attributes not in DER canonical order (RFC 5652 requires sorted SET OF)", nil)
		}
	}

	return nil
}

// compareBytes performs lexicographic comparison of byte slices
// Returns -1 if a < b, 0 if a == b, 1 if a > b
func compareBytes(a, b []byte) int {
	minLen := len(a)
	if len(b) < minLen {
		minLen = len(b)
	}

	for i := 0; i < minLen; i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}

	if len(a) < len(b) {
		return -1
	}
	if len(a) > len(b) {
		return 1
	}
	return 0
}

// constantTimeCompareBigInt performs constant-time comparison of two big integers
// Returns true if they are equal, false otherwise
func constantTimeCompareBigInt(a, b *big.Int) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}

	// Get byte representations
	aBytes := a.Bytes()
	bBytes := b.Bytes()

	// For constant-time comparison, we need equal-length byte slices
	// Pad the shorter one with leading zeros
	maxLen := len(aBytes)
	if len(bBytes) > maxLen {
		maxLen = len(bBytes)
	}

	// Create padded versions
	aPadded := make([]byte, maxLen)
	bPadded := make([]byte, maxLen)
	copy(aPadded[maxLen-len(aBytes):], aBytes)
	copy(bPadded[maxLen-len(bBytes):], bBytes)

	return subtle.ConstantTimeCompare(aPadded, bPadded) == 1
}

// matchesSID verifies that SignerIdentifier matches certificate
// Supports both issuerAndSerialNumber and subjectKeyIdentifier
// Uses constant-time comparison for cryptographic values to prevent timing attacks
func matchesSID(sidRaw asn1.RawValue, cert *x509.Certificate) bool {
	// Check if this is a subjectKeyIdentifier (IMPLICIT [0] OCTET STRING)
	if sidRaw.Tag == 0 && sidRaw.Class == asn1ClassContext {
		// This is a subjectKeyIdentifier
		var keyID []byte
		rest, err := asn1.Unmarshal(sidRaw.Bytes, &keyID)
		if err != nil || len(rest) > 0 {
			return false
		}
		// Use constant-time comparison for key IDs
		if len(cert.SubjectKeyId) == 0 || len(keyID) != len(cert.SubjectKeyId) {
			return false
		}
		return subtle.ConstantTimeCompare(keyID, cert.SubjectKeyId) == 1
	}

	// Otherwise, try to parse as issuerAndSerialNumber
	var sid issuerAndSerialNumber
	rest, err := asn1.Unmarshal(sidRaw.FullBytes, &sid)
	if err != nil || len(rest) > 0 {
		return false
	}

	// Use constant-time comparison for serial numbers
	if !constantTimeCompareBigInt(sid.SerialNumber, cert.SerialNumber) {
		return false
	}

	// Compare issuers (these are public values, but we maintain consistency)
	certIssuer := cert.Issuer.ToRDNSequence()
	if len(sid.Issuer) != len(certIssuer) {
		return false
	}

	// Compare each RDN
	for i := range sid.Issuer {
		if len(sid.Issuer[i]) != len(certIssuer[i]) {
			return false
		}
		for j := range sid.Issuer[i] {
			if !sid.Issuer[i][j].Type.Equal(certIssuer[i][j].Type) {
				return false
			}
			// Use constant-time comparison for RDN values
			if !constantTimeCompareRDNValue(sid.Issuer[i][j].Value, certIssuer[i][j].Value) {
				return false
			}
		}
	}

	return true
}

// constantTimeCompareRDNValue performs constant-time comparison of RDN attribute values.
// RDN values can be strings, byte slices, or other types. This function normalizes them
// to byte slices and performs constant-time comparison to prevent timing attacks.
func constantTimeCompareRDNValue(a, b interface{}) bool {
	// Convert both values to byte slices for comparison
	aBytes := normalizeRDNValue(a)
	bBytes := normalizeRDNValue(b)

	// Perform constant-time comparison
	// If lengths differ, still compare to avoid timing leaks
	if len(aBytes) != len(bBytes) {
		return false
	}
	return subtle.ConstantTimeCompare(aBytes, bBytes) == 1
}

// normalizeRDNValue converts an RDN attribute value to a byte slice for comparison.
// This handles the various types that can appear in X.509 Distinguished Names.
func normalizeRDNValue(v interface{}) []byte {
	switch val := v.(type) {
	case string:
		return []byte(val)
	case []byte:
		return val
	default:
		// For other types (int, etc.), use fmt.Sprintf as fallback
		return []byte(fmt.Sprintf("%v", val))
	}
}

// extractDigestFromAttribute extracts the digest value from an attribute's SET wrapper
func extractDigestFromAttribute(value asn1.RawValue) ([]byte, error) {
	// The value should be a SET containing an OCTET STRING
	if value.Tag != tagSetTag || !value.IsCompound {
		return nil, fmt.Errorf("expected SET, got tag %d", value.Tag)
	}

	// Parse the OCTET STRING from the SET
	var digest []byte
	rest, err := asn1.Unmarshal(value.Bytes, &digest)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal digest: %w", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("trailing data in digest attribute")
	}

	return digest, nil
}
