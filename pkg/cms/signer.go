// Package cms implements CMS/PKCS#7 signature generation with Ed25519 support.
//
// This package fills a gap in the Go ecosystem as existing CMS libraries
// (mozilla/pkcs7, cloudflare/cfssl) do not support Ed25519 signatures.
//
// # Security Considerations
//
// Time Security: The signing time attribute is included in the CMS signature
// and is cryptographically protected. However, the accuracy depends on the
// security of the time source. For production use, provide a TimeSource
// synchronized with a trusted NTP server or use a hardware-based secure time
// source via SignDataWithOptions.
//
// Private Key Memory: Go's garbage collector does not guarantee that memory
// containing sensitive data will be zeroed before being reused or released.
// Private keys passed to SignData will remain in memory until garbage collected,
// and there is no way to force immediate clearing of this memory. For high-security
// environments requiring guaranteed key material erasure from memory, consider:
//   - Using hardware security modules (HSMs) that keep keys in secure hardware
//   - Using platform-specific memory protection mechanisms
//   - Minimizing the time private keys are held in memory
//   - Using short-lived signing keys
package cms

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"sort"
	"time"

	"github.com/jamestexas/go-cms/pkg/cms/internal"
)

// OID definitions for CMS/PKCS#7
var (
	oidSignedData             = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidData                   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidAttributeContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidAttributeMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidAttributeSigningTime   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	oidSHA256                 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidEd25519                = asn1.ObjectIdentifier{1, 3, 101, 112}
)

// TimeSource provides the current time for signature generation.
// Implementations can provide secure time sources (NTP, trusted time servers)
// or fixed times for testing.
//
// Security Note: The signing time is included in the signed attributes and
// is cryptographically protected by the signature. However, the accuracy of
// this time depends on the security of the time source. For high-security
// applications, use a trusted time source synchronized with a reliable NTP server
// or a hardware-based secure time source.
//
// Example implementation:
//
//	type SecureTimeSource struct{}
//
//	func (s *SecureTimeSource) Now() time.Time {
//	    // Query trusted NTP server or hardware time source
//	    return getSecureTime()
//	}
type TimeSource interface {
	// Now returns the current time to be used for signature generation.
	Now() time.Time
}

// SignOptions provides optional parameters for signature generation.
type SignOptions struct {
	// TimeSource provides the time to use for the signing time attribute.
	// If nil, time.Now() is used. For production use, consider using a
	// secure time source synchronized with a trusted time server.
	TimeSource TimeSource
}

// SignData creates a detached CMS/PKCS#7 signature using Ed25519.
//
// This function implements RFC 5652 (CMS) with RFC 8410 (Ed25519 in CMS).
// The signature is detached (does not include the original data).
//
// For more control over signature generation (e.g., custom time sources),
// use SignDataWithOptions.
//
// Parameters:
//   - data: The data to be signed
//   - cert: The X.509 certificate containing the public key
//   - privateKey: The Ed25519 private key for signing
//
// Returns:
//   - DER-encoded CMS/PKCS#7 signature
func SignData(data []byte, cert *x509.Certificate, privateKey ed25519.PrivateKey) ([]byte, error) {
	return SignDataWithOptions(data, cert, privateKey, SignOptions{})
}

// SignDataWithOptions creates a detached CMS/PKCS#7 signature using Ed25519 with custom options.
//
// This function implements RFC 5652 (CMS) with RFC 8410 (Ed25519 in CMS).
// The signature is detached (does not include the original data).
//
// Parameters:
//   - data: The data to be signed
//   - cert: The X.509 certificate containing the public key
//   - privateKey: The Ed25519 private key for signing
//   - opts: Optional parameters for signature generation
//
// Returns:
//   - DER-encoded CMS/PKCS#7 signature
func SignDataWithOptions(data []byte, cert *x509.Certificate, privateKey ed25519.PrivateKey, opts SignOptions) ([]byte, error) {
	// Input validation
	if cert == nil {
		return nil, NewValidationError("certificate", "nil", "must not be nil", nil)
	}
	if privateKey == nil {
		return nil, NewValidationError("private key", "nil", "must not be nil", nil)
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, NewValidationError("private key length",
			fmt.Sprintf("%d bytes", len(privateKey)),
			fmt.Sprintf("must be %d bytes for Ed25519", ed25519.PrivateKeySize), nil)
	}
	if data == nil {
		return nil, NewValidationError("data", "nil", "must not be nil", nil)
	}

	// Validate certificate is currently valid
	now := time.Now()
	if opts.TimeSource != nil {
		now = opts.TimeSource.Now()
	}
	if cert.NotAfter.Before(now) {
		return nil, NewValidationError("certificate",
			fmt.Sprintf("expired at %s", cert.NotAfter),
			"certificate has expired", nil)
	}
	if cert.NotBefore.After(now) {
		return nil, NewValidationError("certificate",
			fmt.Sprintf("not valid until %s", cert.NotBefore),
			"certificate is not yet valid", nil)
	}

	// Validate certificate uses Ed25519
	if cert.PublicKeyAlgorithm != x509.Ed25519 {
		return nil, NewValidationError("certificate.PublicKeyAlgorithm",
			cert.PublicKeyAlgorithm.String(),
			"must be Ed25519", nil)
	}

	// 1. Calculate message digest
	hash := crypto.SHA256.New()
	hash.Write(data)
	messageDigest := hash.Sum(nil)

	// 2. Determine signing time
	signingTime := time.Now()
	if opts.TimeSource != nil {
		signingTime = opts.TimeSource.Now()
	}

	// 3. Create signed attributes
	signedAttrs, err := createSignedAttributes(messageDigest, signingTime)
	if err != nil {
		return nil, err
	}

	// 3. Encode attributes as SET for signing (with SET tag)
	setForSigning, err := encodeAttributesAsSet(signedAttrs)
	if err != nil {
		return nil, NewSignatureError(internal.SigTypeCMS, "failed to encode attributes as SET", err)
	}

	// 4. Sign the SET OF attributes
	signature := ed25519.Sign(privateKey, setForSigning)
	if signature == nil {
		return nil, NewSignatureError(internal.SigTypeCMS, "failed to create signature", nil)
	}

	// 5. Encode attributes as [0] IMPLICIT for storage in SignerInfo
	implicitAttrs, err := encodeSignedAttributesImplicit(signedAttrs)
	if err != nil {
		return nil, NewSignatureError(internal.SigTypeCMS, "failed to encode attributes as IMPLICIT", err)
	}

	// 6. Build SignerInfo with the IMPLICIT encoded attributes
	signerInfo, err := buildSignerInfo(cert, implicitAttrs, signature)
	if err != nil {
		return nil, err
	}

	// 7. Build complete CMS structure
	cmsBytes, err := buildCMS(cert, signerInfo)
	if err != nil {
		return nil, err
	}

	return cmsBytes, nil
}

// attribute represents a CMS attribute
type attribute struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"set"`
}

// createSignedAttributes creates the signed attributes for CMS
func createSignedAttributes(messageDigest []byte, signingTime time.Time) ([]attribute, error) {
	// Encode attribute values - each must be wrapped in a SET
	contentTypeValue, err := asn1.Marshal(oidData)
	if err != nil {
		return nil, NewSignatureError(internal.SigTypeCMS, "failed to marshal content type OID", err)
	}

	messageDigestValue, err := asn1.Marshal(messageDigest)
	if err != nil {
		return nil, NewSignatureError(internal.SigTypeCMS, "failed to marshal message digest", err)
	}

	signingTimeValue, err := asn1.Marshal(signingTime.UTC())
	if err != nil {
		return nil, NewSignatureError(internal.SigTypeCMS, "failed to marshal signing time", err)
	}

	return []attribute{
		{
			Type: oidAttributeContentType,
			Value: asn1.RawValue{
				Class:      0,  // universal
				Tag:        17, // SET
				IsCompound: true,
				Bytes:      contentTypeValue,
			},
		},
		{
			Type: oidAttributeSigningTime,
			Value: asn1.RawValue{
				Class:      0,  // universal
				Tag:        17, // SET
				IsCompound: true,
				Bytes:      signingTimeValue,
			},
		},
		{
			Type: oidAttributeMessageDigest,
			Value: asn1.RawValue{
				Class:      0,  // universal
				Tag:        17, // SET
				IsCompound: true,
				Bytes:      messageDigestValue,
			},
		},
	}, nil
}

// encodeAttributesAsSet creates a proper SET OF Attribute for signing
// Returns the complete SET with tag 0x31
func encodeAttributesAsSet(attrs []attribute) ([]byte, error) {
	// Step 1: Marshal each attribute individually
	var encodedAttrs [][]byte
	for _, attr := range attrs {
		attrBytes, err := asn1.Marshal(attr)
		if err != nil {
			return nil, err
		}
		encodedAttrs = append(encodedAttrs, attrBytes)
	}

	// Step 2: Sort for canonical SET OF ordering (DER requirement)
	sort.Slice(encodedAttrs, func(i, j int) bool {
		return bytes.Compare(encodedAttrs[i], encodedAttrs[j]) < 0
	})

	// Step 3: Concatenate sorted attributes
	var buf bytes.Buffer
	for _, attrBytes := range encodedAttrs {
		buf.Write(attrBytes)
	}
	content := buf.Bytes()

	// Step 4: Create SET with tag 0x31
	result := []byte{0x31} // SET tag

	// Add length
	if len(content) < 128 {
		result = append(result, byte(len(content)))
	} else if len(content) < 256 {
		result = append(result, 0x81, byte(len(content)))
	} else {
		result = append(result, 0x82, byte(len(content)>>8), byte(len(content)))
	}

	// Add content
	result = append(result, content...)
	return result, nil
}

// encodeSignedAttributesImplicit creates [0] IMPLICIT SET OF for storage in SignerInfo
// Returns tag 0xA0 with SET contents (no SET tag)
func encodeSignedAttributesImplicit(attrs []attribute) ([]byte, error) {
	// Step 1: Marshal each attribute individually
	var encodedAttrs [][]byte
	for _, attr := range attrs {
		attrBytes, err := asn1.Marshal(attr)
		if err != nil {
			return nil, err
		}
		encodedAttrs = append(encodedAttrs, attrBytes)
	}

	// Step 2: Sort for canonical SET OF ordering
	sort.Slice(encodedAttrs, func(i, j int) bool {
		return bytes.Compare(encodedAttrs[i], encodedAttrs[j]) < 0
	})

	// Step 3: Concatenate sorted attributes (SET contents without SET tag)
	var buf bytes.Buffer
	for _, attrBytes := range encodedAttrs {
		buf.Write(attrBytes)
	}
	content := buf.Bytes()

	// Step 4: Create [0] IMPLICIT (replaces SET tag with context tag)
	result := []byte{0xA0} // Context-specific, constructed, tag 0

	// Add length
	if len(content) < 128 {
		result = append(result, byte(len(content)))
	} else if len(content) < 256 {
		result = append(result, 0x81, byte(len(content)))
	} else {
		result = append(result, 0x82, byte(len(content)>>8), byte(len(content)))
	}

	// Add content (no SET tag, just the concatenated attributes)
	result = append(result, content...)
	return result, nil
}

// buildSignerInfo manually constructs SignerInfo with proper IMPLICIT [0] for signedAttrs
func buildSignerInfo(cert *x509.Certificate, signedAttrsBytes []byte, signature []byte) ([]byte, error) {
	var buf bytes.Buffer

	// Version (INTEGER 1)
	versionBytes, err := asn1.Marshal(1)
	if err != nil {
		return nil, NewSignatureError(internal.SigTypeCMS, "failed to marshal SignerInfo version", err)
	}
	buf.Write(versionBytes)

	// IssuerAndSerialNumber
	issuerAndSerial := struct {
		Issuer       pkix.RDNSequence
		SerialNumber *big.Int
	}{
		Issuer:       cert.Issuer.ToRDNSequence(),
		SerialNumber: cert.SerialNumber,
	}
	issuerBytes, err := asn1.Marshal(issuerAndSerial)
	if err != nil {
		return nil, NewSignatureError(internal.SigTypeCMS, "failed to marshal issuerAndSerialNumber", err)
	}
	buf.Write(issuerBytes)

	// DigestAlgorithm
	digestAlg := pkix.AlgorithmIdentifier{Algorithm: oidSHA256}
	digestAlgBytes, err := asn1.Marshal(digestAlg)
	if err != nil {
		return nil, NewSignatureError(internal.SigTypeCMS, "failed to marshal digest algorithm", err)
	}
	buf.Write(digestAlgBytes)

	// SignedAttrs as IMPLICIT [0] SET OF Attribute - use the pre-encoded bytes
	buf.Write(signedAttrsBytes)

	// SignatureAlgorithm
	sigAlg := pkix.AlgorithmIdentifier{Algorithm: oidEd25519}
	sigAlgBytes, err := asn1.Marshal(sigAlg)
	if err != nil {
		return nil, NewSignatureError(internal.SigTypeCMS, "failed to marshal signature algorithm", err)
	}
	buf.Write(sigAlgBytes)

	// Signature (OCTET STRING)
	sigBytes, err := asn1.Marshal(signature)
	if err != nil {
		return nil, NewSignatureError(internal.SigTypeCMS, "failed to marshal signature bytes", err)
	}
	buf.Write(sigBytes)

	// Wrap in SEQUENCE
	content := buf.Bytes()
	seqHeader := makeSequenceHeader(len(content))

	result := append(seqHeader, content...)
	return result, nil
}

// buildCMS builds the complete CMS ContentInfo structure
func buildCMS(cert *x509.Certificate, signerInfo []byte) ([]byte, error) {
	// Build SignedData
	var sdBuf bytes.Buffer

	// Version (INTEGER 1)
	versionBytes, err := asn1.Marshal(1)
	if err != nil {
		return nil, NewSignatureError(internal.SigTypeCMS, "failed to marshal SignedData version", err)
	}
	sdBuf.Write(versionBytes)

	// DigestAlgorithms (SET OF AlgorithmIdentifier)
	digestAlgs := []pkix.AlgorithmIdentifier{{Algorithm: oidSHA256}}
	digestAlgsBytes, err := asn1.Marshal(digestAlgs)
	if err != nil {
		return nil, NewSignatureError(internal.SigTypeCMS, "failed to marshal digest algorithms", err)
	}
	// Change SEQUENCE to SET tag
	if len(digestAlgsBytes) > 0 && digestAlgsBytes[0] == 0x30 {
		digestAlgsBytes[0] = 0x31
	}
	sdBuf.Write(digestAlgsBytes)

	// EncapContentInfo
	encapContent := struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
	}{
		ContentType: oidData,
		// Content omitted for detached signature
	}
	encapBytes, err := asn1.Marshal(encapContent)
	if err != nil {
		return nil, NewSignatureError(internal.SigTypeCMS, "failed to marshal encapsulated content info", err)
	}
	sdBuf.Write(encapBytes)

	// Certificates [0] IMPLICIT SET OF Certificate
	// RFC 5652 §5.3 specifies that the context-specific tag replaces the
	// universal SET (0x31) when encoding this field. We therefore append the
	// DER of each full certificate (cert.Raw) directly under the [0] header
	// without introducing an inner SET. Emitting A0..<len>..31 would cause
	// decoders such as OpenSSL to reject the structure with
	// CMS_CertificateChoices errors.
	certPayload := cert.Raw

	certHeader := []byte{0xA0} // context-specific, constructed, tag 0
	if len(certPayload) < 128 {
		certHeader = append(certHeader, byte(len(certPayload)))
	} else {
		certPayloadLen := len(certPayload)
		if certPayloadLen < 256 {
			certHeader = append(certHeader, 0x81, byte(certPayloadLen))
		} else if certPayloadLen < 65536 {
			certHeader = append(certHeader, 0x82, byte(certPayloadLen>>8), byte(certPayloadLen))
		} else {
			// Certificate payload is too large (>= 65536 bytes)
			return nil, NewValidationError("certificate payload size", fmt.Sprintf("%d bytes", certPayloadLen), "exceeds maximum size of 65535 bytes", nil)
		}
	}
	sdBuf.Write(certHeader)
	sdBuf.Write(certPayload)

	// SignerInfos (SET OF SignerInfo)
	siSetHeader := makeSetHeader(len(signerInfo))
	sdBuf.Write(siSetHeader)
	sdBuf.Write(signerInfo)

	// Wrap SignedData in SEQUENCE
	sdContent := sdBuf.Bytes()
	sdSeqHeader := makeSequenceHeader(len(sdContent))
	signedData := append(sdSeqHeader, sdContent...)

	// Build ContentInfo
	var ciBuf bytes.Buffer

	// ContentType (OBJECT IDENTIFIER)
	contentTypeBytes, err := asn1.Marshal(oidSignedData)
	if err != nil {
		return nil, NewSignatureError(internal.SigTypeCMS, "failed to marshal content type OID", err)
	}
	ciBuf.Write(contentTypeBytes)

	// Content [0] EXPLICIT
	contentHeader := []byte{0xA0} // context-specific, constructed, tag 0
	if len(signedData) < 128 {
		contentHeader = append(contentHeader, byte(len(signedData)))
	} else {
		contentLen := len(signedData)
		if contentLen < 256 {
			contentHeader = append(contentHeader, 0x81, byte(contentLen))
		} else if contentLen < 65536 {
			contentHeader = append(contentHeader, 0x82, byte(contentLen>>8), byte(contentLen))
		} else {
			// Content is too large (>= 65536 bytes)
			return nil, NewValidationError("content size", fmt.Sprintf("%d bytes", contentLen), "exceeds maximum size of 65535 bytes", nil)
		}
	}
	ciBuf.Write(contentHeader)
	ciBuf.Write(signedData)

	// Wrap ContentInfo in SEQUENCE
	ciContent := ciBuf.Bytes()
	ciSeqHeader := makeSequenceHeader(len(ciContent))

	return append(ciSeqHeader, ciContent...), nil
}

// makeSequenceHeader creates a SEQUENCE header with the given length
func makeSequenceHeader(length int) []byte {
	header := []byte{0x30} // SEQUENCE tag
	if length < 128 {
		header = append(header, byte(length))
	} else if length < 256 {
		header = append(header, 0x81, byte(length))
	} else if length < 65536 {
		header = append(header, 0x82, byte(length>>8), byte(length))
	} else {
		// For very large structures
		header = append(header, 0x83, byte(length>>16), byte(length>>8), byte(length))
	}
	return header
}

// makeSetHeader creates a SET header with the given length
func makeSetHeader(length int) []byte {
	header := []byte{0x31} // SET tag
	if length < 128 {
		header = append(header, byte(length))
	} else if length < 256 {
		header = append(header, 0x81, byte(length))
	} else if length < 65536 {
		header = append(header, 0x82, byte(length>>8), byte(length))
	} else {
		// For very large structures
		header = append(header, 0x83, byte(length>>16), byte(length>>8), byte(length))
	}
	return header
}
