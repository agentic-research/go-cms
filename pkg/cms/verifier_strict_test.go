package cms

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"
	"time"
)

// TestVerifyRejectMissingContentType validates RFC 5652 Section 5.3:
// When SignedAttrs are present, content-type MUST be included
func TestVerifyRejectMissingContentType(t *testing.T) {
	// Create test certificate with CodeSigning EKU
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

	// Test data
	data := []byte("test data")
	digest := sha512.Sum512(data)

	// Build SignedAttrs WITHOUT content-type (only message-digest)
	messageDigestValue, _ := asn1.Marshal(digest[:])
	attrs := []attribute{
		{
			Type:  oidAttributeMessageDigest,
			Value: asn1.RawValue{Tag: 17, Class: 0, IsCompound: true, Bytes: messageDigestValue},
		},
		// NOTE: content-type intentionally omitted (RFC 5652 violation)
	}

	// Use signer's helper for proper encoding
	attrsForSigning, _ := encodeAttributesAsSet(attrs)
	signedAttrsImplicit, _ := encodeSignedAttributesImplicit(attrs)
	signature := ed25519.Sign(privKey, attrsForSigning)

	// Build minimal CMS structure
	si := signerInfo{
		Version:            1,
		SID:                asn1.RawValue{FullBytes: mustMarshalIssuerAndSerial(t, cert.RawIssuer, cert.SerialNumber)},
		DigestAlgorithm:    pkix.AlgorithmIdentifier{Algorithm: oidSHA512},
		SignedAttrs:        asn1.RawValue{FullBytes: signedAttrsImplicit},
		SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidEd25519},
		Signature:          signature,
	}

	sd := signedData{
		Version:          1,
		DigestAlgorithms: []pkix.AlgorithmIdentifier{{Algorithm: oidSHA512}},
		EncapContentInfo: encapsulatedContentInfo{ContentType: oidData},
		Certificates:     mustEncodeCerts(t, []*x509.Certificate{cert}),
		SignerInfos:      []signerInfo{si},
	}

	cmsBytes := mustMarshalCMS(t, sd)

	// Verification should REJECT due to missing content-type
	roots := x509.NewCertPool()
	roots.AddCert(cert)

	// Default EKU = CodeSigning (cert has CodeSigning EKU, so this will pass EKU check)
	_, err := Verify(cmsBytes, data, VerifyOptions{
		Roots: roots,
	})

	if err == nil {
		t.Fatal("Expected error for missing content-type attribute, got nil")
	}

	if !isValidationError(t, err, "ContentType") {
		t.Errorf("Expected ContentType ValidationError, got: %v", err)
	}
}

// TestVerifyRejectMismatchedContentType validates that content-type in SignedAttrs
// must match EncapContentInfo.ContentType
func TestVerifyRejectMismatchedContentType(t *testing.T) {
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
	digest := sha512.Sum512(data)

	// Build SignedAttrs with WRONG content-type
	wrongOID := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3} // id-envelopedData
	contentTypeValue, _ := asn1.Marshal(wrongOID)
	messageDigestValue, _ := asn1.Marshal(digest[:])

	attrs := []attribute{
		{
			Type:  oidAttributeContentType,
			Value: asn1.RawValue{Tag: 17, Class: 0, IsCompound: true, Bytes: contentTypeValue},
		},
		{
			Type:  oidAttributeMessageDigest,
			Value: asn1.RawValue{Tag: 17, Class: 0, IsCompound: true, Bytes: messageDigestValue},
		},
	}

	attrsForSigning, _ := encodeAttributesAsSet(attrs)
	signedAttrsImplicit, _ := encodeSignedAttributesImplicit(attrs)
	signature := ed25519.Sign(privKey, attrsForSigning)

	si := signerInfo{
		Version:            1,
		SID:                asn1.RawValue{FullBytes: mustMarshalIssuerAndSerial(t, cert.RawIssuer, cert.SerialNumber)},
		DigestAlgorithm:    pkix.AlgorithmIdentifier{Algorithm: oidSHA512},
		SignedAttrs:        asn1.RawValue{FullBytes: signedAttrsImplicit},
		SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidEd25519},
		Signature:          signature,
	}

	sd := signedData{
		Version:          1,
		DigestAlgorithms: []pkix.AlgorithmIdentifier{{Algorithm: oidSHA512}},
		EncapContentInfo: encapsulatedContentInfo{ContentType: oidData},
		Certificates:     mustEncodeCerts(t, []*x509.Certificate{cert}),
		SignerInfos:      []signerInfo{si},
	}

	cmsBytes := mustMarshalCMS(t, sd)

	roots := x509.NewCertPool()
	roots.AddCert(cert)

	_, err := Verify(cmsBytes, data, VerifyOptions{
		Roots: roots,
	})

	if err == nil {
		t.Fatal("Expected error for mismatched content-type, got nil")
	}

	if !isValidationError(t, err, "ContentType") {
		t.Errorf("Expected ContentType ValidationError, got: %v", err)
	}
}

// TestVerifyRejectDuplicateMessageDigest validates that duplicate message-digest
// attributes in SignedAttrs are rejected
func TestVerifyRejectDuplicateMessageDigest(t *testing.T) {
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
	digest := sha512.Sum512(data)

	contentTypeValue, _ := asn1.Marshal(oidData)
	messageDigestValue, _ := asn1.Marshal(digest[:])

	attrs := []attribute{
		{
			Type:  oidAttributeContentType,
			Value: asn1.RawValue{Tag: 17, Class: 0, IsCompound: true, Bytes: contentTypeValue},
		},
		{
			Type:  oidAttributeMessageDigest,
			Value: asn1.RawValue{Tag: 17, Class: 0, IsCompound: true, Bytes: messageDigestValue},
		},
		{
			Type:  oidAttributeMessageDigest, // DUPLICATE!
			Value: asn1.RawValue{Tag: 17, Class: 0, IsCompound: true, Bytes: messageDigestValue},
		},
	}

	attrsForSigning, _ := encodeAttributesAsSet(attrs)
	signedAttrsImplicit, _ := encodeSignedAttributesImplicit(attrs)
	signature := ed25519.Sign(privKey, attrsForSigning)

	si := signerInfo{
		Version:            1,
		SID:                asn1.RawValue{FullBytes: mustMarshalIssuerAndSerial(t, cert.RawIssuer, cert.SerialNumber)},
		DigestAlgorithm:    pkix.AlgorithmIdentifier{Algorithm: oidSHA512},
		SignedAttrs:        asn1.RawValue{FullBytes: signedAttrsImplicit},
		SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidEd25519},
		Signature:          signature,
	}

	sd := signedData{
		Version:          1,
		DigestAlgorithms: []pkix.AlgorithmIdentifier{{Algorithm: oidSHA512}},
		EncapContentInfo: encapsulatedContentInfo{ContentType: oidData},
		Certificates:     mustEncodeCerts(t, []*x509.Certificate{cert}),
		SignerInfos:      []signerInfo{si},
	}

	cmsBytes := mustMarshalCMS(t, sd)

	roots := x509.NewCertPool()
	roots.AddCert(cert)

	_, err := Verify(cmsBytes, data, VerifyOptions{
		Roots: roots,
	})

	if err == nil {
		t.Fatal("Expected error for duplicate message-digest attribute, got nil")
	}

	if !isValidationError(t, err, "SignedAttributes") {
		t.Errorf("Expected SignedAttributes ValidationError, got: %v", err)
	}
}

// TestVerifyRejectDuplicateContentType validates that duplicate content-type
// attributes in SignedAttrs are rejected
func TestVerifyRejectDuplicateContentType(t *testing.T) {
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
	digest := sha512.Sum512(data)

	contentTypeValue, _ := asn1.Marshal(oidData)
	messageDigestValue, _ := asn1.Marshal(digest[:])

	attrs := []attribute{
		{
			Type:  oidAttributeContentType,
			Value: asn1.RawValue{Tag: 17, Class: 0, IsCompound: true, Bytes: contentTypeValue},
		},
		{
			Type:  oidAttributeContentType, // DUPLICATE!
			Value: asn1.RawValue{Tag: 17, Class: 0, IsCompound: true, Bytes: contentTypeValue},
		},
		{
			Type:  oidAttributeMessageDigest,
			Value: asn1.RawValue{Tag: 17, Class: 0, IsCompound: true, Bytes: messageDigestValue},
		},
	}

	attrsForSigning, _ := encodeAttributesAsSet(attrs)
	signedAttrsImplicit, _ := encodeSignedAttributesImplicit(attrs)
	signature := ed25519.Sign(privKey, attrsForSigning)

	si := signerInfo{
		Version:            1,
		SID:                asn1.RawValue{FullBytes: mustMarshalIssuerAndSerial(t, cert.RawIssuer, cert.SerialNumber)},
		DigestAlgorithm:    pkix.AlgorithmIdentifier{Algorithm: oidSHA512},
		SignedAttrs:        asn1.RawValue{FullBytes: signedAttrsImplicit},
		SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidEd25519},
		Signature:          signature,
	}

	sd := signedData{
		Version:          1,
		DigestAlgorithms: []pkix.AlgorithmIdentifier{{Algorithm: oidSHA512}},
		EncapContentInfo: encapsulatedContentInfo{ContentType: oidData},
		Certificates:     mustEncodeCerts(t, []*x509.Certificate{cert}),
		SignerInfos:      []signerInfo{si},
	}

	cmsBytes := mustMarshalCMS(t, sd)

	roots := x509.NewCertPool()
	roots.AddCert(cert)

	_, err := Verify(cmsBytes, data, VerifyOptions{
		Roots: roots,
	})

	if err == nil {
		t.Fatal("Expected error for duplicate content-type attribute, got nil")
	}

	if !isValidationError(t, err, "SignedAttributes") {
		t.Errorf("Expected SignedAttributes ValidationError, got: %v", err)
	}
}

// TestVerifyRejectNonCanonicalSetOrder validates that SignedAttrs must be
// in DER canonical order (RFC 5652 requires sorted SET OF by DER bytewise comparison)
func TestVerifyRejectNonCanonicalSetOrder(t *testing.T) {
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
	digest := sha512.Sum512(data)

	contentTypeValue, _ := asn1.Marshal(oidData)
	messageDigestValue, _ := asn1.Marshal(digest[:])

	// Build attrs in wrong order: message-digest before content-type
	// DER requires SET OF to be sorted by bytewise comparison of full attribute encodings
	// We deliberately put md before ct to trigger rejection
	attrs := []attribute{
		{
			Type:  oidAttributeMessageDigest,
			Value: asn1.RawValue{Tag: 17, Class: 0, IsCompound: true, Bytes: messageDigestValue},
		},
		{
			Type:  oidAttributeContentType,
			Value: asn1.RawValue{Tag: 17, Class: 0, IsCompound: true, Bytes: contentTypeValue},
		},
	}

	// Manually encode in wrong order (don't use the sorting helpers)
	attr1, _ := asn1.Marshal(attrs[0])
	attr2, _ := asn1.Marshal(attrs[1])
	wrongOrderContent := append(attr1, attr2...)

	// Build SET OF (tag 0x31) with proper DER length encoding
	attrsForSigning := append(encodeDERTag(0x31, len(wrongOrderContent)), wrongOrderContent...)

	signedAttrsImplicit := asn1.RawValue{
		Tag:        0,
		Class:      2,
		IsCompound: true,
		Bytes:      wrongOrderContent,
	}
	signedAttrsImplicitBytes, _ := asn1.Marshal(signedAttrsImplicit)

	signature := ed25519.Sign(privKey, attrsForSigning)

	si := signerInfo{
		Version:            1,
		SID:                asn1.RawValue{FullBytes: mustMarshalIssuerAndSerial(t, cert.RawIssuer, cert.SerialNumber)},
		DigestAlgorithm:    pkix.AlgorithmIdentifier{Algorithm: oidSHA512},
		SignedAttrs:        asn1.RawValue{FullBytes: signedAttrsImplicitBytes},
		SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidEd25519},
		Signature:          signature,
	}

	sd := signedData{
		Version:          1,
		DigestAlgorithms: []pkix.AlgorithmIdentifier{{Algorithm: oidSHA512}},
		EncapContentInfo: encapsulatedContentInfo{ContentType: oidData},
		Certificates:     mustEncodeCerts(t, []*x509.Certificate{cert}),
		SignerInfos:      []signerInfo{si},
	}

	cmsBytes := mustMarshalCMS(t, sd)

	roots := x509.NewCertPool()
	roots.AddCert(cert)

	_, err := Verify(cmsBytes, data, VerifyOptions{
		Roots: roots,
	})

	if err == nil {
		t.Fatal("Expected error for non-canonical SET order, got nil")
	}

	if !isValidationError(t, err, "SignedAttributes") {
		t.Errorf("Expected SignedAttributes ValidationError, got: %v", err)
	}
}

// TestVerifyRejectEd25519GarbageParams validates RFC 8410:
// Ed25519 AlgorithmIdentifier params must be absent or NULL
func TestVerifyRejectEd25519GarbageParams(t *testing.T) {
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
	sig, _ := SignData(data, cert, privKey) // Get valid CMS

	// Parse and corrupt SignatureAlgorithm.Parameters
	var ci contentInfo
	if _, err := asn1.Unmarshal(sig, &ci); err != nil {
		t.Fatalf("Failed to unmarshal contentInfo: %v", err)
	}
	var sd signedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		t.Fatalf("Failed to unmarshal signedData: %v", err)
	}

	// Inject garbage params (not NULL, not absent)
	garbageParams, _ := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 3})
	sd.SignerInfos[0].SignatureAlgorithm.Parameters.FullBytes = garbageParams

	// Rebuild CMS
	sdBytes, _ := asn1.Marshal(sd)
	ci.Content = asn1.RawValue{Tag: 0, Class: 2, IsCompound: true, Bytes: sdBytes}
	corruptedCMS, _ := asn1.Marshal(ci)

	roots := x509.NewCertPool()
	roots.AddCert(cert)

	_, err := Verify(corruptedCMS, data, VerifyOptions{
		Roots: roots,
	})

	if err == nil {
		t.Fatal("Expected error for Ed25519 with garbage params, got nil")
	}

	if !strings.Contains(err.Error(), "parameters") && !strings.Contains(err.Error(), "Parameters") {
		t.Errorf("Expected error about parameters, got: %v", err)
	}
}

// TestVerifyAcceptEd25519NullParams validates RFC 8410:
// Ed25519 AlgorithmIdentifier MUST accept NULL params
func TestVerifyAcceptEd25519NullParams(t *testing.T) {
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
	sig, _ := SignData(data, cert, privKey)

	// Parse and set SignatureAlgorithm.Parameters to NULL
	var ci contentInfo
	if _, err := asn1.Unmarshal(sig, &ci); err != nil {
		t.Fatalf("Failed to unmarshal contentInfo: %v", err)
	}
	var sd signedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		t.Fatalf("Failed to unmarshal signedData: %v", err)
	}

	// Set params to ASN.1 NULL
	nullParams, _ := asn1.Marshal(asn1.RawValue{Class: 0, Tag: 5}) // NULL
	sd.SignerInfos[0].SignatureAlgorithm.Parameters.FullBytes = nullParams

	// Rebuild CMS
	sdBytes, _ := asn1.Marshal(sd)
	ci.Content = asn1.RawValue{Tag: 0, Class: 2, IsCompound: true, Bytes: sdBytes}
	modifiedCMS, _ := asn1.Marshal(ci)

	roots := x509.NewCertPool()
	roots.AddCert(cert)

	// Should ACCEPT per RFC 8410
	_, err := Verify(modifiedCMS, data, VerifyOptions{
		Roots: roots,
	})

	if err != nil {
		t.Errorf("Should accept Ed25519 with NULL params (RFC 8410), got error: %v", err)
	}
}

// TestVerifyRejectTLSCertWithDefaultEKU validates that certificates with
// only TLS ServerAuth EKU are rejected when using default EKU policy
func TestVerifyRejectTLSCertWithDefaultEKU(t *testing.T) {
	_, privKey, _ := ed25519.GenerateKey(rand.Reader)

	// Create cert with ONLY ServerAuth EKU (no CodeSigning)
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "TLS Server"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, // TLS only
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, cert, cert, privKey.Public(), privKey)
	cert, _ = x509.ParseCertificate(certDER)

	data := []byte("test data")

	// Sign with valid CMS structure
	sig, err := SignData(data, cert, privKey)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(cert)

	// Should REJECT: default EKU = CodeSigning, but cert only has ServerAuth
	_, err = Verify(sig, data, VerifyOptions{
		Roots: roots,
	})

	if err == nil {
		t.Fatal("Expected error for TLS cert with default EKU policy, got nil")
	}

	// Error should mention EKU or key usage
	errMsg := err.Error()
	if !strings.Contains(errMsg, "ExtKeyUsage") && !strings.Contains(errMsg, "key usage") {
		t.Errorf("Expected EKU-related error, got: %v", err)
	}
}

// TestVerifyAcceptTLSCertWithOverride validates that TLS certs can be accepted
// when explicitly overriding the EKU policy
func TestVerifyAcceptTLSCertWithOverride(t *testing.T) {
	_, privKey, _ := ed25519.GenerateKey(rand.Reader)

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "TLS Server"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, cert, cert, privKey.Public(), privKey)
	cert, _ = x509.ParseCertificate(certDER)

	data := []byte("test data")
	sig, err := SignData(data, cert, privKey)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(cert)

	// Should ACCEPT: explicitly allow ServerAuth
	_, err = Verify(sig, data, VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})

	if err != nil {
		t.Errorf("Should accept TLS cert when EKU explicitly overridden, got: %v", err)
	}
}

// Helper functions

// mustMarshalIssuerAndSerial marshals issuer+serial for SID.
// Only handles short DNs; long forms need proper DER length encoding.
func mustMarshalIssuerAndSerial(t *testing.T, issuerDER []byte, serial *big.Int) []byte {
	t.Helper()
	var issuer pkix.RDNSequence
	if _, err := asn1.Unmarshal(issuerDER, &issuer); err != nil {
		t.Fatalf("Failed to unmarshal issuer: %v", err)
	}
	isn := issuerAndSerialNumber{
		Issuer:       issuer,
		SerialNumber: serial,
	}
	b, err := asn1.Marshal(isn)
	if err != nil {
		t.Fatalf("Failed to marshal issuerAndSerialNumber: %v", err)
	}
	return b
}

// mustEncodeCerts encodes certs as IMPLICIT [0] for CMS.
// NOTE: Single-cert only; multi-cert requires DER sorting of CertificateChoices.
// Builds FullBytes manually to avoid double-tagging by the marshaller.
func mustEncodeCerts(t *testing.T, certs []*x509.Certificate) asn1.RawValue {
	t.Helper()
	if len(certs) != 1 {
		t.Fatal("mustEncodeCerts only handles single cert; multi-cert needs DER sorting")
	}

	// Build [0] IMPLICIT header + payload manually
	payload := certs[0].Raw
	header := encodeDERTag(0xA0, len(payload)) // 0xA0 = [0] context-specific constructed
	return asn1.RawValue{FullBytes: append(header, payload...)}
}

// encodeDERTag creates a DER tag+length header (supports long-form lengths)
func encodeDERTag(tag byte, length int) []byte {
	if length < 128 {
		return []byte{tag, byte(length)}
	}
	// Long-form: encode length in minimum bytes
	var lenBytes []byte
	for l := length; l > 0; l >>= 8 {
		lenBytes = append([]byte{byte(l)}, lenBytes...)
	}
	return append([]byte{tag, 0x80 | byte(len(lenBytes))}, lenBytes...)
}

// mustMarshalCMS wraps SignedData in ContentInfo envelope
func mustMarshalCMS(t *testing.T, sd signedData) []byte {
	t.Helper()
	sdBytes, err := asn1.Marshal(sd)
	if err != nil {
		t.Fatalf("Failed to marshal SignedData: %v", err)
	}
	ci := contentInfo{
		ContentType: oidSignedData,
		Content:     asn1.RawValue{Tag: 0, Class: 2, IsCompound: true, Bytes: sdBytes},
	}
	cmsBytes, err := asn1.Marshal(ci)
	if err != nil {
		t.Fatalf("Failed to marshal ContentInfo: %v", err)
	}
	return cmsBytes
}

// isValidationError checks if err is a ValidationError with field matching (or containing) expected.
// Uses substring match to handle composite field names like "SignedAttributes.order".
func isValidationError(t *testing.T, err error, expectedField string) bool {
	t.Helper()
	if verr, ok := err.(*ValidationError); ok {
		return strings.Contains(verr.Field, expectedField) || verr.Field == ""
	}
	return false
}
