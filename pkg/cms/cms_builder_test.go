package cms

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- SKI is a PKIX identifier, not a security primitive
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

// cmsBuilder is an internal test-only harness that constructs CMS
// SignedData messages from scratch with explicit control over fields the
// production signer doesn't expose. It exists because the verifier's full
// behavioural surface — SKI-form SignerInfo, invalid version/SID pairs,
// non-default EncapContentInfo OIDs — cannot be exercised through the
// public SignData entry point.
//
// Two design rules:
//
//  1. The signature itself is always *real* — produced by ed25519 over
//     the canonical-DER SignedAttributes (Case 1) or directly over the
//     content (Case 2). Tests that probe verifier behaviour must observe
//     real cryptographic outcomes, not asn1-decode-passes-and-stops.
//  2. Every knob has a sensible default that yields a verify-clean CMS,
//     so tests can isolate exactly one deviation at a time.

// sidForm selects how SignerIdentifier is encoded inside SignerInfo.
//
//   - sidIAS: SEQUENCE { Issuer, SerialNumber } — RFC 5652 Case A,
//     SignerInfo.Version MUST be 1.
//   - sidSKI: [0] IMPLICIT OCTET STRING — RFC 5652 Case B,
//     SignerInfo.Version MUST be 3.
type sidForm int

const (
	sidIAS sidForm = iota
	sidSKI
)

// cmsBuildConfig collects every knob the builder exposes. Zero values
// resolve to verify-clean defaults; tests override only what they probe.
type cmsBuildConfig struct {
	// Data is the detached content the verifier will be asked to
	// reconstruct the digest of. Defaults to a short non-empty payload.
	Data []byte

	// SIDForm controls SignerIdentifier encoding (default: sidIAS).
	SIDForm sidForm

	// SIVersion overrides SignerInfo.Version. Zero means "derive from
	// SIDForm" (1 for IAS, 3 for SKI). Tests that want to probe mismatch
	// (e.g. SKI+version=1) set this explicitly.
	SIVersion int

	// SDVersion overrides SignedData.Version. Zero means default of 1.
	SDVersion int

	// EContentOID overrides EncapContentInfo.eContentType. Zero (nil)
	// means oidData (1.2.840.113549.1.7.1).
	EContentOID asn1.ObjectIdentifier

	// OmitAttrs produces a Case 2 (no signedAttributes) CMS when true.
	OmitAttrs bool

	// CorruptSKI replaces SKI bytes with garbage when SIDForm is sidSKI.
	// Used to test that matchesSID rejects key-id mismatch.
	CorruptSKI bool

	// SKIUseExplicit forces the EXPLICIT-wrapped encoding of the SKI SID
	// (`A0 <len> 04 <ski-len> <ski>`) instead of the canonical IMPLICIT
	// form. Used to verify the canonicality check in matchesSID.
	SKIUseExplicit bool
}

// newBuilderSigner returns a self-signed Ed25519 cert/key/pool whose
// cert has a populated SubjectKeyId (so SKI-form SignerInfo can match
// against it). Reusable across builder-driven tests.
func newBuilderSigner(tb testing.TB) (*x509.Certificate, ed25519.PrivateKey, *x509.CertPool) {
	tb.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		tb.Fatalf("ed25519.GenerateKey: %v", err)
	}
	// Compute a PKIX-standard SubjectKeyId (RFC 5280 §4.2.1.2 method 1:
	// 160-bit SHA-1 of the DER-encoded subjectPublicKey BIT STRING value).
	// SHA-1 is the IETF-blessed input here — it's an identifier, not a
	// security primitive. Go's auto-SKI only triggers for IsCA=true certs,
	// so we set it explicitly.
	skiSum := sha1.Sum(priv.Public().(ed25519.PublicKey)) // #nosec G401 -- see above
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0xc115),
		Subject:      pkix.Name{Organization: []string{"go-cms builder"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		SubjectKeyId: skiSum[:],
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	if err != nil {
		tb.Fatalf("x509.CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		tb.Fatalf("x509.ParseCertificate: %v", err)
	}
	if len(cert.SubjectKeyId) == 0 {
		tb.Fatal("cert has empty SubjectKeyId; SKI tests need a non-empty one")
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return cert, priv, pool
}

// buildTestCMS assembles a CMS SignedData blob byte-for-byte according
// to cfg, producing a *real* Ed25519 signature over the canonical SET OF
// SignedAttributes (Case 1) or directly over Data (Case 2).
//
// The returned bytes are intended to be passed straight to Verify; for
// happy-path inputs the verifier accepts them. Tests modify cfg one
// knob at a time to probe specific verifier branches.
func buildTestCMS(tb testing.TB, cert *x509.Certificate, priv ed25519.PrivateKey, cfg cmsBuildConfig) []byte {
	tb.Helper()

	// Resolve defaults.
	data := cfg.Data
	if data == nil {
		data = []byte("builder-default-content")
	}
	siVersion := cfg.SIVersion
	if siVersion == 0 {
		if cfg.SIDForm == sidSKI {
			siVersion = 3
		} else {
			siVersion = 1
		}
	}
	sdVersion := cfg.SDVersion
	if sdVersion == 0 {
		sdVersion = 1
	}
	eContentOID := cfg.EContentOID
	if eContentOID == nil {
		eContentOID = oidData
	}

	// 1. Compute SignedAttributes (Case 1) and sign.
	var signedAttrsImplicit []byte
	var signature []byte
	if cfg.OmitAttrs {
		signature = ed25519.Sign(priv, data)
	} else {
		digest := sha512.Sum512(data)
		attrs, err := createSignedAttributes(digest[:], time.Now().UTC())
		if err != nil {
			tb.Fatalf("createSignedAttributes: %v", err)
		}
		setBytes, err := encodeAttributesAsSet(attrs)
		if err != nil {
			tb.Fatalf("encodeAttributesAsSet: %v", err)
		}
		signature = ed25519.Sign(priv, setBytes)
		signedAttrsImplicit, err = encodeSignedAttributesImplicit(attrs)
		if err != nil {
			tb.Fatalf("encodeSignedAttributesImplicit: %v", err)
		}
	}

	// 2. Build SignerInfo.
	siBytes := encodeSignerInfo(tb, cert, signedAttrsImplicit, signature, oidSHA512, siVersion, cfg.SIDForm, cfg.CorruptSKI, cfg.SKIUseExplicit)

	// 3. Build the rest of the structure (SignedData + ContentInfo).
	return encodeOuterCMS(tb, cert, siBytes, oidSHA512, sdVersion, eContentOID)
}

// encodeSignerInfo emits the SignerInfo SEQUENCE according to cfg.
//
// SignerInfo ::= SEQUENCE {
//     version           CMSVersion,
//     sid               SignerIdentifier,
//     digestAlgorithm   DigestAlgorithmIdentifier,
//     signedAttrs       [0] IMPLICIT SignedAttributes OPTIONAL,
//     signatureAlgorithm SignatureAlgorithmIdentifier,
//     signature         SignatureValue }
func encodeSignerInfo(
	tb testing.TB,
	cert *x509.Certificate,
	signedAttrsImplicit []byte,
	signature []byte,
	digestOID asn1.ObjectIdentifier,
	version int,
	form sidForm,
	corruptSKI bool,
	skiUseExplicit bool,
) []byte {
	tb.Helper()
	var buf bytes.Buffer

	// Version INTEGER.
	mustMarshal(tb, &buf, version)

	// SignerIdentifier.
	switch form {
	case sidIAS:
		ias := struct {
			Issuer       pkix.RDNSequence
			SerialNumber *big.Int
		}{
			Issuer:       cert.Issuer.ToRDNSequence(),
			SerialNumber: cert.SerialNumber,
		}
		mustMarshal(tb, &buf, ias)

	case sidSKI:
		ski := cert.SubjectKeyId
		if corruptSKI {
			ski = bytes.Repeat([]byte{0xff}, len(ski))
		}
		if skiUseExplicit {
			// Non-canonical EXPLICIT [0] wrapping for malleability tests:
			// A0 <len> 04 <ski-len> <ski>. asn1.Marshal can't emit this
			// directly so we hand-build the TLV.
			buf.WriteByte(0xA0)
			buf.WriteByte(byte(2 + len(ski)))
			buf.WriteByte(0x04)
			buf.WriteByte(byte(len(ski)))
			buf.Write(ski)
		} else {
			// Canonical RFC 5652 §5.3 form: [0] IMPLICIT OCTET STRING —
			// the OCTET STRING tag is replaced by [0]. Tag byte 0x80
			// (context, primitive, tag 0), length, raw SKI bytes.
			buf.WriteByte(0x80)
			buf.WriteByte(byte(len(ski)))
			buf.Write(ski)
		}
	}

	// DigestAlgorithm.
	mustMarshal(tb, &buf, pkix.AlgorithmIdentifier{Algorithm: digestOID})

	// SignedAttrs [0] IMPLICIT (omitted for Case 2).
	if signedAttrsImplicit != nil {
		buf.Write(signedAttrsImplicit)
	}

	// SignatureAlgorithm.
	mustMarshal(tb, &buf, pkix.AlgorithmIdentifier{Algorithm: oidEd25519})

	// Signature OCTET STRING.
	mustMarshal(tb, &buf, signature)

	// Wrap in SEQUENCE.
	content := buf.Bytes()
	header := makeSequenceHeader(len(content))
	return append(header, content...)
}

// encodeOuterCMS wraps SignerInfo bytes into a full ContentInfo →
// SignedData → SignerInfos chain. Mirrors signer.buildCMS but with
// explicit version + eContentType control.
func encodeOuterCMS(
	tb testing.TB,
	cert *x509.Certificate,
	signerInfo []byte,
	digestOID asn1.ObjectIdentifier,
	sdVersion int,
	eContentOID asn1.ObjectIdentifier,
) []byte {
	tb.Helper()
	var sdBuf bytes.Buffer

	// Version.
	mustMarshal(tb, &sdBuf, sdVersion)

	// DigestAlgorithms SET OF AlgorithmIdentifier.
	digestAlgBytes, err := asn1.Marshal([]pkix.AlgorithmIdentifier{{Algorithm: digestOID}})
	if err != nil {
		tb.Fatalf("marshal digest algs: %v", err)
	}
	// asn1 emits SEQUENCE OF (0x30); CMS expects SET OF (0x31).
	if len(digestAlgBytes) > 0 && digestAlgBytes[0] == 0x30 {
		digestAlgBytes[0] = 0x31
	}
	sdBuf.Write(digestAlgBytes)

	// EncapContentInfo: SEQUENCE { eContentType, [0] EXPLICIT eContent OPTIONAL }
	// eContent omitted for detached signature.
	encap := struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
	}{ContentType: eContentOID}
	mustMarshal(tb, &sdBuf, encap)

	// Certificates [0] IMPLICIT — raw DER, no inner SET (matching the
	// signer's chosen encoding; OpenSSL rejects an inner SET here).
	certHeader := []byte{0xA0}
	cl := len(cert.Raw)
	switch {
	case cl < 128:
		certHeader = append(certHeader, byte(cl))
	case cl < 256:
		certHeader = append(certHeader, 0x81, byte(cl))
	case cl < 65536:
		certHeader = append(certHeader, 0x82, byte(cl>>8), byte(cl))
	default:
		tb.Fatalf("cert too large: %d bytes", cl)
	}
	sdBuf.Write(certHeader)
	sdBuf.Write(cert.Raw)

	// SignerInfos SET OF SignerInfo.
	siSetHeader := makeSetHeader(len(signerInfo))
	sdBuf.Write(siSetHeader)
	sdBuf.Write(signerInfo)

	// SignedData SEQUENCE.
	sdContent := sdBuf.Bytes()
	sdHeader := makeSequenceHeader(len(sdContent))
	signedData := append(sdHeader, sdContent...)

	// ContentInfo SEQUENCE { contentType id-signedData, content [0] EXPLICIT SignedData }
	var ciBuf bytes.Buffer
	mustMarshal(tb, &ciBuf, oidSignedData)

	// [0] EXPLICIT wraps the SignedData SEQUENCE.
	wrappedSD := wrapExplicitContext0(signedData)
	ciBuf.Write(wrappedSD)

	ciContent := ciBuf.Bytes()
	ciHeader := makeSequenceHeader(len(ciContent))
	return append(ciHeader, ciContent...)
}

// wrapExplicitContext0 produces "A0 <len> <inner>" — the EXPLICIT [0]
// wrapping around the SignedData SEQUENCE in ContentInfo.
func wrapExplicitContext0(inner []byte) []byte {
	header := []byte{0xA0} // context-specific, constructed, tag 0
	l := len(inner)
	switch {
	case l < 128:
		header = append(header, byte(l))
	case l < 256:
		header = append(header, 0x81, byte(l))
	case l < 65536:
		header = append(header, 0x82, byte(l>>8), byte(l))
	default:
		header = append(header, 0x83, byte(l>>16), byte(l>>8), byte(l))
	}
	return append(header, inner...)
}

// mustMarshal asn1.Marshals v and appends to buf, failing the test on
// error. Used internally to keep the builder code readable.
func mustMarshal(tb testing.TB, buf *bytes.Buffer, v any) {
	tb.Helper()
	b, err := asn1.Marshal(v)
	if err != nil {
		tb.Fatalf("asn1.Marshal(%T): %v", v, err)
	}
	buf.Write(b)
}
