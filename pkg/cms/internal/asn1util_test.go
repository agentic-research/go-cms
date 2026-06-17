package internal

import (
	"bytes"
	"encoding/asn1"
	"testing"
)

// These tests close the largest remaining mutation-testing coverage gap
// on the package: gremlins runs against pkg/cms/ and could not see any
// tests that linked the pkg/cms/internal/ package, so every mutant in
// the three Marshal*Header helpers and MarshalSafe registered as NOT
// COVERED. The helpers are functionally parallel to makeSequenceHeader /
// makeSetHeader in pkg/cms/signer.go (themselves tested in
// pkg/cms/length_boundary_test.go), so the same boundary-table approach
// applies here.
//
// Test cases probe both sides of every DER length-form boundary
// (X.690 §8.1.3.4) so a `<` ↔ `<=` mutation produces a detectable
// difference.

var lengthCases = []struct {
	length int
	encLen []byte // length-encoding bytes (no tag)
}{
	{0, []byte{0x00}},
	{1, []byte{0x01}},
	{126, []byte{0x7e}},
	{127, []byte{0x7f}},
	{128, []byte{0x81, 0x80}},
	{129, []byte{0x81, 0x81}},
	{254, []byte{0x81, 0xfe}},
	{255, []byte{0x81, 0xff}},
	{256, []byte{0x82, 0x01, 0x00}},
	{257, []byte{0x82, 0x01, 0x01}},
	{65534, []byte{0x82, 0xff, 0xfe}},
	{65535, []byte{0x82, 0xff, 0xff}},
	{65536, []byte{0x83, 0x01, 0x00, 0x00}},
	{65537, []byte{0x83, 0x01, 0x00, 0x01}},
}

// TestMarshalSequenceHeader asserts byte-exact DER SEQUENCE headers at
// and around every length-form boundary.
func TestMarshalSequenceHeader(t *testing.T) {
	for _, tc := range lengthCases {
		t.Run(lengthName(tc.length), func(t *testing.T) {
			got := MarshalSequenceHeader(tc.length)
			want := append([]byte{0x30}, tc.encLen...)
			if !bytes.Equal(got, want) {
				t.Errorf("MarshalSequenceHeader(%d) = % x, want % x", tc.length, got, want)
			}
		})
	}
}

// TestMarshalSetHeader asserts byte-exact DER SET headers at and around
// every length-form boundary.
func TestMarshalSetHeader(t *testing.T) {
	for _, tc := range lengthCases {
		t.Run(lengthName(tc.length), func(t *testing.T) {
			got := MarshalSetHeader(tc.length)
			want := append([]byte{0x31}, tc.encLen...)
			if !bytes.Equal(got, want) {
				t.Errorf("MarshalSetHeader(%d) = % x, want % x", tc.length, got, want)
			}
		})
	}
}

// TestMarshalImplicitHeader asserts byte-exact DER [0] IMPLICIT headers
// at and around every length-form boundary. Used by the signer's
// signedAttributes wrapping (0xA0 tag for IMPLICIT context-specific 0).
func TestMarshalImplicitHeader(t *testing.T) {
	for _, tc := range lengthCases {
		t.Run(lengthName(tc.length), func(t *testing.T) {
			got := MarshalImplicitHeader(tc.length)
			want := append([]byte{0xA0}, tc.encLen...)
			if !bytes.Equal(got, want) {
				t.Errorf("MarshalImplicitHeader(%d) = % x, want % x", tc.length, got, want)
			}
		})
	}
}

// TestMarshalSafe asserts MarshalSafe is a faithful pass-through to
// asn1.Marshal — same outputs, same errors. The helper exists as a
// single seam for future hardening (e.g. depth limits) and we test the
// current behavior so any future divergence is intentional and visible.
func TestMarshalSafe(t *testing.T) {
	cases := []struct {
		name  string
		value any
	}{
		{"int", 42},
		{"bool", true},
		{"byteslice", []byte{0x01, 0x02, 0x03}},
		{"oid", asn1.ObjectIdentifier{1, 3, 101, 112}},
		{"string", "hello"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotSafe, errSafe := MarshalSafe(c.value)
			gotDirect, errDirect := asn1.Marshal(c.value)
			if (errSafe == nil) != (errDirect == nil) {
				t.Fatalf("MarshalSafe err=%v vs asn1.Marshal err=%v", errSafe, errDirect)
			}
			if !bytes.Equal(gotSafe, gotDirect) {
				t.Errorf("MarshalSafe(% q) = % x; asn1.Marshal = % x", c.name, gotSafe, gotDirect)
			}
		})
	}
}

// TestConstants pins the package's documented size limits. Changing
// these values is a security-relevant decision (it shifts the DoS
// resistance envelope), so the test exists to force the change through
// code review.
func TestConstants(t *testing.T) {
	if MaxSignatureSize != 1024*1024 {
		t.Errorf("MaxSignatureSize = %d, want %d (1MB)", MaxSignatureSize, 1024*1024)
	}
	if MaxCertSize != 64*1024 {
		t.Errorf("MaxCertSize = %d, want %d (64KB)", MaxCertSize, 64*1024)
	}
	if SigTypeCMS != "cms" {
		t.Errorf("SigTypeCMS = %q, want %q", SigTypeCMS, "cms")
	}
}

// lengthName turns a length into a stable subtest name covering every
// boundary case.
func lengthName(length int) string {
	switch length {
	case 0:
		return "len_0_empty"
	case 1:
		return "len_1"
	case 126:
		return "len_126_below_short_max"
	case 127:
		return "len_127_short_max"
	case 128:
		return "len_128_long1_min"
	case 129:
		return "len_129"
	case 254:
		return "len_254_below_long1_max"
	case 255:
		return "len_255_long1_max"
	case 256:
		return "len_256_long2_min"
	case 257:
		return "len_257"
	case 65534:
		return "len_65534_below_long2_max"
	case 65535:
		return "len_65535_long2_max"
	case 65536:
		return "len_65536_long3_min"
	case 65537:
		return "len_65537"
	default:
		return "len_arbitrary"
	}
}
