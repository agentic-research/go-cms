package cms

import (
	"bytes"
	"testing"
)

// These tests exercise the DER length-encoding boundaries in
// makeSequenceHeader and makeSetHeader (signer.go). Each `if length < N`
// boundary survived mutation testing before this file because every
// integration test happens to sit on one side of every boundary — Case 1
// signatures always produce SET sizes in a specific range that doesn't
// flip when a `<` becomes `<=`.
//
// The fix is direct table tests on the helpers with byte-exact expected
// output at both sides of each boundary. The byte sequences come straight
// from RFC 5280 §4.2.1.1 / X.690 §8.1.3.4:
//
//   length         encoding
//   0..127         (short form)              one byte: length
//   128..255       (long form, 1 octet)      81 <length>
//   256..65535     (long form, 2 octets)     82 <high> <low>
//   65536..2^24-1  (long form, 3 octets)     83 <hi> <mid> <low>
//
// We test the immediate neighbours of every boundary so a `<` ↔ `<=`
// mutation produces an output difference our table check will catch.

var lengthEncodingCases = []struct {
	length int
	encLen []byte // length-encoding bytes only (no tag byte)
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

// TestMakeSequenceHeaderBoundaries asserts byte-exact DER SEQUENCE
// headers at and around every length-encoding boundary. Kills the
// CONDITIONALS_BOUNDARY mutants at signer.go:879/881/883 (and the
// matching CONDITIONALS_NEGATION variants).
func TestMakeSequenceHeaderBoundaries(t *testing.T) {
	for _, tc := range lengthEncodingCases {
		t.Run(headerCaseName(tc.length), func(t *testing.T) {
			got := makeSequenceHeader(tc.length)
			want := append([]byte{0x30}, tc.encLen...) // SEQUENCE tag + length
			if !bytes.Equal(got, want) {
				t.Errorf("makeSequenceHeader(%d) = % x, want % x", tc.length, got, want)
			}
		})
	}
}

// TestMakeSetHeaderBoundaries: same probes for the SET helper. Kills the
// CONDITIONALS_BOUNDARY mutants at signer.go:895/897/899.
func TestMakeSetHeaderBoundaries(t *testing.T) {
	for _, tc := range lengthEncodingCases {
		t.Run(headerCaseName(tc.length), func(t *testing.T) {
			got := makeSetHeader(tc.length)
			want := append([]byte{0x31}, tc.encLen...) // SET tag + length
			if !bytes.Equal(got, want) {
				t.Errorf("makeSetHeader(%d) = % x, want % x", tc.length, got, want)
			}
		})
	}
}

// TestMakeHeader_Roundtrip cross-checks our header output against the
// strict parser the verifier uses: every header makeSequenceHeader emits
// must parse cleanly via parseASN1Length and yield the input length back.
// Catches drift between the producer and consumer sides.
func TestMakeHeader_Roundtrip(t *testing.T) {
	for _, tc := range lengthEncodingCases {
		t.Run(headerCaseName(tc.length), func(t *testing.T) {
			header := makeSequenceHeader(tc.length)
			// parseASN1Length needs trailing bytes that satisfy the
			// length check (it validates "length <= remaining"). Pad
			// with zeros sized to match the declared length.
			full := append(header, make([]byte, tc.length)...)
			gotLen, newPos, err := parseASN1Length(full, 1) // skip tag byte
			if err != nil {
				t.Fatalf("parseASN1Length rejected our header for length %d: %v", tc.length, err)
			}
			if gotLen != tc.length {
				t.Errorf("parseASN1Length round-trip: got length %d, want %d", gotLen, tc.length)
			}
			if newPos != len(header) {
				t.Errorf("parseASN1Length newPos %d, want %d (header length)", newPos, len(header))
			}
		})
	}
}

// headerCaseName turns a length into a stable subtest name.
func headerCaseName(length int) string {
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
