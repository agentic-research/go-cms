package cms

import "testing"

// TestParseASN1LengthRejectsNonCanonical asserts that parseASN1Length rejects
// non-canonical DER length encodings. DER (RFC 5652 §10.1 mandates DER for
// SignedAttributes) requires:
//
//   - Short form (single byte, value < 128) when the length fits.
//   - Long form (0x8N followed by N bytes) only for lengths >= 128, using
//     the minimum number of bytes (no leading zero bytes).
//
// Without these checks, an attacker can re-encode any length byte in a CMS
// blob from short form to long form, producing structurally distinct but
// cryptographically valid alternate forms of the same message — a
// malleability bypass that breaks content-addressing or duplicate detection
// guarantees built on top of the CMS blob hash.
func TestParseASN1LengthRejectsNonCanonical(t *testing.T) {
	// Each case is a length encoding followed by enough payload bytes that
	// the bounds check passes — so the only reason for rejection should be
	// non-canonical encoding.
	cases := []struct {
		name  string
		input []byte
	}{
		{"long-form for value 0 (must use short)", []byte{0x81, 0x00}},
		{"long-form for value 5 (must use short)", append([]byte{0x81, 0x05}, make([]byte, 5)...)},
		{"long-form for value 127 (must use short)", append([]byte{0x81, 0x7f}, make([]byte, 127)...)},
		{"long-form for value 128 with leading zero", append([]byte{0x82, 0x00, 0x80}, make([]byte, 128)...)},
		{"long-form for value 256 with leading zero", append([]byte{0x83, 0x00, 0x01, 0x00}, make([]byte, 256)...)},
		{"long-form four-byte with leading zero", append([]byte{0x84, 0x00, 0x00, 0x01, 0x00}, make([]byte, 256)...)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := parseASN1Length(tc.input, 0)
			if err == nil {
				t.Errorf("parseASN1Length accepted non-canonical DER encoding %x; RFC 5652 §10.1 requires DER for SignedAttributes", tc.input)
			}
		})
	}
}

// TestParseASN1LengthAcceptsCanonical confirms valid DER length encodings
// are still accepted after the strictness check is added.
func TestParseASN1LengthAcceptsCanonical(t *testing.T) {
	cases := []struct {
		name   string
		input  []byte
		length int
	}{
		{"short-form 0", []byte{0x00}, 0},
		{"short-form 5", []byte{0x05, 1, 2, 3, 4, 5}, 5},
		{"short-form 127", append([]byte{0x7f}, make([]byte, 127)...), 127},
		{"long-form 128", append([]byte{0x81, 0x80}, make([]byte, 128)...), 128},
		{"long-form 255", append([]byte{0x81, 0xff}, make([]byte, 255)...), 255},
		{"long-form 256", append([]byte{0x82, 0x01, 0x00}, make([]byte, 256)...), 256},
		{"long-form 65535", append([]byte{0x82, 0xff, 0xff}, make([]byte, 65535)...), 65535},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			length, _, err := parseASN1Length(tc.input, 0)
			if err != nil {
				t.Errorf("parseASN1Length rejected canonical DER encoding %x: %v", tc.input[:min(len(tc.input), 8)], err)
				return
			}
			if length != tc.length {
				t.Errorf("parseASN1Length returned length %d, expected %d", length, tc.length)
			}
		})
	}
}
