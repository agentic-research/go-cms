// Package internal provides shared internal utilities for the CMS package.
package internal

import "encoding/asn1"

// MarshalSequenceHeader creates a SEQUENCE header with the given length.
// Returns the DER-encoded tag and length bytes for a SEQUENCE.
func MarshalSequenceHeader(length int) []byte {
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

// MarshalSetHeader creates a SET header with the given length.
// Returns the DER-encoded tag and length bytes for a SET.
func MarshalSetHeader(length int) []byte {
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

// MarshalImplicitHeader creates an IMPLICIT [0] tag header with the given length.
// Returns the DER-encoded tag and length bytes for IMPLICIT [0] (tag 0xA0).
func MarshalImplicitHeader(length int) []byte {
	header := []byte{0xA0} // Context-specific, constructed, tag 0
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

// MarshalSafe wraps asn1.Marshal with explicit error checking.
// This helper is used throughout the CMS package to ensure all ASN.1
// encoding operations properly handle errors.
func MarshalSafe(v interface{}) ([]byte, error) {
	return asn1.Marshal(v)
}
