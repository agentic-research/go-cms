// Package internal provides shared internal utilities for the CMS package.
package internal

// Signature and operation type constants
const (
	SigTypeCMS     = "cms"
	OpSign         = "sign"
	OpVerify       = "verify"
	KeyTypePublic  = "public"
	KeyTypePrivate = "private"
)

// Size limits for CMS structures
const (
	// MaxSignatureSize is the maximum allowed CMS signature size (1MB)
	// This prevents memory exhaustion attacks from malformed signatures
	MaxSignatureSize = 1024 * 1024

	// MaxCertSize is the maximum allowed certificate size (64KB)
	// Standard X.509 certificates are typically 1-4KB
	MaxCertSize = 64 * 1024
)
