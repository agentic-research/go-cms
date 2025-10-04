// Package cms provides CMS/PKCS#7 signature generation and verification with Ed25519 support.
package cms

import (
	"fmt"
)

// SignatureError provides detailed information about signature verification failures
type SignatureError struct {
	Type    string // Type of signature (binding, request, CMS, etc.)
	Reason  string // Human-readable reason for failure
	Wrapped error  // Underlying error
}

func (e *SignatureError) Error() string {
	if e.Wrapped != nil {
		return fmt.Sprintf("signature error (%s): %s: %v", e.Type, e.Reason, e.Wrapped)
	}
	return fmt.Sprintf("signature error (%s): %s", e.Type, e.Reason)
}

func (e *SignatureError) Unwrap() error {
	return e.Wrapped
}

// NewSignatureError creates a new SignatureError
func NewSignatureError(sigType, reason string, wrapped error) *SignatureError {
	return &SignatureError{
		Type:    sigType,
		Reason:  reason,
		Wrapped: wrapped,
	}
}

// KeyError provides detailed information about key operation failures
type KeyError struct {
	Operation string // Operation that failed (generate, load, verify, etc.)
	KeyType   string // Type of key (master, ephemeral, etc.)
	Wrapped   error  // Underlying error
}

func (e *KeyError) Error() string {
	if e.Wrapped != nil {
		return fmt.Sprintf("key error (%s %s): %v", e.Operation, e.KeyType, e.Wrapped)
	}
	return fmt.Sprintf("key error (%s %s)", e.Operation, e.KeyType)
}

func (e *KeyError) Unwrap() error {
	return e.Wrapped
}

// NewKeyError creates a new KeyError
func NewKeyError(operation, keyType string, wrapped error) *KeyError {
	return &KeyError{
		Operation: operation,
		KeyType:   keyType,
		Wrapped:   wrapped,
	}
}

// ValidationError represents validation failures
type ValidationError struct {
	Field   string // Field that failed validation
	Value   string // Value that was invalid (if safe to include)
	Reason  string // Why it's invalid
	Wrapped error  // Underlying error
}

func (e *ValidationError) Error() string {
	if e.Value != "" {
		return fmt.Sprintf("validation error: field %s with value '%s' is invalid: %s", e.Field, e.Value, e.Reason)
	}
	return fmt.Sprintf("validation error: field %s is invalid: %s", e.Field, e.Reason)
}

func (e *ValidationError) Unwrap() error {
	return e.Wrapped
}

// NewValidationError creates a new ValidationError
func NewValidationError(field, value, reason string, wrapped error) *ValidationError {
	return &ValidationError{
		Field:   field,
		Value:   value,
		Reason:  reason,
		Wrapped: wrapped,
	}
}
