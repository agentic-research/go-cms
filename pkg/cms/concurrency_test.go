package cms

import (
	"bytes"
	"sync"
	"testing"
)

// TestVerifyConcurrent asserts that Verify is safe to call concurrently
// against the same CMS blob and trust pool. A bug here — any hidden shared
// state, package-level cache, or mutable type passed by value-of-pointer —
// would surface either as a race (under `go test -race`) or a verification
// inconsistency across goroutines.
//
// Run with: go test -race ./pkg/cms -run TestVerifyConcurrent
func TestVerifyConcurrent(t *testing.T) {
	cert, priv, pool := newFuzzSigner(t)
	opts := VerifyOptions{Roots: pool}

	data := []byte("concurrent verify invariant")
	sig, err := SignData(data, cert, priv)
	if err != nil {
		t.Fatalf("SignData: %v", err)
	}

	const (
		goroutines    = 32
		perGoroutine  = 200
		totalAttempts = goroutines * perGoroutine
	)

	var wg sync.WaitGroup
	failures := make(chan error, totalAttempts)

	for range goroutines {
		wg.Go(func() {
			for range perGoroutine {
				certs, err := Verify(sig, data, opts)
				if err != nil {
					failures <- err
					return
				}
				if len(certs) == 0 || !bytes.Equal(certs[0].Raw, cert.Raw) {
					failures <- errInconsistentResult
					return
				}
			}
		})
	}
	wg.Wait()
	close(failures)

	for err := range failures {
		t.Errorf("concurrent Verify failed: %v", err)
		return
	}
}

// TestSignConcurrent asserts that SignData is safe to call concurrently with
// the same key+cert. Ed25519 signing is deterministic, so all outputs of the
// Case 2 path should be byte-identical. Concurrent Case 1 outputs will
// differ in the signing-time attribute but each must independently verify.
func TestSignConcurrent(t *testing.T) {
	cert, priv, pool := newFuzzSigner(t)
	opts := VerifyOptions{Roots: pool}

	data := []byte("concurrent sign invariant")

	const goroutines = 32

	t.Run("case2_deterministic", func(t *testing.T) {
		baseline, err := SignDataWithoutAttributes(data, cert, priv)
		if err != nil {
			t.Fatalf("SignDataWithoutAttributes baseline: %v", err)
		}

		var wg sync.WaitGroup
		mismatches := make(chan int, goroutines)

		for range goroutines {
			wg.Go(func() {
				sig, err := SignDataWithoutAttributes(data, cert, priv)
				if err != nil {
					mismatches <- -1
					return
				}
				if !bytes.Equal(sig, baseline) {
					mismatches <- len(sig)
				}
			})
		}
		wg.Wait()
		close(mismatches)

		for n := range mismatches {
			t.Errorf("concurrent Case 2 sign produced non-deterministic output (len=%d)", n)
		}
	})

	t.Run("case1_each_verifies", func(t *testing.T) {
		var wg sync.WaitGroup
		failures := make(chan error, goroutines)

		for range goroutines {
			wg.Go(func() {
				sig, err := SignData(data, cert, priv)
				if err != nil {
					failures <- err
					return
				}
				if _, err := Verify(sig, data, opts); err != nil {
					failures <- err
				}
			})
		}
		wg.Wait()
		close(failures)

		for err := range failures {
			t.Errorf("concurrent Case 1 sign+verify failed: %v", err)
			return
		}
	})
}

// errInconsistentResult is a sentinel returned through the failures channel
// when a concurrent Verify returns the wrong cert. Defined as a package-level
// value so the test reporter prints a stable message.
var errInconsistentResult = inconsistentResultErr{}

type inconsistentResultErr struct{}

func (inconsistentResultErr) Error() string {
	return "Verify returned inconsistent cert across goroutines"
}
