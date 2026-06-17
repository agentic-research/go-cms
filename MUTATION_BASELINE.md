# Mutation Testing Baseline

This document inventories the mutants that the test suite does not kill, with a one-line justification for each category. CI enforces an 80% efficacy floor (see `.github/workflows/ci.yml`); new mutants outside the categories below should fail review.

> **This project has not been independently audited.** The work described here is internal hardening done by the maintainer with audit-equivalent methodology — fuzzing, mutation testing, named threat-class tests, RFC-clause-traceable tests. Treat this document as a *self-assessment*, not an external attestation.

## Methodology

- Tool: [`gremlins`](https://github.com/go-gremlins/gremlins)
- Command: `make mutation-test` (runs from `pkg/cms/` with `--timeout-coefficient 30`)
- Gate: `--threshold-efficacy 80` in the CI `mutation` job

## Current numbers (last measured 2026-06-17)

| Package | Killed | Lived | Not covered | Efficacy | Coverage |
|---|---|---|---|---|---|
| `pkg/cms` | 221 | 44 | 23 | **83.40%** | 92.01% |
| `pkg/cms/internal` | 18 | 0 | 2 | **100.00%** | 90.00% |

Run `make mutation-test` to reproduce; full output goes to stderr.

## Why we don't chase 100% on `pkg/cms`

Half the remaining mutants are unkillable without weakening the library. The lived/not-covered set decomposes into four categories.

### Category A — Logically equivalent (cannot be killed; ~15 mutants)

The mutation produces code that's semantically identical to the original.

| Example | Why it's equivalent |
|---|---|
| `signer.go:212` — `if opts.DigestAlgorithm != 0 && opts.DigestAlgorithm != SHA512` | RFC 8419 always-override-anyway: code uses SHA-512 regardless. Mutating either `!=` to `==` doesn't change observable behavior. |
| `parseASN1Length` overflow detection `length < 0` | Belt-and-suspenders against integer overflow. The earlier `numBytes > 4` check already prevents triggering it on 64-bit platforms. |

These mutants would only be "killable" by deleting the defense-in-depth code. We keep the code.

### Category B — Defensive bounds (effectively unreachable; ~12 mutants)

The mutation flips a comparison whose true value requires an input the test suite refuses to construct: ≥2 GB ASN.1 inputs, malformed lengths past `parseASN1Length`'s upstream sanity checks.

Triggering these mutants in tests would mean instantiating multi-gigabyte allocations on every test run. The CI cost (slow tests, brittle infrastructure) outweighs the bug-catching value.

### Category C — Error-message format strings (~5 mutants)

Mutants in `errors.go` that change the wording of an error string. Production callers should not depend on error string content; behavioral assertions in the test suite check for `errors.Is/As` matches, not substrings.

### Category D — Genuine boundary cases (~10 mutants, addressable)

Specific input sizes our tests don't naturally hit (e.g. a SignerInfo whose total length lands at exactly 65,536 bytes). These are the *only* category where additional tests would meaningfully improve mutation efficacy.

We don't pursue them because the bug-finding return is low — the existing length-boundary tests (`length_boundary_test.go`) already cover the load-bearing branches in `makeSequenceHeader`/`makeSetHeader`, and the remaining mutants live in fully-tested code that the mutation tool's boundary-flipping heuristic struggles to distinguish from the original.

## Promotion criteria

If a *new* lived mutant appears in CI that isn't covered by Categories A–D above:

1. Read the mutant's location. Identify what behavior it perturbs.
2. If it represents a real bug surface → add a test that kills it.
3. If it falls under one of the categories above → update this file with the new instance.
4. Never bump the CI threshold down to accommodate a regression; raise tests up instead.

## What this baseline does not capture

- **Cryptographic primitive correctness** (Ed25519, SHA-256/384/512): covered by Go stdlib's own test suite plus our `TestRFC8032TestVectors` regression check, not by mutation testing.
- **Side-channel resistance**: not tested by mutation. Constant-time properties are checked by code review and `subtle.ConstantTimeCompare`/`crypto/subtle` usage audits.
- **OpenSSL interop**: covered by `make docker-test`, not by mutation.
- **Supply chain**: covered by `gosec`, `govulncheck`, pinned action SHAs, and `go.mod` minimum version (1.25.5).
