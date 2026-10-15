# Scan impact report — `agent/scan-fixes` vs `main` (07bab18)

Branch: `agent/scan-fixes`, 11 tiny commits, all on top of `main`.
Tests: `go test` (all packages except slow `stream/internal`) green before and after.
This file is intentionally untracked — not committed.

## How to review

```sh
git log --oneline main..agent/scan-fixes
git show <hash>   # one fix per commit
```

## 1. Nil signature panics → remote DoS (fixed, verified)

Before: `Verify(msg, nil)` panicked with nil dereference.
After: returns `ErrInvalidSignature`.

- `4be2a07 eddsa: reject nil signature in Verify` — `eddsa/eddsa.go:362`
- `6a8147b mldsa: reject nil signature in Verify` — `mldsa/mldsa.go:426`
- `f76444e rsa: reject nil signature in Verify and VerifyHash` — `rsa/rsa.go:477,486`
- `3bcb563 xdsa: reject nil signature in Verify` — `xdsa/xdsa.go:498`

Impact: any path that forwards a lookup-miss or failed-decode signature
(`Signer()` → miss → `Verify`, `cose.Verify` → `verifier.Verify`) crashed
the process instead of returning an authentication failure. Attacker-influenced
`kid` + missing key = crash. Fail-closed now: caller gets a normal
verification error. Verified: reproducer panicked before, returns
`signature verification failed` after.

## 2. Nil session key panics in xHPKE (fixed)

- `e9c3a12 xhpke: reject nil session key in Open and NewReceiver` — `xhpke/xhpke.go:242,271`

Before: `sessionKey[:]` on nil panicked.
After: returns `ErrOpenFailed`.
Impact: same DoS shape on the decrypt path. `cose.Decrypt` length-checks
before copy so that path was already safe; direct `xhpke` API users were not.
No behavior change for valid inputs.

## 3. Nil verifier/recipient panics in COSE header checks (fixed)

- `856dfb2 cose: reject nil verifier and recipient in header checks` — `cose/cose.go:903,922`

Before: `verifier.Fingerprint()` / `recipient.Fingerprint()` panicked on nil.
After: returns `ErrUnexpectedKey`.
Impact: app doing `Signer(bytes)` → lookup miss → `Verify(..., nil, ...)`
crashed instead of “unknown key”. Remote `kid` controls the trigger.
Low severity (requires app to skip its own nil check), now defense-in-depth.

## 4. Swallowed marshal errors in COSE verify (fixed, hygiene)

- `df098cb cose: propagate Sig_structure marshal errors in verify` — `cose/cose.go:488,584`

Before: `toBeSigned, _ := cbor.Marshal(&sig)` ignored the error.
After: returns the error.
Impact: not exploitable today — `Context="Signature1"` is fixed,
`Protected`/`aad` are non-nil by construction, `Payload` is `[]byte{}` or
nil-checked, so marshal cannot fail. Risk was masking: a future struct change
could make marshal fallible, and verify would then run over nil bytes and
report `ErrInvalidSignature` instead of the real cause. No test change.

## 5. Negative array/map headers encoded as huge uint64 (fixed)

- `d22dce9 cbor: reject negative array and map header lengths` — `cbor/cbor.go:248`

Before: `uint64(-1)` → `0xFFFFFFFFFFFFFFFF`, peer decodes a giant header.
After: panics fast with `cbor: negative ... header length`.
Impact: programmer-error guard, not attacker bytes directly (internal callers
pass `len() >= 0`). Without it, a single bad caller emits a DoS-shaped
payload: peer allocates/loops on a bogus size. Panic is intentional here
(caller bug, fail fast locally instead of corrupting the wire).

## 6. Narrow-int silent truncation (fixed)

- `bd59bcf cbor: reject integer overflow for narrow int types` — `cbor/reflect.go:365,373`

Before: `reflect.SetUint(300)` into `uint8` silently stored `44` (verified).
After: returns `ErrIntegerOverflow` via `OverflowUint`/`OverflowInt`.
Impact: data corruption, not just style. A CBOR `300` decoded into
`struct { V uint8 }` previously succeeded with the wrong value; security
fields (counts, key ids, versions) could truncate past validation. Now it
fails loudly, consistent with existing `int64` overflow tests.

## 7. Unbounded nested decode → stack exhaustion (fixed)

- `a122f6d cbor: bound nested decode depth to maxDepth` — `cbor/reflect.go:318`

Before: `decodeValue` recursed with no counter; `maxDepth=32` only applied to
`skipObject`/`verifyObject` (`Raw` path).
After: `decodeValueDepth` returns `ErrMaxDepthExceeded` past 32.
Impact: deeply nested array/map/struct input to typed `Unmarshal` could grow
the Go stack far beyond the `Raw`/`Verify` budget. Now typed and raw paths
share the same bound. Valid inputs (depth ≤ 32) unaffected.

## 8. Nil/non-pointer decode target panic (fixed)

- `bb24295 cbor: reject nil and non-pointer decode targets` — `cbor/reflect.go:312`

Before: `Decode(nil)` / `Decode(nonPointer)` reached `reflect.New` on an
invalid value and panicked.
After: returns `ErrUnsupportedType`.
Impact: robustness only. Catches caller bugs at the API boundary instead of
a reflect panic. No change for correct callers.

## Deliberately not changed

- gstyle `nil_guard` on `cose/cose.go:477,573` (`maxDrift` vs `header`): false
  positive. `header` is `nil,err`-paired from `verifySigProtectedHeader`,
  deref is err-guarded. No commit.
- gstyle `deviant` on `stream/internal/stream.go:105,107` (`errors.New`/
  `fmt.Errorf` “unchecked”): false positive. Values are assigned to `r.err`,
  not discarded. No commit.
- `forcetypeassert` in `cwt/claims/confirm.go:108,121` and
  `SecretKey.PublicKey` asserts: constrained generics / stdlib invariants,
  not attacker-reachable. No commit.
- `ParsePublicKeyDER` clone divergence (`mldsa` vs `xdsa` vs `xhpke`):
  confirmed stylistic only. `mldsa65.UnmarshalBinary` length-checks; `0xFF`
  probes accepted without panic in all three. No commit.
- Stale-before-verify ordering and detached/embedded-empty equivalence in
  `cose`: real observations but protocol tradeoffs, left for maintainer
  decision. No commit.
