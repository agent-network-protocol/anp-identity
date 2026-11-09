Behavioral guidelines to reduce common LLM coding mistakes. Merge with project-specific instructions as needed.

**Tradeoff:** These guidelines bias toward caution over speed. For trivial tasks, use judgment.

## 1. Think Before Coding

**Don't assume. Don't hide confusion. Surface tradeoffs.**

Before implementing:
- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them - don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what's confusing. Ask.

## 2. Simplicity First

**Minimum code that solves the problem. Nothing speculative.**

- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.
- Prefer reliable existing libraries or patterns over reinventing the wheel.
- If you write 200 lines and it could be 50, rewrite it.

Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes, simplify.

## 3. Surgical Changes

**Touch only what you must. Clean up only your own mess.**

When editing existing code:
- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it - don't delete it.

When your changes create orphans:
- Remove imports/variables/functions that YOUR changes made unused.
- Don't remove pre-existing dead code unless asked.

The test: Every changed line should trace directly to the user's request.

## 4. Goal-Driven Execution

**Define success criteria. Loop until verified.**

Transform tasks into verifiable goals:
- "Add validation" → "Write tests for invalid inputs, then make them pass"
- "Fix the bug" → "Write a test that reproduces it, then make it pass"
- "Refactor X" → "Ensure tests pass before and after"

For multi-step tasks, state a brief plan:
```
1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]
```

Strong success criteria let you loop independently. Weak criteria ("make it work") require constant clarification.

---

**These guidelines are working if:** fewer unnecessary changes in diffs, fewer rewrites due to overcomplication, and clarifying questions come before implementation rather than after mistakes.

# Repository Guidelines

## Shared rules

Engineering work follows [AI Coding Rules](../../awiki-harness/rules/ai-coding-rules.md).
Behavior changes and verification follow the relevant [Verification Policy](../../awiki-harness/rules/verification-policy.md)
sections; production behavior needs owning unit coverage and applicable System/product E2E review.
If Harness is absent, use local docs/tests/CI and disclose missing acceptance evidence.

- Support E1 and rootless Web identity creation, device enrollment/adoption, and
  normal document/device changes. Web has no DID RootControl, Root Import,
  root transfer, or recovery. The Store encryption root remains method-independent.
  Do not add K1, PlainLegacy, P-256 legacy E2EE,
  general backup, root-provider rekey, or root-control rotation. The approved private-key
  egress exception is the default-off `root-export` Rust API used by the
  existing `RootKeyEnvelopeV1` transfer flow. Do not generalize it to other key
  roles or expose it through the default Node binding. The user-approved
  `pin-recovery` Rust-only exception permits single-root PIN backup and
  operation-bound pending recovery as specified in [the custody contract](docs/pin-root-recovery.md).
  This exception does not expose root material through Node or Dart.
- Keep all comments, documentation comments, errors, and logs in English.
- Except for the explicit Rust root-key export, private key material must never
  appear in a public API output, FFI export, serialized DTO, debug output, or
  error message. The root export and Rust import inputs must use zeroizing
  raw/DER bytes, be non-serializable and non-`Debug`, and never use ordinary
  `String` PEM.
- All mutating storage paths must take the store's cross-process exclusive lock
  and use generation/CAS checks. Recovery and orphan cleanup follow the same rule.
- `PublicationUncertain` may only transition through reconcile. It must never
  expose a direct abort path.
- Keep tests in dedicated files unless private helper access requires a small
  unit test. Shared Verification Policy defines coverage and product E2E ownership.
- Prefer the existing `anp` crate and the referenced im-core vault code over
  duplicate cryptographic or storage implementations.
- Keep `key-import` as a permanent, default-off feature and exclude it from the
  default Node binding. General migration import is allowed only while the
  target identity does not exist and must verify every private key against the
  DID document public method before committing.
- Root transfer senders emit the existing `RootKeyEnvelopeV1` format only. The
  Rust host must explicitly enable `root-export` and preserve its
  user-confirmation gate before calling the root export. Do not add format
  negotiation or automatic wrapped/legacy fallback.
- A Rust host may receive an authenticated legacy `RootKeyEnvelopeV1` and pass
  its root key through the dedicated zeroizing legacy-root ingress. That path is
  receive-only, requires an existing rootless identity with the same pinned
  root fingerprint and verified transfer evidence, and must never persist the
  plaintext in a persistent DTO, journal, log, or temporary file. A malformed
  or unknown wrapped envelope must never be retried through the legacy parser.
