# Windows registration recovery verification

Run date: 2026-11-09. This records client regressions and acceptance gates; it is
not a declaration that a public identity or three-protocol business flow passed.

## Observed defects and changes

- Windows synthesizes POSIX stat mode bits. Applying Unix group/other-bit checks
  to a Windows state directory or encrypted credential file prevented normal
  registration from advancing. Unix checks remain enforced; Windows relies on
  the owner-controlled directory ACL. Credential reads also reject non-files
  and symbolic links.
- An owner onboarding record could permanently block a new form after the
  creation ledger confirmed deletion of its identity. Startup now archives only
  a matching approved protocol-creation request with a deleted result and no
  existing execution directory. The private owner record is retained, the
  version advances under the store lock, and stale writers fail CAS. A new form
  and creation approval are still required.
- Existing execution state, missing deletion evidence, unavailable providers,
  and uncertain publication do not qualify for archival or replay.
- The owner page and public status expose stable failure categories, including
  storage failure and deleted identity, without credential/provider details.
- The service-settings test retains persistence/CAS coverage on Windows and
  restricts only its POSIX permission assertions to POSIX platforms.

## Validation

Windows, Node 22.22.3: build, API snapshot/type checks, and generated-artifact
checks passed. After restoring the ignored native binding from the exact
published Windows dependency (version 0.2.6, verified SHA-256), the complete
plugin tests passed: 39 files passed, 11 skipped; 354 tests passed, 19 skipped.
The skipped Linux/live tests are not product acceptance evidence. Initial
missing-binding errors and the Windows-only mode assertion failure were retained
in the local run record rather than treated as product defects.

Regression coverage includes owner input retention, stale/concurrent archive
writers, initialized flows without a journal, absent deletion evidence, unavailable
providers, UI reason projection, and platform-specific private-mode semantics.

## Product acceptance status

The Windows Desktop test uses a new data home with registry Identity 0.1.16,
ANP 0.1.4 and PAP 0.1.4. Its owner-only ACL was inspected. The original personal
data home and its awiki.me registration were not migrated or overwritten.
The new registration preference was confirmed in the actual owner page as
`https://awiki.info`, with no identity present at the recorded baseline. Public
JSON-RPC invalid-request probes confirm reachability only; registration/account
compatibility still requires a successful dedicated test registration.

Publication, Handle/DID/CIMD verification, and authenticated ANP/MCP/PAP business
reads remain gated on owner verification. No OTP or account details are collected
in chat, and no repeated registration request is issued to guess an outcome.

ANP source regressions: 14 passed. PAP related Windows regressions: 49 passed
after test portability fixes and a test-process OpenSSL PATH adjustment. Shared
MCP domain/once/consent regressions: 37 passed on Node 24.21.0; its candidate
package compiled and bundled. The released Desktop MCP package lacks the fork's
domain entry, so its presence must be verified after actual candidate loading.
These source checks are separate from Desktop business acceptance.

The existing isolated Service Agent was restarted with its dedicated PostgreSQL
container. Certificate-verified local readiness and public metadata returned 200;
unauthenticated business routes were rejected. Public-only domain/TLS restrictions
remain in effect: this loopback development service cannot be counted as a
production Desktop domain connection. Authenticated writes and cross-protocol
readback were not executed.

External posting and Matchall requirement publication are outside authorization.
External discovery probes do not establish authenticated document reads, a
Matchall draft, or matching-result retrieval. All such missing business evidence
must remain explicitly blocked or unexecuted in the final report.

## Remaining risk

Windows ACL security is separate from POSIX mode bits; this patch does not audit
or repair arbitrary directory ACLs. Recovery depends on trusted ledger evidence
and cannot recover an initialized or uncertain remote operation. The fresh
Desktop candidate still needs product validation; unit results do not replace it.
The referenced shared awiki-harness rule checkout was absent, so local source,
tests and repository instructions were used.
