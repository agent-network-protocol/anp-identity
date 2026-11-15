# Windows registration recovery verification

Run dates: 2026-11-09 through 2026-11-10 (Asia/Shanghai). This records client regressions and acceptance gates; it is
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
- An uncertain flow now performs at most one signed, read-only device Registry
  check per controller. It exposes only closed outcomes and numeric HTTP/RPC
  status. It never registers, saves credentials, adopts a document, or changes
  the uncertain result to success. The existing manager/provider fence remains
  authoritative; ordinary contexts cannot acquire this inspection.

## Validation

Windows, Node 22.22.3: build, API snapshot/type checks, and generated-artifact
checks passed. After restoring the ignored native binding from the exact
published Windows dependency (version 0.2.6, verified SHA-256), the complete
plugin tests initially passed with 354 tests. After the read-only inspection
change, the final complete run passed: 40 files passed, 11 skipped; 362 tests
passed, 19 skipped.
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

The verified 0.1.16 candidate resumed the same approved request and reached SMS
verification. After owner OTP submission, the public DID endpoint returned 200
with the matching DID, but the local journal retained registerStarted=true and
registered=false, with no stored management credential ciphertext. Desktop still
reported registration_uncertain and not published. CIMD and authenticated
ANP/MCP/PAP business reads remain blocked. No OTP or account details were
collected in chat, and no repeated registration request was issued.

The real Desktop candidate's signed device_registry_get inspection returned
HTTP 401. An anonymous read-only baseline also returned 401 / JSON-RPC -32000;
its error mentioned Bearer, Token and Authorization. The client contract uses
HTTP Message Signatures without Bearer fallback. An independent
@awiki/anp-typescript-sdk 0.9.4 verifier accepted the equivalent native 0.2.6
signature from a generated isolated identity. This suggests deployed server
authentication-contract incompatibility, but server traces are still needed for
final attribution. Public DID availability alone is not a registration receipt.

ANP source regressions: 14 passed. PAP related Windows regressions: 49 passed
after test portability fixes and a test-process OpenSSL PATH adjustment. Shared
MCP domain/once/consent regressions: 37 passed on Node 24.21.0; its candidate
package compiled and bundled. The complete matching source Host built through
all eight artifact gates and ran on Windows. Actual Loader state and tool registry
confirmed the domain entry and all four tool families; the real module path and
hash were recorded. No business tool was invoked. Directly overlaying the fork
package onto the released Desktop had earlier caused duplicate registrations;
the failed package tree/lock were retained and the Desktop dependency layout was
restored. These source Host checks are separate from Desktop business acceptance.

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
and cannot recover an initialized or uncertain remote operation. Local recovery
and diagnostic changes were verified in the actual Desktop candidate; real
publication and downstream business validation remain blocked by the 401.
The referenced shared awiki-harness rule checkout was absent, so local source,
tests and repository instructions were used.

The [Chinese acceptance report](windows-acceptance-20261109.zh-CN.md) records the
step-by-step outcomes, preserved failures, attribution limits and server handoff.
