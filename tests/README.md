# DSH identity acceptance tests

System scenarios belong to `tests/system/`; real DSH + DeepSeek browser journeys belong to `tests/e2e/`.
The repository owns its runner, assertions and fixtures. These tests do not use
`awiki-system-test`, import sibling source modules, or change shared DSH profiles.

This suite is being implemented. `--list` distinguishes executable scenarios from
`not_implemented`. Selecting a missing case or running the incomplete full suite
returns a nonzero status; absence of tests is never a pass.

## Running

Use Node >=24.9, the current Harness CLI and the ordinary npm install prerequisites.
Run the following commands from `packages/dsh-anp-identity`:

```sh
npm run test:acceptance-support
npm run test:system -- --list
npm run test:system -- --case ID-S04
npm run test:e2e -- --list
```

`DSH_CLI` selects the built DSH CLI bin (default: the sibling independent Harness).
`AWIKI_IDENTITY_PACKAGE` selects an absolute identity-plugin candidate tarball or
an exact published identity-plugin version. When omitted, this repository builds and packs its own identity plugin.
The subject candidate is built and packed into a protected temporary directory.

S01 records the subject tarball SHA-256, installed entry hashes, exact identity
version and npm integrity, plus the actual native platform package, binary path,
version and SHA-256. Native wrapper/platform versions must agree. The evidence
is a native node:test diagnostic on the current OS/architecture; it creates no
separate result archive and does not imply cross-platform acceptance.

Installation uses normal npm resolution with scripts disabled, preserving peer
dependency checks. A candidate/Host mismatch is a failure, not a reason to force
installation or change public version numbers.

The deterministic controller is a private fixture installed by the actual Loader.
Only its parent's IPC channel can request ordinary consumer or user manager actions.
It registers no model tools or network listener. This is system-test control,
not the browser actor required for E2E.
The separately installed ordinary consumer used by ID-E04 registers only the
read-only acceptance tool described in `e2e/README.md`; it has no manager capability.

## Legacy evidence ownership

| Existing entry | Ownership decision and boundary |
|---|---|
| `packages/dsh-anp-identity/test/` and native bindings tests | Retain owning unit/component and compatibility checks; their fixtures do not establish awiki.me or model acceptance. |
| `packages/dsh-anp-identity/scripts/run-functional-e2e.mjs` | Retain the local HTTPS-verifier/legacy Host integration entry. Its localhost certificate/verifier contract differs from these public-service and real-model journeys; it is not called by the new runners or counted as a remote pass. |
| Existing `awiki-system-test/tests_v2/dsh_identity/test_public_identity_mcp.py` | Its ordered creation phase establishes the AS-unknown-client precondition for the subsequent MCP admission/expiry/restart journey on a separate identity-testing target. Retain that MCP integration prerequisite; these new identity/ANP/PAP runners neither import it nor copy its MCP/AS assertions. No MCP coverage is claimed here. |

## Protected factors and fixed destinations

`AWIKI_TEST_FACTOR_FILE` selects the protected AWiki Me YAML (fields `otp.phone`
and `otp.code`) or an explicit dotenv (only `DEV_OTP_PHONE` and `DEV_OTP_CODE`).
The default is the existing `~/awiki-space/awiki-me/tests/e2e/configs/e2e.local.yaml`.
Files must be owned by the invoking user, have no group/other permissions, and
must not be symlinks. `AWIKI_E2E_OTP_PHONE` and `AWIKI_E2E_OTP_CODE` override
as a complete pair. Missing explicit input never falls back to another file.

Identity requests go to `https://awiki.me`. Discovery begins at
`https://agent-network-protocol.com`; discovered origins are checked by the
actual Host. Service URLs, DB configuration and unrelated credentials in the
factor file are never inherited. The configured phone, OTP, tokens and private
keys must not be printed, recorded in prompts, snapshots or command arguments.

## Planned coverage

These are implementation locations, not a passing full-run report. Run `--list`
for the current executable selection and use the native result for test outcomes.

| Case | Scenario | Implementation / remaining gap |
|---|---|---|
| ID-S01 | Candidate installation | `system/authorization.test.mjs` |
| ID-S02 | E1 registration and publication | `system/publication.test.mjs` |
| ID-S03 | Rootless Web registration | `system/publication.test.mjs`; target server-info currently advertises Web creation disabled |
| ID-S04 | Creation denial/cancellation | `system/authorization.test.mjs` |
| ID-S05 | Once-only authorization | `system/authorization.test.mjs` |
| ID-S06 | Retained grant revocation | `system/authorization.test.mjs` |
| ID-S07 | Actual Host restart | `system/authorization.test.mjs` |
| ID-S08 | Separate consumers and signing purposes | `system/consumer-isolation.test.mjs`; E1/Web parameterized; Web creation currently disabled by target |
| ID-S09 | Uncertain publication reconciliation | `system/publication-uncertain.test.mjs`; explicit response fault; same Web prerequisite |
| ID-S10 | Public output secrecy and exact cleanup | `system/output-cleanup.test.mjs` |
| ID-E01 | Model-driven creation with UI approval | `e2e/creation.spec.mjs`; real UI supports international E.164 factors |
| ID-E02 | Model creation rejected through UI | `e2e/creation.spec.mjs`; real UI rejection before registration |
| ID-E03 | Reuse an existing identity | `e2e/reuse.spec.mjs`; actual model and UI selection |
| ID-E04 | UI once approval and revocation | `e2e/authorization.spec.mjs`; real model, ordinary consumer and product approval UI |
| ID-E05 | Model session and identity after restart | `e2e/reuse.spec.mjs`; actual process restart and persisted session |

## Output and cleanup boundary

ID-S08 installs two independent ordinary consumers through the real Loader. The
ANP-role consumer uses an approved HTTP grant; the PAP-role consumer uses a
task-owned static Host policy and real native delegated keys. It checks cross-caller
grant rejection, PAP Session/DPoP key-purpose rejection and independent lease/grant
revocation. This is identity-foundation evidence; it does not replace the owning
ANP/PAP adapter wire or model tests. Both E1 and Web are declared; focused E1 runs
cannot establish Web coverage. The fixture checks the public awiki.me server-info
before registration. An advertised disabled method fails with
`acceptance_target_web_creation_disabled` before starting a Host or issuing OTP.

ID-S09 explicitly buffers the real HTTPS DID RPC response in the current DSH's
Undici 8 consumer callback, up to 128 KiB. After the real CIMD prepare step, one
successful DID-binding receipt is delivered as invalid JSON. Signing and remote
storage are unchanged. The fault must report applied; then public manager retry
must recover publication without another successful document-update receipt.
Compact credentials and response bytes never leave the controller. An unsupported
transport fails the case instead of silently omitting the fault.

ID-S10 checks ordinary public output, published metadata/JWKS, and raw captured
CLI output for the configured factor, private-key PEM, compact assertions and the
model API key. Output checks accumulate in memory from startup and return booleans
only; they do not export offending bytes. After exact teardown, the publication
must be unavailable and the fixture verifies that other factor owners are unchanged.
This is scoped to the Node/CLI outputs and public DTOs exercised by the case; it
does not claim an exhaustive native-memory or operating-system secret audit.

Unit/fixture checks are separate from installed-Host system evidence and real-model
E2E evidence. The local custody scenarios do not claim remote registration or publication.
Each runtime has a private temporary DSH home and state. Restart tests stop and
reopen the same state with a new process. Teardown waits for the actual child to
exit before removing owned files; failure does not authorize killing other processes.

Live registration and writes require an exact cleanup route before creation.
Uncertain writes are queried, never replayed. Do not bulk-delete identities by phone.
Preserve only necessary private recovery input if cleanup remains unresolved.

Use native runner output and concise failure diagnostics. Do not create
`verification-runs/`, replacement archives or execution indexes. Full acceptance
receives a concise final HTML report according to workspace rules after all
implementation is complete; focused checks are reported directly.
