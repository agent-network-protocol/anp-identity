# Shared protocol management

This branch adds one Identity-owned Protocol Management settings section for installed ANP, PAP and MCP adapters. It replaces the PAP manual connection navigation, not the stored connections, credentials, identities or authorization history. Installation order does not create a second section. Identity creation/publication remains in Identity Management.

## Owner policy and persistence

Read and write each select `allow_all`, `whitelist`, `ask` or `deny`. Defaults are declared reads allowed and writes asked. Whitelist entries contain an exact IDNA hostname and explicit protocols; the outside behavior is either ask or deny. There is no suffix, wildcard or implicit subdomain matching. An adapter must retain the original discovery origin and validate the graph that binds it to the actual service destination. A service directory entry is never a whitelist grant.

The additive `manager-settings/protocol-access.json` document has schema 1 and a monotonic version. Updates require the owner's manager Context and expected version, use a cross-process exclusive lock and atomic rename, and preserve restrictive filesystem permissions. Malformed settings fail closed and are not overwritten with defaults. No private keys, tokens, operation bodies or generic signing permissions are stored here. Any policy edit invalidates earlier execution admissions, including pending approvals. Explicit operation disables, disconnected sessions and identity-ledger refusals remain independent fences.

Older plugins do not implement these rules. Disable managed protocol adapters before downgrading; keeping the settings file alone cannot make an older client enforce a new deny rule. Use Identity 0.1.15 or later together with PAP 0.1.4 and ANP 0.1.4; do not mix these adapters with an older Identity Host. Runtime capability checks reject an absent shared policy API rather than silently falling back to old write behavior. MCP also requires the matching Harness domain connector implementation (commit 194aaf492e or a compatible successor); installing these npm plugins alone does not update the official MCP client.

## Operation classification

The Host classifier uses protocol semantics, not a model-supplied operation label. HTTP methods are checked together with declared request bodies, authorization requirements, optional `x-agent-effect` (`read`, `write`, `unknown`, `payment`) and optional `x-agent-annotations` boolean hints (`readOnlyHint`, `destructiveHint`, `paymentHint`). This supports explicitly declared read-only POST queries. Conflicting or malformed semantics cannot become automatic reads. OAuth scopes or malformed security requirements remain additional privileges. A declared payment, unknown effect or additional privilege always asks unless its governing rule denies it, even under all-write permission.

MCP classification uses actual advertised tool hints rather than its POST transport or the tool name. A read requires affirmative `readOnlyHint: true` and `destructiveHint: false`; conflicting or missing hints are not automatic reads. Protocol metadata cannot prove a remote implementation has no undisclosed side effects: the service remains responsible for accurate declarations, and the owner's all-write choice is a broad authorization.

## Execution boundary

The manager Remote exposes only owner query/update methods. Installed adapters bind a separate policy facade that cannot edit settings, approve requests or obtain native keys. Opaque per-adapter targets bind the validated discovery origin and exact destination origins. Every admission is checked again after asynchronous identity, token or signing work and immediately before transport.

PAP uses the shared rule for every business request, including previously enabled reads. Allowed writes do not create permanent route permissions. Ask uses the existing exact once-only owner dialog; deny sends no business request. Discovery preserves the original origin through redirects and refreshes from that origin. A once-approved or policy-allowed mutation is not automatically replayed after a session/token/nonce response. Errors distinguish no business transport attempt, unknown outcome and received HTTP response.

ANP propagates the original origin through the complete directory → description → interface → operation graph. The Host prepares an admission and independently rechecks it during the exact dispatch. Ask consumes the actual once grant; allow uses only the validated operation under current policy. Both paths retain native DID authentication and public-only transport. Generic authorized HTTP leases for managed protocol consumers are rejected so an old client cannot bypass the new gate. Explicit legacy ANP origin restrictions remain additional fences; when none is configured, the global domain opt-in uses the managed public-HTTPS boundary rather than requiring per-domain configuration.

The official MCP domain connector uses logical and physical request checks, minimum advertised read-scope selection, exact original-domain binding and execution-local native signers. Non-domain configured connections are not implicitly managed and are explicitly labeled. The installed local candidate passed real reads and writes through all three protocols on both listed services, including local deny and original-domain whitelist cases. These results do not imply an npm publication or remote deployment. Matching candidate artifacts are identified by integrity and source/file digests; final registry versions are a separate release step.

## Focused evidence

Run the owning policy, manager, navigation and adapter tests. Cross-repository native components require the adapters' built artifacts and explicit source roots:

```sh
# Build dsh-pap and dsh-anp first. From this package:
DSH_SHARED_PRODUCT_F_SOURCE=/absolute/path/to/dsh-pap \
DSH_SHARED_ANP_SOURCE=/absolute/path/to/dsh-anp \
DSH_SHARED_HARNESS_SOURCE=/absolute/path/to/dsh-harness-identity \
npx vitest run test/pap-retry-native.spec.ts test/anp-policy-native.spec.ts test/mcp-policy-native.spec.ts
```

Those components use real native custody, the actual Host ledger/policy and isolated remote HTTP. They are not live-service or UI acceptance. Cases skip without their explicit source roots, so a default package test run does not establish this evidence. The batch-1 PAP artifact is a negative control: its retry/once phase passes but its persistent all-write assertion fails. Real public writes must still be correlated with the actual protocol response and readback; uncertain writes are never retried automatically.

## Agent configuration tools (third-batch candidate)

The installed owner manager registers two purpose-specific tools when the real Tools and Agent Registry services are available:

- `protocol_permissions({action:"get"})` reads the same policy and adapter state as this page. `action:"set"` requires `expectedVersion` and complete `policy.read` / `policy.write` rules. Read before changing and preserve unrelated settings.
- `identity_settings({action:"get"})` reads public identities, the saved default and registration service. `action:"set_default"` requires that preference's `expectedVersion` and the exact returned published `identityId` (the Host resolves the complete DID/reference), or `identity:null` for automatic selection. `action:"set_registration_service"` requires the registration setting's version and a canonical HTTPS origin. It affects future registrations only; existing identities and in-progress flows retain their service pins.

Every tool mutation opens one in-session owner approval with the exact persistent before/after values. An absent answerer, rejection, cancellation, detached/forged Agent, delegated mutation, disabled manager or stale setting version prevents the write. This is confirmation of a persistent configuration change, not repeated approval of every business operation. A saved write allowance subsequently follows the shared policy without redundant business dialogs. Payment, unknown effects, extra privileges, existing denials and generic signing remain separate. No `approve:true`, caller/consumer override, OTP, token, private key or lifecycle mutation is accepted. Queries need no confirmation. The normal DSH session stores the tool call, versioned change result and paired approval audit; these contain public settings only, never credentials. A lost result must be reconciled by querying, not blindly replayed.

`manager-settings/default-identity.json` is an additive schema-1 CAS preference under the same protected cross-process storage boundary. A missing file preserves the profile's configured default; saved `null` explicitly chooses automatic selection. Multiple eligible candidates or an unavailable saved identity fail closed without substitution. Merely selecting a display row in Identity Management does not save a default. Every saved change advances the default admission epoch, including changing back to an earlier identity; identity-specific encrypted storage remains unchanged. New explicit PAP/MCP connections adopt the new epoch while old in-flight operations retain their identity fences. No identities, keys, sessions, tokens or old grants are erased by changing the default.

The page and Agent use the same owner backend. UI drafts survive external version changes and cannot silently overwrite them. Identity creation/publication/deletion, approvals, OTP entry, Host adapter installation/enablement, key custody and generic signing are intentionally not configuration-tool actions. Runtime capability checks and final package/live Agent acceptance are required before treating the candidate as installed or released.
