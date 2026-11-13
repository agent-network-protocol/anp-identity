# End to end scenarios

Real DSH + DeepSeek scenarios and user UI actors are implemented here.
See [the acceptance instructions](../README.md). Missing planned cases are listed by the runner and cannot produce a passing full result.

ID-E01/ID-E02 use the actual shipped DSH Web profile and Chromium. The model requests
the creation entry; input, approval/OTP or rejection use the real product form/dialog.
Manager RPCs are read-only observations in this journey, not substitutes for UI
decisions. International E.164 factors use the product's full international-number
input; the actor never invents a dialing code or passes factors to the model.
ID-E01 preflights exact cleanup and saves its run-derived selector before UI
approval, then records the actual E1 DID including its root identifier before OTP
submission. Other factor owners must remain unchanged after teardown. The real
creation and rejection journeys have been verified with the protected configured
factor; future runs still require the actual target and cleanup preconditions.


ID-E03 and ID-E05 use a deterministically prepared, genuinely published identity;
they do not claim GUI creation coverage. The user actor selects that existing
identity in the actual Web settings. The real model calls `identity_status`, and
its final DID/publication answer must agree with the independent identity state.
No new creation request or factor challenge is allowed. ID-E05 stops and restarts
the actual Host, verifies a different PID, resumes the persisted model session,
and checks the same identity in the real UI again. User-factor contents are not
provided in model messages. GUI creation/approval belongs to ID-E01; UI grant
revocation belongs to ID-E04.

ID-E04 installs the identity acceptance consumer normally through the Loader.
Its model tool only requests ordinary identity access and reads a fixed public
protocol catalog with the real custody/HTTP implementation; it has no approval,
grant management or Provider API. The real browser actor chooses once/permanent
permission and revokes through product UI. On the next execution the previously
consumed grant is actually tried and rejected before fresh permission is requested.
After revocation the retained permanent object fails with zero additional sends.
The fixture tool is scoped identity-foundation evidence, not an ANP adapter E2E.
Registration of the initial identity is deterministic fixture preparation; it
does not replace ID-E01's GUI creation journey. The fixture starts anonymous
discovery at agent-network-protocol.com and requires the advertised official
Agent origin before requesting its fixed catalog read. It does not implement
the ANP adapter's full OpenAPI operation-reference discovery.
