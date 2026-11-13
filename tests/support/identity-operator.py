"""Task-scoped DID/CIMD cleanup on the existing identity host; no service reconfiguration."""
import asyncio
import hashlib
import ast
import json
import re
import runpy
import sys
from datetime import datetime, timezone
from pathlib import Path

def validate(request):
    if not isinstance(request, dict) or request.get("action") not in {"preflight", "peers", "inspect", "observe", "cleanup"}:
        raise ValueError("scope")
    if request["action"] == "preflight":
        if set(request) != {"action"}:
            raise ValueError("scope")
        return
    if set(request) != {"action", "runId", "handle", "did"}:
        raise ValueError("scope")
    run = request["runId"]
    if not isinstance(run, str) or not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", run):
        raise ValueError("scope")
    if request["handle"] != "systestdw" + run.replace("-", "")[:16]:
        raise ValueError("scope")
    if not isinstance(request["did"], str) or not re.fullmatch(r"did:(?:wba|web):awiki\.me:[A-Za-z0-9_.:%-]+", request["did"]):
        raise ValueError("scope")

async def derive_protocol_scope(session, owner, settings, request):
    """Authorize only a fresh, single-document protocol identity from this exact run."""
    from sqlmodel import select
    now = owner["_utc"](datetime.now(timezone.utc))
    Handle, Document, User = owner["SQLModelHandle"], owner["SQLModelDIDDocument"], owner["SQLModelUser"]
    handles = (await session.exec(select(Handle).where(
        Handle.handle == request["handle"], Handle.domain == "awiki.me").with_for_update())).all()
    if len(handles) != 1:
        raise ValueError("protocol_handle_cardinality")
    handle = handles[0]
    users = (await session.exec(select(User).where(User.id == handle.user_id).with_for_update())).all()
    documents = (await session.exec(select(Document).where(Document.user_id == handle.user_id).with_for_update())).all()
    all_handles = (await session.exec(select(Handle).where(Handle.user_id == handle.user_id).with_for_update())).all()
    if len(users) != 1 or len(documents) != 1 or len(all_handles) != 1:
        raise ValueError("protocol_account_cardinality")
    user, document = users[0], documents[0]
    if (user.user_type != "local" or user.origin_type != "local" or user.status != "active"
        or handle.status != "active" or handle.did != request["did"]
        or handle.phone != settings.dev_otp_phone
        or any(getattr(handle, key) is not None for key in ("email", "ton_wallet_address", "telegram_user_id", "telegram_bot_id"))
        or document.did != request["did"] or document.status != "active" or not document.is_agent
        or document.role is not None or not isinstance(document.document, dict)
        or document.document.get("id") != request["did"]
        or not all(owner["_in_cleanup_window"](row.created_at, now=now) for row in (user, handle, document))):
        raise ValueError("protocol_identity_scope")
    dids = frozenset({request["did"]})
    # Protocol-only tests never provision message runtimes, join/recovery or push state.
    forbidden = [
        ("SQLModelJoinSession", "account_user_id", user.id),
        ("SQLModelRecoverySession", "account_user_id", user.id),
        ("SQLModelPushInstallation", "user_id", user.id),
        ("SQLModelDIDTransitionEdge", "user_id", user.id),
        ("SQLModelRootImportCompletion", "did", document.did),
    ]
    for model_name, field, value in forbidden:
        model = owner[model_name]
        if (await session.exec(select(model).where(getattr(model, field) == value).with_for_update())).first():
            raise ValueError("protocol_unexpected_lifecycle_resource")
    for model, field in [(Document, "did"), (Handle, "did")]:
        if (await session.exec(select(model).where(getattr(model, field) == document.did, model.user_id != user.id))).first():
            raise ValueError("protocol_cross_account_reference")
    from sqlalchemy import or_
    for model_name, fields in [
        ("SQLModelJoinSession", ("did",)),
        ("SQLModelRecoverySession", ("expected_old_did", "new_did")),
        ("SQLModelPushInstallation", ("owner_did",)),
        ("SQLModelDIDTransitionEdge", ("predecessor_did", "successor_did")),
    ]:
        model = owner[model_name]
        if (await session.exec(select(model).where(or_(
                *(getattr(model, field) == document.did for field in fields))).with_for_update())).first():
            raise ValueError("protocol_cross_account_reference")
    await owner["_require_no_external_cleanup_assets"](session, account_id=user.id, handle_id=handle.id, dids=dids)
    History = owner["SQLModelHandleHistory"]
    histories = (await session.exec(select(History).where(History.user_id == user.id).with_for_update())).all()
    owner["_require_closed_recovery_history"](histories, documents=documents, transition_edges=[], handle=handle, now=now)
    Identity, Credential = owner["SQLModelIdentity"], owner["SQLModelCredential"]
    identities = (await session.exec(select(Identity).where(Identity.user_id == user.id).with_for_update())).all()
    identity_ids = frozenset(row.id for row in identities)
    credentials = (await session.exec(select(Credential).where(Credential.identity_id.in_(tuple(identity_ids))).with_for_update())).all() if identity_ids else []
    exact = frozenset({user.id, document.did, request["handle"] + ".awiki.me"})
    Idempotency, Outbox = owner["SQLModelIdentityIdempotency"], owner["SQLModelIdentityOutbox"]
    idempotencies = await owner["_lock_cleanup_rows"](session, Idempotency,
        list((await session.exec(select(Idempotency))).all()),
        lambda row: owner["_json_references_cleanup_scope"](row.result, exact_values=exact, dids=dids))
    outboxes = await owner["_lock_cleanup_rows"](session, Outbox,
        list((await session.exec(select(Outbox))).all()),
        lambda row: row.aggregate_id in exact or owner["_json_references_cleanup_scope"](row.payload, exact_values=exact, dids=dids))
    Verification = owner["SQLModelVerification"]
    verifications = (await session.exec(select(Verification).where(or_(
        Verification.user_id == user.id,
        (Verification.identity_type == "phone") & (Verification.identity_value == handle.phone))))).all()
    verifications = await owner["_lock_cleanup_rows"](session, Verification, list(verifications),
        lambda row: row.user_id == user.id or (row.user_id is None and row.identity_type == "phone"
            and row.identity_value == handle.phone and row.purpose == "awiki.identity.register.v1"
            and row.target == request["handle"] + ".awiki.me"))
    return owner["_HandleRecoveryCleanupScope"](
        account_id=user.id, handle_id=handle.id, full_handle=request["handle"] + ".awiki.me",
        phone=handle.phone, dids=dids, transition_edge_ids=frozenset(),
        identity_ids=identity_ids, credential_ids=frozenset(row.id for row in credentials),
        verification_ids=frozenset(row.id for row in verifications),
        idempotency_ids=frozenset(row.id for row in idempotencies),
        identity_outbox_ids=frozenset(row.id for row in outboxes), root_completion_ids=frozenset())

async def execute(request):
    # The deployed service runs from this release's src tree; use that exact
    # installed owner runtime, never a workstation checkout or test replacement.
    release = Path("/opt/awiki/services/user-service/current").resolve(strict=True)
    sys.path.insert(0, str(release / "src"))
    from sqlalchemy import delete
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from sqlmodel import select
    from sqlmodel.ext.asyncio.session import AsyncSession
    from user_service.storage.sqlmodel.models.cimd import SQLModelClientPublication, SQLModelPapCallback
    owner_path = Path("/opt/awiki/services/user-service/current/scripts/run_account_state_sync_test_action.py")
    owner = runpy.run_path(str(owner_path))
    settings, _, _, _, _ = owner["_load_runtime_configuration"](Path("/etc/awiki/user-service.env"))
    if settings.did_hostname != "awiki.me" or settings.handle_domain != "awiki.me" or not settings.dev_otp_phone:
        raise ValueError("target")
    for function in ["_derive_handle_recovery_cleanup_scope", "_delete_handle_recovery_cleanup_scope", "_cleanup_residual_count"]:
        if not callable(owner.get(function)):
            raise ValueError("owner_version")
    engine = create_async_engine(settings.database_url, pool_pre_ping=True,
        connect_args={"init_command": "SET time_zone = '+00:00'"})
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    try:
        async with factory() as session:
            if request["action"] == "preflight":
                # Real schema/connection checks; no challenge, account or permission writes.
                for model in [owner["SQLModelHandle"], owner["SQLModelDIDDocument"], SQLModelClientPublication, SQLModelPapCallback]:
                    await session.exec(select(model).limit(0))
                return {"ready": True, "target": "https://awiki.me", "exactIdentityCleanup": True}
            async with session.begin():
                Handle, Document = owner["SQLModelHandle"], owner["SQLModelDIDDocument"]
                if request["action"] == "peers":
                    rows = (await session.exec(select(Handle.id, Handle.user_id, Handle.did).where(
                        Handle.phone == settings.dev_otp_phone, Handle.did != request["did"]))).all()
                    encoded = json.dumps(sorted(tuple(row) for row in rows), separators=(",", ":")).encode()
                    return {"otherHandleCount": len(rows), "otherHandlesDigest": hashlib.sha256(encoded).hexdigest()}
                handles = (await session.exec(select(Handle).where(
                    Handle.handle == request["handle"], Handle.domain == "awiki.me").with_for_update())).all()
                if not handles:
                    orphans = (await session.exec(select(Document).where(Document.did == request["did"]))).all()
                    if orphans:
                        raise ValueError("orphan_scope")
                    return {"matched": False} if request["action"] == "observe" else {"cleanupComplete": True, "accountsDeleted": 0}
                if len(handles) != 1 or handles[0].did != request["did"]:
                    raise ValueError("scope_not_found")
                handle = handles[0]
                if request["action"] == "inspect":
                    docs = (await session.exec(select(Document).where(Document.user_id == handle.user_id))).all()
                    now = owner["_utc"](datetime.now(timezone.utc))
                    return {"documents": [{"status": row.status, "isAgent": row.is_agent, "role": row.role,
                        "ownedDid": owner["_is_owned_cleanup_did"](row.did, "awiki.me"),
                        "documentMatches": isinstance(row.document, dict) and row.document.get("id") == row.did,
                        "recent": owner["_in_cleanup_window"](row.created_at, now=now)} for row in docs]}
                scope = await derive_protocol_scope(session, owner, settings, request)
                if scope is None or set(scope.dids) != {request["did"]}:
                    raise ValueError("scope")
                documents = (await session.exec(select(Document).where(
                    Document.user_id == handle.user_id).with_for_update())).all()
                document_ids = tuple(document.id for document in documents)
                callbacks = (await session.exec(select(SQLModelPapCallback).where(
                    SQLModelPapCallback.document_id.in_(document_ids)).with_for_update())).all()
                if callbacks:
                    raise ValueError("account_callback_cleanup_not_supported")
                publications = (await session.exec(select(SQLModelClientPublication).where(
                    SQLModelClientPublication.document_id.in_(document_ids)).with_for_update())).all()
                if any(not row.client_id.startswith("https://awiki.me/") for row in publications):
                    raise ValueError("publication_scope")
                if request["action"] == "observe":
                    return {"matched": True, "publicationVersions": len(publications)}
                # Retain the owning operator's account/phone/age/resource checks, and extend
                # deletion only to public material versions belonging to these exact DID rows.
                await session.exec(delete(SQLModelClientPublication).where(
                    SQLModelClientPublication.document_id.in_(document_ids)))
                await owner["_delete_handle_recovery_cleanup_scope"](session, scope=scope)
                if await owner["_cleanup_residual_count"](session, scope=scope):
                    raise ValueError("cleanup_unconfirmed")
                residual = (await session.exec(select(SQLModelClientPublication).where(
                    SQLModelClientPublication.document_id.in_(document_ids)))).all()
                if residual:
                    raise ValueError("cleanup_unconfirmed")
                return {"cleanupComplete": True, "accountsDeleted": 1, "publicationVersionsDeleted": len(publications)}
    finally:
        await engine.dispose()

if __name__ == "__main__":
    try:
        request = json.load(sys.stdin)
        validate(request)
        print(json.dumps(asyncio.run(execute(request))))
    except Exception as error:
        # Only the exception class is diagnostic; no settings, SQL, factors or payload values.
        reason = "unclassified"
        if type(error) is ValueError:
            source = Path("/opt/awiki/services/user-service/current/scripts/run_account_state_sync_test_action.py").read_text()
            literals = {node.args[0].value for node in ast.walk(ast.parse(source))
                        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                        and node.func.id == "ValueError" and node.args
                        and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)}
            if str(error) in literals:
                reason = str(error)
        print(json.dumps({"error": "identity_operator_failed", "category": type(error).__name__, "reason": reason}))
        sys.exit(1)
