use super::{IdentityTransitionJournal, IdentityTransitionJournalState};
use serde_json::json;

#[test]
fn legacy_provider_document_is_read_but_never_written() {
    let journal = IdentityTransitionJournal::new(
        "operation-1".to_owned(),
        "did:wba:example.com:users:alice:e1_old".to_owned(),
        "identity-old".to_owned(),
        1,
        "did:wba:example.com:users:alice:e1_new".to_owned(),
        "identity-new".to_owned(),
        1,
        json!({"id": "did:wba:example.com:users:alice:e1_old"}),
        json!({"id": "did:wba:example.com:users:alice:e1_old"}),
        json!({"id": "did:wba:example.com:users:alice:e1_new"}),
        "predecessor-digest".to_owned(),
        "successor-digest".to_owned(),
        "unverified".to_owned(),
        "2026-09-03T00:00:00Z".to_owned(),
    );

    let mut encoded = serde_json::to_value(&journal).expect("serialize current journal");
    assert!(encoded.get("provider_document").is_none());
    encoded["provider_document"] = json!({"id": "did:wba:example.com"});

    let decoded: IdentityTransitionJournal =
        serde_json::from_value(encoded).expect("read legacy provider document");
    assert!(decoded._legacy_provider_document.is_some());
    assert_eq!(decoded.state, IdentityTransitionJournalState::Prepared);
    assert!(serde_json::to_value(decoded)
        .expect("serialize migrated journal")
        .get("provider_document")
        .is_none());
}
