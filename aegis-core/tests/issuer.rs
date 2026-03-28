use std::sync::Arc;
use std::time::Duration;

use aegis_core::{
    Action, AegisError, Constraints, Ed25519TokenSigner, InMemoryTokenStore, IssuerConfig,
    ParamConstraint, Resource, TokenIssuer, TokenSigner, TokenStore,
};

fn make_issuer() -> TokenIssuer<Ed25519TokenSigner, InMemoryTokenStore> {
    let signer = Ed25519TokenSigner::generate();
    let store = Arc::new(InMemoryTokenStore::new());
    let config = IssuerConfig::default();
    TokenIssuer::new(signer, store, config)
}

fn make_request() -> aegis_core::TokenRequest {
    aegis_core::TokenRequest {
        subject: "alice".to_string(),
        resource: Resource::new("file:///data/reports").unwrap(),
        actions: vec![Action::Read],
        constraints: Constraints::new(),
        ttl: Some(Duration::from_secs(600)),
        delegatable: false,
        max_uses: None,
    }
}

// ── Valid issuance ──────────────────────────────────────────────────────

#[test]
fn issue_valid_token() {
    let issuer = make_issuer();
    let signed = issuer.issue(make_request()).unwrap();
    assert_eq!(signed.token.subject(), "alice");
    assert_eq!(signed.token.actions(), &[Action::Read]);
    assert!(signed.token.expires_at().is_some());
    assert!(!signed.token.is_revoked());
}

#[test]
fn issued_token_stored_and_retrievable() {
    let issuer = make_issuer();
    let signed = issuer.issue(make_request()).unwrap();
    let retrieved = issuer.get(signed.token.id()).unwrap();
    assert_eq!(signed.token.id(), retrieved.token.id());
}

#[test]
fn issued_token_signature_verifies() {
    let issuer = make_issuer();
    let signed = issuer.issue(make_request()).unwrap();
    assert!(issuer
        .signer()
        .verify(&signed.token, &signed.signature)
        .is_ok());
}

#[test]
fn issue_with_constraints() {
    let issuer = make_issuer();
    let mut req = make_request();
    req.constraints = Constraints::new()
        .add("format", ParamConstraint::Exact("csv".into()))
        .unwrap();
    let signed = issuer.issue(req).unwrap();
    assert!(signed.token.constraints().get("format").is_some());
}

#[test]
fn issue_delegatable_token() {
    let issuer = make_issuer();
    let mut req = make_request();
    req.delegatable = true;
    let signed = issuer.issue(req).unwrap();
    assert!(signed.token.is_delegatable());
}

#[test]
fn issue_with_max_uses() {
    let issuer = make_issuer();
    let mut req = make_request();
    req.max_uses = Some(5);
    let signed = issuer.issue(req).unwrap();
    assert_eq!(signed.token.max_uses(), Some(5));
}

// ── TTL clamping ────────────────────────────────────────────────────────

#[test]
fn ttl_clamped_to_max() {
    let signer = Ed25519TokenSigner::generate();
    let store = Arc::new(InMemoryTokenStore::new());
    let config = IssuerConfig {
        default_ttl: Duration::from_secs(60),
        max_ttl: Duration::from_secs(300), // 5 minutes max
    };
    let issuer = TokenIssuer::new(signer, store, config);

    let mut req = make_request();
    req.ttl = Some(Duration::from_secs(9999)); // Way over max

    let signed = issuer.issue(req).unwrap();
    let expires = signed.token.expires_at().unwrap();
    let issued = signed.token.issued_at();
    let actual_ttl = (expires - issued).num_seconds();

    // Should be clamped to ~300s (allow 2s tolerance for test timing)
    assert!(
        actual_ttl <= 302,
        "TTL should be clamped to 300s, got {actual_ttl}s"
    );
}

#[test]
fn default_ttl_applied_when_none() {
    let signer = Ed25519TokenSigner::generate();
    let store = Arc::new(InMemoryTokenStore::new());
    let config = IssuerConfig {
        default_ttl: Duration::from_secs(120),
        max_ttl: Duration::from_secs(86400),
    };
    let issuer = TokenIssuer::new(signer, store, config);

    let mut req = make_request();
    req.ttl = None;

    let signed = issuer.issue(req).unwrap();
    let expires = signed.token.expires_at().unwrap();
    let issued = signed.token.issued_at();
    let actual_ttl = (expires - issued).num_seconds();

    assert!(
        (118..=122).contains(&actual_ttl),
        "Expected ~120s default TTL, got {actual_ttl}s"
    );
}

// ── Rejection cases ─────────────────────────────────────────────────────

#[test]
fn empty_actions_rejected() {
    let issuer = make_issuer();
    let mut req = make_request();
    req.actions = vec![];
    let err = issuer.issue(req).unwrap_err();
    assert!(matches!(err, AegisError::NoActions));
}

#[test]
fn empty_subject_rejected() {
    let issuer = make_issuer();
    let mut req = make_request();
    req.subject = String::new();
    let err = issuer.issue(req).unwrap_err();
    assert!(matches!(err, AegisError::EmptySubject));
}

#[test]
fn zero_max_uses_rejected() {
    let issuer = make_issuer();
    let mut req = make_request();
    req.max_uses = Some(0);
    let err = issuer.issue(req).unwrap_err();
    assert!(matches!(err, AegisError::InvalidMaxUses));
}

// ── Store operations ────────────────────────────────────────────────────

#[test]
fn store_list_returns_all_tokens() {
    let issuer = make_issuer();
    for _ in 0..5 {
        issuer.issue(make_request()).unwrap();
    }
    assert_eq!(issuer.list().len(), 5);
}

#[test]
fn store_delete_removes_token() {
    let issuer = make_issuer();
    let signed = issuer.issue(make_request()).unwrap();
    let id = signed.token.id();
    issuer.delete(id).unwrap();
    let err = issuer.get(id).unwrap_err();
    assert!(matches!(err, AegisError::TokenNotFound { .. }));
}

#[test]
fn store_delete_nonexistent_errors() {
    let issuer = make_issuer();
    let err = issuer.delete(uuid::Uuid::new_v4()).unwrap_err();
    assert!(matches!(err, AegisError::TokenNotFound { .. }));
}

#[test]
fn store_get_nonexistent_errors() {
    let issuer = make_issuer();
    let err = issuer.get(uuid::Uuid::new_v4()).unwrap_err();
    assert!(matches!(err, AegisError::TokenNotFound { .. }));
}

#[test]
fn store_is_empty_initially() {
    let store = InMemoryTokenStore::new();
    assert!(store.is_empty());
    assert_eq!(store.len(), 0);
}

#[test]
fn store_contains_after_insert() {
    let issuer = make_issuer();
    let signed = issuer.issue(make_request()).unwrap();
    assert!(issuer.store().contains(signed.token.id()));
}

// ── Concurrent access (1000 parallel inserts) ───────────────────────────

#[test]
fn concurrent_1000_inserts() {
    let signer = Ed25519TokenSigner::generate();
    let store = Arc::new(InMemoryTokenStore::new());
    let config = IssuerConfig::default();
    let issuer = Arc::new(TokenIssuer::new(signer, store, config));

    let handles: Vec<_> = (0..1000)
        .map(|i| {
            let issuer = Arc::clone(&issuer);
            std::thread::spawn(move || {
                let req = aegis_core::TokenRequest {
                    subject: format!("user-{i}"),
                    resource: Resource::new(format!("file:///data/{i}")).unwrap(),
                    actions: vec![Action::Read],
                    constraints: Constraints::new(),
                    ttl: Some(Duration::from_secs(300)),
                    delegatable: false,
                    max_uses: None,
                };
                issuer.issue(req).unwrap()
            })
        })
        .collect();

    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(results.len(), 1000);
    assert_eq!(issuer.list().len(), 1000);

    // Verify each token is retrievable
    for signed in &results {
        let retrieved = issuer.get(signed.token.id()).unwrap();
        assert_eq!(signed.token.id(), retrieved.token.id());
    }
}

#[test]
fn concurrent_insert_and_delete() {
    let signer = Ed25519TokenSigner::generate();
    let store = Arc::new(InMemoryTokenStore::new());
    let config = IssuerConfig::default();
    let issuer = Arc::new(TokenIssuer::new(signer, store, config));

    // Pre-populate 500 tokens
    let mut ids = Vec::new();
    for i in 0..500 {
        let req = aegis_core::TokenRequest {
            subject: format!("user-{i}"),
            resource: Resource::new("file:///data").unwrap(),
            actions: vec![Action::Read],
            constraints: Constraints::new(),
            ttl: Some(Duration::from_secs(300)),
            delegatable: false,
            max_uses: None,
        };
        let signed = issuer.issue(req).unwrap();
        ids.push(signed.token.id());
    }

    // Concurrently: 500 threads delete, 500 threads insert
    let mut handles = Vec::new();

    for id in ids {
        let issuer = Arc::clone(&issuer);
        handles.push(std::thread::spawn(move || {
            issuer.delete(id).unwrap();
        }));
    }

    for i in 500..1000 {
        let issuer = Arc::clone(&issuer);
        handles.push(std::thread::spawn(move || {
            let req = aegis_core::TokenRequest {
                subject: format!("user-{i}"),
                resource: Resource::new("file:///data").unwrap(),
                actions: vec![Action::Read],
                constraints: Constraints::new(),
                ttl: Some(Duration::from_secs(300)),
                delegatable: false,
                max_uses: None,
            };
            issuer.issue(req).unwrap();
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    // All 500 originals deleted, 500 new inserted
    assert_eq!(issuer.list().len(), 500);
}

// ── TokenRequest serde roundtrip ────────────────────────────────────────

#[test]
fn token_request_serde_roundtrip() {
    let req = make_request();
    let json = serde_json::to_string(&req).unwrap();
    let req2: aegis_core::TokenRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(req.subject, req2.subject);
    assert_eq!(req.actions, req2.actions);
    assert_eq!(req.delegatable, req2.delegatable);
    assert_eq!(req.ttl, req2.ttl);
}
