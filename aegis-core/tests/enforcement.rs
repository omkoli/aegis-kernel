use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use aegis_core::{
    Action, Constraints, Decision, DelegationRequest, DelegationService, Ed25519TokenSigner,
    EnforcementEngine, InMemoryTokenStore, IssuerConfig, ParamConstraint, Resource, TokenIssuer,
    TokenRequest, TokenStore, ToolCallRequest,
};
use uuid::Uuid;

// ── Test infrastructure ─────────────────────────────────────────────────

fn setup() -> (
    TokenIssuer<Ed25519TokenSigner, InMemoryTokenStore>,
    DelegationService<Ed25519TokenSigner, InMemoryTokenStore>,
    EnforcementEngine<Ed25519TokenSigner, InMemoryTokenStore>,
) {
    let signer = Ed25519TokenSigner::generate();
    let store = Arc::new(InMemoryTokenStore::new());
    let key_bytes = signer.signing_key_bytes();

    let issuer = TokenIssuer::new(
        Ed25519TokenSigner::from_bytes(&key_bytes),
        Arc::clone(&store),
        IssuerConfig {
            default_ttl: Duration::from_secs(3600),
            max_ttl: Duration::from_secs(86400),
        },
    );
    let delegation = DelegationService::new(
        Ed25519TokenSigner::from_bytes(&key_bytes),
        Arc::clone(&store),
    );
    let engine = EnforcementEngine::new(signer, store);

    (issuer, delegation, engine)
}

fn base_request() -> TokenRequest {
    TokenRequest {
        subject: "agent-1".into(),
        resource: Resource::new("file:///data/reports").unwrap(),
        actions: vec![Action::Read, Action::Write],
        constraints: Constraints::new(),
        ttl: Some(Duration::from_secs(3600)),
        delegatable: true,
        max_uses: Some(100),
    }
}

fn tool_call(token_id: Uuid) -> ToolCallRequest {
    ToolCallRequest {
        agent_id: "agent-1".into(),
        tool_name: "read_file".into(),
        action: Action::Read,
        resource: Resource::new("file:///data/reports").unwrap(),
        parameters: HashMap::new(),
        token_id,
    }
}

// ── 1. Valid token → ALLOW with audit ───────────────────────────────────

#[test]
fn valid_token_allow_with_audit() {
    let (issuer, _deleg, engine) = setup();
    let signed = issuer.issue(base_request()).unwrap();
    let call = tool_call(signed.token.id());

    let result = engine.enforce(&call);

    assert_eq!(result.decision, Decision::Allow);
    assert_eq!(result.audit.decision, Decision::Allow);
    assert_eq!(result.audit.agent_id, "agent-1");
    assert_eq!(result.audit.tool_name, "read_file");
    assert_eq!(result.audit.action, Action::Read);
    assert_eq!(result.audit.resource_path, "file:///data/reports");
    assert_eq!(result.audit.token_id, signed.token.id());
    assert_eq!(result.audit.reason, "all checks passed");
    assert!(result.audit.token_chain.is_empty()); // root token
    assert!(result.audit.latency_us > 0);
}

// ── 2. Expired token → DENY with audit ─────────────────────────────────

#[test]
fn expired_token_deny_with_audit() {
    let (issuer, _deleg, engine) = setup();
    let mut req = base_request();
    req.ttl = Some(Duration::from_millis(1));
    let signed = issuer.issue(req).unwrap();
    std::thread::sleep(Duration::from_millis(10));

    let result = engine.enforce(&tool_call(signed.token.id()));

    assert_eq!(result.decision, Decision::Deny);
    assert!(result.audit.reason.contains("expired"));
}

// ── 3. Tampered signature → DENY ────────────────────────────────────────

#[test]
fn tampered_signature_deny_with_audit() {
    let (issuer, _deleg, engine) = setup();
    let signed = issuer.issue(base_request()).unwrap();
    let id = signed.token.id();

    // Tamper the stored entry
    let mut bad_sig_bytes = signed.signature.to_bytes();
    bad_sig_bytes[0] ^= 0xff;
    issuer.store().delete(id).unwrap();
    issuer
        .store()
        .insert(aegis_core::SignedToken {
            token: signed.token.clone(),
            signature: aegis_core::TokenSignature::from_bytes(&bad_sig_bytes),
        })
        .unwrap();

    let result = engine.enforce(&tool_call(id));

    assert_eq!(result.decision, Decision::Deny);
    assert!(result.audit.reason.contains("signature invalid"));
}

// ── 4. Wrong resource → DENY ───────────────────────────────────────────

#[test]
fn wrong_resource_deny_with_audit() {
    let (issuer, _deleg, engine) = setup();
    let signed = issuer.issue(base_request()).unwrap();

    let mut call = tool_call(signed.token.id());
    call.resource = Resource::new("file:///etc/shadow").unwrap();

    let result = engine.enforce(&call);

    assert_eq!(result.decision, Decision::Deny);
    assert!(result.audit.reason.contains("resource mismatch"));
}

// ── 5. Wrong action → DENY ─────────────────────────────────────────────

#[test]
fn wrong_action_deny_with_audit() {
    let (issuer, _deleg, engine) = setup();
    let signed = issuer.issue(base_request()).unwrap();

    let mut call = tool_call(signed.token.id());
    call.action = Action::Delete; // only Read, Write granted

    let result = engine.enforce(&call);

    assert_eq!(result.decision, Decision::Deny);
    assert!(result.audit.reason.contains("not permitted"));
}

// ── 6. Revoked token → DENY ────────────────────────────────────────────

#[test]
fn revoked_token_deny_with_audit() {
    let (issuer, deleg, engine) = setup();
    let signed = issuer.issue(base_request()).unwrap();
    deleg.revoke_cascade(signed.token.id()).unwrap();

    let result = engine.enforce(&tool_call(signed.token.id()));

    assert_eq!(result.decision, Decision::Deny);
    assert!(result.audit.reason.contains("revoked"));
}

// ── 7. Wrong agent → DENY ──────────────────────────────────────────────

#[test]
fn wrong_agent_deny_with_audit() {
    let (issuer, _deleg, engine) = setup();
    let signed = issuer.issue(base_request()).unwrap();

    let mut call = tool_call(signed.token.id());
    call.agent_id = "evil-agent".into();

    let result = engine.enforce(&call);

    assert_eq!(result.decision, Decision::Deny);
    assert!(result.audit.reason.contains("does not match"));
}

// ── 8. Usage exhausted → DENY ──────────────────────────────────────────

#[test]
fn usage_exhausted_deny_with_audit() {
    let (issuer, _deleg, engine) = setup();
    let mut req = base_request();
    req.max_uses = Some(3);
    let signed = issuer.issue(req).unwrap();
    let call = tool_call(signed.token.id());

    for _ in 0..3 {
        let r = engine.enforce(&call);
        assert_eq!(r.decision, Decision::Allow);
    }

    let result = engine.enforce(&call);
    assert_eq!(result.decision, Decision::Deny);
    assert!(result.audit.reason.contains("usage exhausted"));
}

// ── 9. Token not found → DENY ──────────────────────────────────────────

#[test]
fn nonexistent_token_deny_with_audit() {
    let (_issuer, _deleg, engine) = setup();
    let call = tool_call(Uuid::new_v4());

    let result = engine.enforce(&call);

    assert_eq!(result.decision, Decision::Deny);
    assert!(result.audit.reason.contains("not found"));
}

// ── 10. Constraint violation → DENY ────────────────────────────────────

#[test]
fn constraint_violation_deny_with_audit() {
    let (issuer, _deleg, engine) = setup();
    let mut req = base_request();
    req.constraints = Constraints::new()
        .add("format", ParamConstraint::Exact("json".into()))
        .unwrap();
    let signed = issuer.issue(req).unwrap();

    let mut call = tool_call(signed.token.id());
    call.parameters.insert("format".into(), "xml".into());

    let result = engine.enforce(&call);

    assert_eq!(result.decision, Decision::Deny);
    assert!(result.audit.reason.contains("constraint violation"));
}

// ── 11. Delegation chain appears in audit ───────────────────────────────

#[test]
fn delegation_chain_in_audit() {
    let (issuer, deleg, engine) = setup();
    let root = issuer.issue(base_request()).unwrap();

    let child = deleg
        .delegate(DelegationRequest {
            parent_token_id: root.token.id(),
            new_subject: "child-agent".into(),
            actions: vec![Action::Read],
            constraints: Constraints::new(),
            delegatable: true,
            max_uses: Some(50),
            ttl_secs: Some(1800),
        })
        .unwrap();

    let grandchild = deleg
        .delegate(DelegationRequest {
            parent_token_id: child.token.id(),
            new_subject: "grandchild-agent".into(),
            actions: vec![Action::Read],
            constraints: Constraints::new(),
            delegatable: false,
            max_uses: Some(10),
            ttl_secs: Some(600),
        })
        .unwrap();

    // Enforce using grandchild's token
    let call = ToolCallRequest {
        agent_id: "grandchild-agent".into(),
        tool_name: "read_file".into(),
        action: Action::Read,
        resource: Resource::new("file:///data/reports").unwrap(),
        parameters: HashMap::new(),
        token_id: grandchild.token.id(),
    };

    let result = engine.enforce(&call);

    assert_eq!(result.decision, Decision::Allow);
    // Chain should be [child_id, root_id]
    assert_eq!(result.audit.token_chain.len(), 2);
    assert_eq!(result.audit.token_chain[0], child.token.id());
    assert_eq!(result.audit.token_chain[1], root.token.id());
}

// ── 12. Cascaded revocation denies delegated token ──────────────────────

#[test]
fn cascaded_revocation_denies_delegated_token() {
    let (issuer, deleg, engine) = setup();
    let root = issuer.issue(base_request()).unwrap();

    let child = deleg
        .delegate(DelegationRequest {
            parent_token_id: root.token.id(),
            new_subject: "child-agent".into(),
            actions: vec![Action::Read],
            constraints: Constraints::new(),
            delegatable: false,
            max_uses: None,
            ttl_secs: None,
        })
        .unwrap();

    // Revoke root → child is also revoked
    deleg.revoke_cascade(root.token.id()).unwrap();

    let call = ToolCallRequest {
        agent_id: "child-agent".into(),
        tool_name: "read_file".into(),
        action: Action::Read,
        resource: Resource::new("file:///data/reports").unwrap(),
        parameters: HashMap::new(),
        token_id: child.token.id(),
    };

    let result = engine.enforce(&call);
    assert_eq!(result.decision, Decision::Deny);
    assert!(result.audit.reason.contains("revoked"));
}

// ── 13. AuditEntry has unique request_id ────────────────────────────────

#[test]
fn audit_entries_have_unique_request_ids() {
    let (issuer, _deleg, engine) = setup();
    let signed = issuer.issue(base_request()).unwrap();
    let call = tool_call(signed.token.id());

    let r1 = engine.enforce(&call);
    let r2 = engine.enforce(&call);

    assert_ne!(r1.audit.request_id, r2.audit.request_id);
}

// ── 14. AuditEntry timestamp is recent ──────────────────────────────────

#[test]
fn audit_entry_timestamp_is_recent() {
    let (issuer, _deleg, engine) = setup();
    let signed = issuer.issue(base_request()).unwrap();
    let before = chrono::Utc::now();

    let result = engine.enforce(&tool_call(signed.token.id()));

    let after = chrono::Utc::now();
    assert!(result.audit.timestamp >= before);
    assert!(result.audit.timestamp <= after);
}

// ── 15. AuditEntry serde roundtrip ──────────────────────────────────────

#[test]
fn audit_entry_serde_roundtrip() {
    let (issuer, _deleg, engine) = setup();
    let signed = issuer.issue(base_request()).unwrap();

    let result = engine.enforce(&tool_call(signed.token.id()));
    let json = serde_json::to_string(&result.audit).unwrap();
    let audit2: aegis_core::AuditEntry = serde_json::from_str(&json).unwrap();

    assert_eq!(result.audit.request_id, audit2.request_id);
    assert_eq!(result.audit.agent_id, audit2.agent_id);
    assert_eq!(result.audit.decision, audit2.decision);
    assert_eq!(result.audit.token_id, audit2.token_id);
    assert_eq!(result.audit.reason, audit2.reason);
}

// ── 16. Latency is recorded ─────────────────────────────────────────────

#[test]
fn latency_is_recorded() {
    let (issuer, _deleg, engine) = setup();
    let signed = issuer.issue(base_request()).unwrap();

    let result = engine.enforce(&tool_call(signed.token.id()));

    // Latency should be > 0 (at minimum a few microseconds)
    assert!(result.audit.latency_us > 0);
}

// ── 17. Multiple sequential decisions are all correct ───────────────────

#[test]
fn multiple_sequential_decisions_correct() {
    let (issuer, _deleg, engine) = setup();
    let signed = issuer.issue(base_request()).unwrap();

    // Valid call
    let r = engine.enforce(&tool_call(signed.token.id()));
    assert_eq!(r.decision, Decision::Allow);

    // Wrong action
    let mut bad_action = tool_call(signed.token.id());
    bad_action.action = Action::Delete;
    let r = engine.enforce(&bad_action);
    assert_eq!(r.decision, Decision::Deny);

    // Wrong resource
    let mut bad_resource = tool_call(signed.token.id());
    bad_resource.resource = Resource::new("file:///nope").unwrap();
    let r = engine.enforce(&bad_resource);
    assert_eq!(r.decision, Decision::Deny);

    // Nonexistent token
    let r = engine.enforce(&tool_call(Uuid::new_v4()));
    assert_eq!(r.decision, Decision::Deny);

    // Valid again (still works)
    let r = engine.enforce(&tool_call(signed.token.id()));
    assert_eq!(r.decision, Decision::Allow);
}

// ── 18. Root token has empty chain ──────────────────────────────────────

#[test]
fn root_token_has_empty_chain() {
    let (issuer, _deleg, engine) = setup();
    let signed = issuer.issue(base_request()).unwrap();

    let result = engine.enforce(&tool_call(signed.token.id()));
    assert!(result.audit.token_chain.is_empty());
}

// ── 19. Deny audit still records all fields ─────────────────────────────

#[test]
fn deny_audit_records_all_fields() {
    let (_issuer, _deleg, engine) = setup();
    let fake_id = Uuid::new_v4();
    let call = ToolCallRequest {
        agent_id: "rogue".into(),
        tool_name: "hack_tool".into(),
        action: Action::Execute,
        resource: Resource::new("file:///etc/shadow").unwrap(),
        parameters: HashMap::new(),
        token_id: fake_id,
    };

    let result = engine.enforce(&call);

    assert_eq!(result.decision, Decision::Deny);
    assert_eq!(result.audit.agent_id, "rogue");
    assert_eq!(result.audit.tool_name, "hack_tool");
    assert_eq!(result.audit.action, Action::Execute);
    assert_eq!(result.audit.resource_path, "file:///etc/shadow");
    assert_eq!(result.audit.token_id, fake_id);
    assert!(result.audit.latency_us > 0);
}
