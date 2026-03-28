use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use aegis_core::{
    Action, Constraints, Ed25519TokenSigner, InMemoryTokenStore, IssuerConfig, ParamConstraint,
    Resource, TokenIssuer, TokenRequest, TokenSigner, TokenStore, TokenValidator, ToolCallRequest,
    ValidationResult,
};
use uuid::Uuid;

/// Helper: creates an issuer + validator sharing the same signer and store.
fn setup() -> (
    TokenIssuer<Ed25519TokenSigner, InMemoryTokenStore>,
    TokenValidator<Ed25519TokenSigner, InMemoryTokenStore>,
) {
    // We need two signers from the same key so signatures verify.
    let signer = Ed25519TokenSigner::generate();
    let store = Arc::new(InMemoryTokenStore::new());

    // Clone the signing key bytes to create an identical signer for the validator.
    let signer_bytes = signer.signing_key_bytes();
    let signer2 = Ed25519TokenSigner::from_bytes(&signer_bytes);

    let config = IssuerConfig {
        default_ttl: Duration::from_secs(3600),
        max_ttl: Duration::from_secs(86400),
    };

    let issuer = TokenIssuer::new(signer, Arc::clone(&store), config);
    let validator = TokenValidator::new(signer2, store);
    (issuer, validator)
}

fn base_request() -> TokenRequest {
    TokenRequest {
        subject: "agent-1".into(),
        resource: Resource::new("file:///data/reports").unwrap(),
        actions: vec![Action::Read],
        constraints: Constraints::new(),
        ttl: Some(Duration::from_secs(600)),
        delegatable: false,
        max_uses: None,
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

// ── 1. Valid token → ALLOW ──────────────────────────────────────────────

#[test]
fn valid_token_allows() {
    let (issuer, validator) = setup();
    let signed = issuer.issue(base_request()).unwrap();
    let result = validator.validate(&tool_call(signed.token.id())).unwrap();
    assert_eq!(result, ValidationResult::Allow);
}

// ── 2. Expired token → DENY ────────────────────────────────────────────

#[test]
fn expired_token_denied() {
    let (issuer, validator) = setup();
    // Issue with very short TTL
    let mut req = base_request();
    req.ttl = Some(Duration::from_millis(1));
    let signed = issuer.issue(req).unwrap();

    // Wait for expiry
    std::thread::sleep(Duration::from_millis(10));

    let result = validator.validate(&tool_call(signed.token.id())).unwrap();
    assert!(matches!(result, ValidationResult::Deny(msg) if msg.contains("expired")));
}

// ── 3. Tampered signature → error ──────────────────────────────────────

#[test]
fn tampered_signature_denied() {
    let (issuer, validator) = setup();
    let signed = issuer.issue(base_request()).unwrap();
    let id = signed.token.id();

    // Tamper: replace the stored entry with one that has a bad signature
    let mut bad_sig_bytes = signed.signature.to_bytes();
    bad_sig_bytes[0] ^= 0xff;
    let tampered = aegis_core::SignedToken {
        token: signed.token.clone(),
        signature: aegis_core::TokenSignature::from_bytes(&bad_sig_bytes),
    };
    // Delete original and insert tampered
    issuer.store().delete(id).unwrap();
    issuer.store().insert(tampered).unwrap();

    let result = validator.validate(&tool_call(id));
    assert!(result.is_err(), "tampered signature should cause an error");
}

// ── 4. Wrong resource → DENY ───────────────────────────────────────────

#[test]
fn wrong_resource_denied() {
    let (issuer, validator) = setup();
    let signed = issuer.issue(base_request()).unwrap();

    let mut call = tool_call(signed.token.id());
    call.resource = Resource::new("file:///etc/shadow").unwrap();

    let result = validator.validate(&call).unwrap();
    assert!(matches!(result, ValidationResult::Deny(msg) if msg.contains("resource mismatch")));
}

// ── 5. Wrong action → DENY ─────────────────────────────────────────────

#[test]
fn wrong_action_denied() {
    let (issuer, validator) = setup();
    let signed = issuer.issue(base_request()).unwrap();

    let mut call = tool_call(signed.token.id());
    call.action = Action::Delete;

    let result = validator.validate(&call).unwrap();
    assert!(matches!(result, ValidationResult::Deny(msg) if msg.contains("not permitted")));
}

// ── 6. Revoked token → DENY ────────────────────────────────────────────

#[test]
fn revoked_token_denied() {
    let (issuer, validator) = setup();
    let signed = issuer.issue(base_request()).unwrap();
    let id = signed.token.id();

    // Revoke: delete, mutate, re-sign, re-insert
    let mut entry = issuer.store().delete(id).unwrap();
    entry.token.revoke().unwrap();
    let new_sig = issuer.signer().sign(&entry.token).unwrap();
    issuer
        .store()
        .insert(aegis_core::SignedToken {
            token: entry.token,
            signature: new_sig,
        })
        .unwrap();

    let result = validator.validate(&tool_call(id)).unwrap();
    assert!(matches!(result, ValidationResult::Deny(msg) if msg.contains("revoked")));
}

// ── 7. Wrong agent (subject mismatch) → DENY ───────────────────────────

#[test]
fn wrong_agent_denied() {
    let (issuer, validator) = setup();
    let signed = issuer.issue(base_request()).unwrap();

    let mut call = tool_call(signed.token.id());
    call.agent_id = "evil-agent".into();

    let result = validator.validate(&call).unwrap();
    assert!(matches!(result, ValidationResult::Deny(msg) if msg.contains("does not match")));
}

// ── 8. Usage exhausted → DENY ──────────────────────────────────────────

#[test]
fn usage_exhausted_denied() {
    let (issuer, validator) = setup();
    let mut req = base_request();
    req.max_uses = Some(3);
    let signed = issuer.issue(req).unwrap();
    let call = tool_call(signed.token.id());

    // Use all 3 allowed uses
    for _ in 0..3 {
        let result = validator.validate(&call).unwrap();
        assert_eq!(result, ValidationResult::Allow);
    }

    // 4th use should be denied
    let result = validator.validate(&call).unwrap();
    assert!(matches!(result, ValidationResult::Deny(msg) if msg.contains("usage exhausted")));
}

#[test]
fn usage_count_tracked() {
    let (issuer, validator) = setup();
    let mut req = base_request();
    req.max_uses = Some(10);
    let signed = issuer.issue(req).unwrap();
    let id = signed.token.id();
    let call = tool_call(id);

    assert_eq!(validator.usage_count(id), 0);

    validator.validate(&call).unwrap();
    assert_eq!(validator.usage_count(id), 1);

    validator.validate(&call).unwrap();
    assert_eq!(validator.usage_count(id), 2);
}

// ── 9. Constraint violation → DENY ─────────────────────────────────────

#[test]
fn constraint_violation_exact_denied() {
    let (issuer, validator) = setup();
    let mut req = base_request();
    req.constraints = Constraints::new()
        .add("format", ParamConstraint::Exact("json".into()))
        .unwrap();
    let signed = issuer.issue(req).unwrap();

    let mut call = tool_call(signed.token.id());
    call.parameters.insert("format".into(), "xml".into());

    let result = validator.validate(&call).unwrap();
    assert!(matches!(result, ValidationResult::Deny(msg) if msg.contains("constraint violation")));
}

#[test]
fn constraint_violation_range_denied() {
    let (issuer, validator) = setup();
    let mut req = base_request();
    req.constraints = Constraints::new()
        .add(
            "limit",
            ParamConstraint::Range {
                min: 1.0,
                max: 100.0,
            },
        )
        .unwrap();
    let signed = issuer.issue(req).unwrap();

    let mut call = tool_call(signed.token.id());
    call.parameters.insert("limit".into(), "999".into());

    let result = validator.validate(&call).unwrap();
    assert!(matches!(result, ValidationResult::Deny(msg) if msg.contains("constraint violation")));
}

#[test]
fn constraint_violation_one_of_denied() {
    let (issuer, validator) = setup();
    let mut req = base_request();
    req.constraints = Constraints::new()
        .add(
            "env",
            ParamConstraint::OneOf(vec!["staging".into(), "prod".into()]),
        )
        .unwrap();
    let signed = issuer.issue(req).unwrap();

    let mut call = tool_call(signed.token.id());
    call.parameters.insert("env".into(), "dev".into());

    let result = validator.validate(&call).unwrap();
    assert!(matches!(result, ValidationResult::Deny(msg) if msg.contains("constraint violation")));
}

#[test]
fn constraint_satisfied_allows() {
    let (issuer, validator) = setup();
    let mut req = base_request();
    req.constraints = Constraints::new()
        .add("format", ParamConstraint::Exact("json".into()))
        .unwrap();
    let signed = issuer.issue(req).unwrap();

    let mut call = tool_call(signed.token.id());
    call.parameters.insert("format".into(), "json".into());

    let result = validator.validate(&call).unwrap();
    assert_eq!(result, ValidationResult::Allow);
}

// ── 10. Token not found → error ────────────────────────────────────────

#[test]
fn nonexistent_token_errors() {
    let (_issuer, validator) = setup();
    let call = tool_call(Uuid::new_v4());
    let result = validator.validate(&call);
    assert!(result.is_err());
}

// ── 11. ToolCallRequest serde roundtrip ─────────────────────────────────

#[test]
fn tool_call_request_serde_roundtrip() {
    let call = ToolCallRequest {
        agent_id: "agent-1".into(),
        tool_name: "read_file".into(),
        action: Action::Read,
        resource: Resource::new("file:///data").unwrap(),
        parameters: {
            let mut m = HashMap::new();
            m.insert("format".into(), "json".into());
            m
        },
        token_id: Uuid::new_v4(),
    };
    let json = serde_json::to_string(&call).unwrap();
    let call2: ToolCallRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(call.agent_id, call2.agent_id);
    assert_eq!(call.token_id, call2.token_id);
    assert_eq!(call.action, call2.action);
}

// ── 12. Performance: 10K validations ────────────────────────────────────
// Ed25519 verify is ~8ms in debug mode (~60µs in release), so the full
// 10K-in-1s target only holds for optimised builds. In debug we run a
// smaller batch to ensure the pipeline works, and rely on the release
// build for the real benchmark.

#[test]
fn validation_performance() {
    let (issuer, validator) = setup();
    let signed = issuer.issue(base_request()).unwrap();
    let call = tool_call(signed.token.id());

    // Warm up
    validator.validate(&call).unwrap();

    let iterations = if cfg!(debug_assertions) { 100 } else { 10_000 };

    let start = std::time::Instant::now();
    for _ in 0..iterations {
        let result = validator.validate(&call).unwrap();
        assert_eq!(result, ValidationResult::Allow);
    }
    let elapsed = start.elapsed();
    let avg_micros = elapsed.as_micros() as f64 / iterations as f64;

    eprintln!(
        "{iterations} validations in {:.2}ms ({avg_micros:.1}µs/op, {:.0} ops/sec)",
        elapsed.as_millis(),
        1_000_000.0 / avg_micros
    );

    if cfg!(debug_assertions) {
        // Debug: just ensure it completes in reasonable time
        assert!(
            elapsed.as_secs() < 120,
            "{iterations} validations took {elapsed:?}, unexpectedly slow"
        );
    } else {
        // Release: 10K validations must complete under 1 second
        assert!(
            elapsed.as_secs() < 1,
            "10K validations took {elapsed:?}, expected < 1s"
        );
    }
}
