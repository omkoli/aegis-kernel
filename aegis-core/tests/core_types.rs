use aegis_core::{Action, AegisError, CapabilityToken, Constraints, ParamConstraint, Resource};
use chrono::{Duration, Utc};

// ── Resource tests ──────────────────────────────────────────────────────

#[test]
fn resource_valid_path() {
    let r = Resource::new("file:///etc/config").unwrap();
    assert_eq!(r.path(), "file:///etc/config");
}

#[test]
fn resource_empty_path_rejected() {
    let err = Resource::new("").unwrap_err();
    assert!(matches!(err, AegisError::EmptyResourcePath));
}

#[test]
fn resource_serde_roundtrip() {
    let r = Resource::new("net://api.example.com/v1").unwrap();
    let json = serde_json::to_string(&r).unwrap();
    let r2: Resource = serde_json::from_str(&json).unwrap();
    assert_eq!(r, r2);
}

// ── Action tests ────────────────────────────────────────────────────────

#[test]
fn action_custom_valid() {
    let a = Action::custom("audit").unwrap();
    assert_eq!(a, Action::Custom("audit".to_string()));
}

#[test]
fn action_custom_empty_rejected() {
    let err = Action::custom("").unwrap_err();
    assert!(matches!(err, AegisError::EmptyActionName));
}

#[test]
fn action_serde_roundtrip() {
    for action in [Action::Read, Action::Write, Action::Execute, Action::Delete] {
        let json = serde_json::to_string(&action).unwrap();
        let a2: Action = serde_json::from_str(&json).unwrap();
        assert_eq!(action, a2);
    }
}

#[test]
fn action_custom_serde_roundtrip() {
    let a = Action::custom("deploy").unwrap();
    let json = serde_json::to_string(&a).unwrap();
    let a2: Action = serde_json::from_str(&json).unwrap();
    assert_eq!(a, a2);
}

// ── ParamConstraint tests ───────────────────────────────────────────────

#[test]
fn param_constraint_range_valid() {
    let c = ParamConstraint::range(0.0, 100.0).unwrap();
    assert_eq!(
        c,
        ParamConstraint::Range {
            min: 0.0,
            max: 100.0
        }
    );
}

#[test]
fn param_constraint_range_equal_bounds() {
    let c = ParamConstraint::range(5.0, 5.0).unwrap();
    assert_eq!(c, ParamConstraint::Range { min: 5.0, max: 5.0 });
}

#[test]
fn param_constraint_range_inverted_rejected() {
    let err = ParamConstraint::range(100.0, 0.0).unwrap_err();
    assert!(matches!(err, AegisError::InvalidRange { min, max } if min == 100.0 && max == 0.0));
}

#[test]
fn param_constraint_serde_roundtrip() {
    let cases = vec![
        ParamConstraint::Exact("hello".to_string()),
        ParamConstraint::OneOf(vec!["a".into(), "b".into()]),
        ParamConstraint::Regex(r"^\d+$".to_string()),
        ParamConstraint::Range {
            min: 1.0,
            max: 10.0,
        },
    ];
    for c in cases {
        let json = serde_json::to_string(&c).unwrap();
        let c2: ParamConstraint = serde_json::from_str(&json).unwrap();
        assert_eq!(c, c2);
    }
}

// ── Constraints tests ───────────────────────────────────────────────────

#[test]
fn constraints_add_and_get() {
    let c = Constraints::new()
        .add("limit", ParamConstraint::Exact("10".into()))
        .unwrap();
    assert_eq!(c.len(), 1);
    assert!(matches!(c.get("limit"), Some(ParamConstraint::Exact(v)) if v == "10"));
}

#[test]
fn constraints_empty_key_rejected() {
    let err = Constraints::new()
        .add("", ParamConstraint::Exact("x".into()))
        .unwrap_err();
    assert!(matches!(err, AegisError::EmptyConstraintKey));
}

#[test]
fn constraints_default_is_empty() {
    let c = Constraints::new();
    assert!(c.is_empty());
    assert_eq!(c.len(), 0);
}

// ── CapabilityToken tests ───────────────────────────────────────────────

#[test]
fn token_valid_construction() {
    let resource = Resource::new("file:///tmp").unwrap();
    let token = CapabilityToken::new(
        resource.clone(),
        vec![Action::Read],
        Constraints::new(),
        None,
    )
    .unwrap();
    assert_eq!(token.resource(), &resource);
    assert_eq!(token.actions(), &[Action::Read]);
    assert!(!token.is_revoked());
}

#[test]
fn token_no_actions_rejected() {
    let resource = Resource::new("file:///tmp").unwrap();
    let err = CapabilityToken::new(resource, vec![], Constraints::new(), None).unwrap_err();
    assert!(matches!(err, AegisError::NoActions));
}

#[test]
fn token_past_expiry_rejected() {
    let resource = Resource::new("file:///tmp").unwrap();
    let past = Utc::now() - Duration::hours(1);
    let err = CapabilityToken::new(resource, vec![Action::Read], Constraints::new(), Some(past))
        .unwrap_err();
    assert!(matches!(err, AegisError::TokenAlreadyExpired { .. }));
}

#[test]
fn token_revoke_once_ok() {
    let resource = Resource::new("file:///tmp").unwrap();
    let mut token =
        CapabilityToken::new(resource, vec![Action::Read], Constraints::new(), None).unwrap();
    assert!(token.revoke().is_ok());
    assert!(token.is_revoked());
}

#[test]
fn token_double_revoke_rejected() {
    let resource = Resource::new("file:///tmp").unwrap();
    let mut token =
        CapabilityToken::new(resource, vec![Action::Read], Constraints::new(), None).unwrap();
    token.revoke().unwrap();
    let err = token.revoke().unwrap_err();
    assert!(matches!(err, AegisError::TokenAlreadyRevoked { .. }));
}

#[test]
fn token_permits_granted_action() {
    let resource = Resource::new("file:///tmp").unwrap();
    let token = CapabilityToken::new(
        resource,
        vec![Action::Read, Action::Write],
        Constraints::new(),
        None,
    )
    .unwrap();
    assert!(token.permits(&Action::Read));
    assert!(token.permits(&Action::Write));
    assert!(!token.permits(&Action::Delete));
}

#[test]
fn token_is_expired_at() {
    let resource = Resource::new("file:///tmp").unwrap();
    let future = Utc::now() + Duration::hours(1);
    let token = CapabilityToken::new(
        resource,
        vec![Action::Read],
        Constraints::new(),
        Some(future),
    )
    .unwrap();
    assert!(!token.is_expired_at(Utc::now()));
    assert!(token.is_expired_at(future + Duration::seconds(1)));
}

#[test]
fn token_serde_roundtrip() {
    let resource = Resource::new("net://db/users").unwrap();
    let constraints = Constraints::new()
        .add(
            "max_rows",
            ParamConstraint::Range {
                min: 1.0,
                max: 1000.0,
            },
        )
        .unwrap();
    let token = CapabilityToken::new(
        resource,
        vec![Action::Read, Action::custom("query").unwrap()],
        constraints,
        None,
    )
    .unwrap();
    let json = serde_json::to_string(&token).unwrap();
    let token2: CapabilityToken = serde_json::from_str(&json).unwrap();
    assert_eq!(token, token2);
}

// ── Error display tests ─────────────────────────────────────────────────

#[test]
fn error_messages_are_descriptive() {
    let e = AegisError::EmptyResourcePath;
    assert!(e.to_string().contains("empty"));

    let e = AegisError::InvalidRange {
        min: 10.0,
        max: 5.0,
    };
    let msg = e.to_string();
    assert!(msg.contains("10") && msg.contains("5"));

    let e = AegisError::NoActions;
    assert!(e.to_string().contains("action"));
}
