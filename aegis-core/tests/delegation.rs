use std::sync::Arc;
use std::time::Duration;

use aegis_core::{
    Action, AegisError, Constraints, DelegationRequest, DelegationService, Ed25519TokenSigner,
    InMemoryTokenStore, IssuerConfig, ParamConstraint, Resource, TokenIssuer, TokenSigner,
    TokenStore,
};
use uuid::Uuid;

/// Shared setup: creates an issuer and delegation service over the same store.
fn setup() -> (
    TokenIssuer<Ed25519TokenSigner, InMemoryTokenStore>,
    DelegationService<Ed25519TokenSigner, InMemoryTokenStore>,
) {
    let signer = Ed25519TokenSigner::generate();
    let store = Arc::new(InMemoryTokenStore::new());

    let signer_bytes = signer.signing_key_bytes();
    let signer2 = Ed25519TokenSigner::from_bytes(&signer_bytes);

    let config = IssuerConfig {
        default_ttl: Duration::from_secs(3600),
        max_ttl: Duration::from_secs(86400),
    };

    let issuer = TokenIssuer::new(signer, Arc::clone(&store), config);
    let delegation = DelegationService::new(signer2, store);
    (issuer, delegation)
}

fn issue_delegatable(
    issuer: &TokenIssuer<Ed25519TokenSigner, InMemoryTokenStore>,
) -> aegis_core::SignedToken {
    issuer
        .issue(aegis_core::TokenRequest {
            subject: "root-agent".into(),
            resource: Resource::new("file:///data/reports").unwrap(),
            actions: vec![Action::Read, Action::Write, Action::Execute],
            constraints: Constraints::new(),
            ttl: Some(Duration::from_secs(3600)),
            delegatable: true,
            max_uses: Some(100),
        })
        .unwrap()
}

fn issue_non_delegatable(
    issuer: &TokenIssuer<Ed25519TokenSigner, InMemoryTokenStore>,
) -> aegis_core::SignedToken {
    issuer
        .issue(aegis_core::TokenRequest {
            subject: "root-agent".into(),
            resource: Resource::new("file:///data/reports").unwrap(),
            actions: vec![Action::Read],
            constraints: Constraints::new(),
            ttl: Some(Duration::from_secs(3600)),
            delegatable: false,
            max_uses: None,
        })
        .unwrap()
}

// ── 1. Valid delegation ─────────────────────────────────────────────────

#[test]
fn valid_delegation_narrower_scope() {
    let (issuer, delegation) = setup();
    let parent = issue_delegatable(&issuer);

    let child = delegation
        .delegate(DelegationRequest {
            parent_token_id: parent.token.id(),
            new_subject: "child-agent".into(),
            actions: vec![Action::Read],
            constraints: Constraints::new(),
            delegatable: false,
            max_uses: Some(10),
            ttl_secs: Some(600),
        })
        .unwrap();

    assert_eq!(child.token.subject(), "child-agent");
    assert_eq!(child.token.actions(), &[Action::Read]);
    assert_eq!(child.token.parent_id(), Some(parent.token.id()));
    assert!(!child.token.is_delegatable());
    assert_eq!(child.token.max_uses(), Some(10));
}

#[test]
fn valid_delegation_equal_scope() {
    let (issuer, delegation) = setup();
    let parent = issue_delegatable(&issuer);

    let child = delegation
        .delegate(DelegationRequest {
            parent_token_id: parent.token.id(),
            new_subject: "child-agent".into(),
            actions: vec![Action::Read, Action::Write, Action::Execute],
            constraints: Constraints::new(),
            delegatable: true,
            max_uses: Some(100),
            ttl_secs: Some(3600),
        })
        .unwrap();

    assert_eq!(child.token.actions().len(), 3);
    assert!(child.token.is_delegatable());
}

#[test]
fn delegation_stored_and_retrievable() {
    let (issuer, delegation) = setup();
    let parent = issue_delegatable(&issuer);

    let child = delegation
        .delegate(DelegationRequest {
            parent_token_id: parent.token.id(),
            new_subject: "child-agent".into(),
            actions: vec![Action::Read],
            constraints: Constraints::new(),
            delegatable: false,
            max_uses: None,
            ttl_secs: None,
        })
        .unwrap();

    let retrieved = delegation.store().get(child.token.id()).unwrap();
    assert_eq!(retrieved.token.id(), child.token.id());
}

#[test]
fn delegation_signature_verifies() {
    let (issuer, delegation) = setup();
    let parent = issue_delegatable(&issuer);

    let child = delegation
        .delegate(DelegationRequest {
            parent_token_id: parent.token.id(),
            new_subject: "child-agent".into(),
            actions: vec![Action::Read],
            constraints: Constraints::new(),
            delegatable: false,
            max_uses: None,
            ttl_secs: None,
        })
        .unwrap();

    assert!(delegation
        .signer()
        .verify(&child.token, &child.signature)
        .is_ok());
}

// ── 2. Non-delegatable rejection ────────────────────────────────────────

#[test]
fn non_delegatable_parent_rejected() {
    let (issuer, delegation) = setup();
    let parent = issue_non_delegatable(&issuer);

    let err = delegation
        .delegate(DelegationRequest {
            parent_token_id: parent.token.id(),
            new_subject: "child-agent".into(),
            actions: vec![Action::Read],
            constraints: Constraints::new(),
            delegatable: false,
            max_uses: None,
            ttl_secs: None,
        })
        .unwrap_err();

    assert!(matches!(err, AegisError::NotDelegatable { .. }));
}

// ── 3. Scope escalation blocked ─────────────────────────────────────────

#[test]
fn action_escalation_blocked() {
    let (issuer, delegation) = setup();
    let parent = issue_delegatable(&issuer);

    let err = delegation
        .delegate(DelegationRequest {
            parent_token_id: parent.token.id(),
            new_subject: "child-agent".into(),
            actions: vec![Action::Delete], // parent has Read, Write, Execute — not Delete
            constraints: Constraints::new(),
            delegatable: false,
            max_uses: None,
            ttl_secs: None,
        })
        .unwrap_err();

    assert!(matches!(err, AegisError::ScopeEscalation { .. }));
}

#[test]
fn max_uses_escalation_blocked() {
    let (issuer, delegation) = setup();
    let parent = issue_delegatable(&issuer); // max_uses = 100

    let err = delegation
        .delegate(DelegationRequest {
            parent_token_id: parent.token.id(),
            new_subject: "child-agent".into(),
            actions: vec![Action::Read],
            constraints: Constraints::new(),
            delegatable: false,
            max_uses: Some(999), // exceeds parent's 100
            ttl_secs: None,
        })
        .unwrap_err();

    assert!(matches!(err, AegisError::ScopeEscalation { .. }));
}

#[test]
fn max_uses_inherited_from_parent_when_omitted() {
    let (issuer, delegation) = setup();
    let parent = issue_delegatable(&issuer); // max_uses = 100

    let child = delegation
        .delegate(DelegationRequest {
            parent_token_id: parent.token.id(),
            new_subject: "child-agent".into(),
            actions: vec![Action::Read],
            constraints: Constraints::new(),
            delegatable: false,
            max_uses: None, // should inherit parent's 100
            ttl_secs: None,
        })
        .unwrap();

    assert_eq!(child.token.max_uses(), Some(100));
}

// ── 4. TTL clamping ────────────────────────────────────────────────────

#[test]
fn ttl_clamped_to_parent_remaining() {
    let (issuer, delegation) = setup();
    let parent = issue_delegatable(&issuer); // 3600s TTL

    let child = delegation
        .delegate(DelegationRequest {
            parent_token_id: parent.token.id(),
            new_subject: "child-agent".into(),
            actions: vec![Action::Read],
            constraints: Constraints::new(),
            delegatable: false,
            max_uses: None,
            ttl_secs: Some(999_999), // Way more than parent's remaining ~3600s
        })
        .unwrap();

    let parent_exp = parent.token.expires_at().unwrap();
    let child_exp = child.token.expires_at().unwrap();
    assert!(child_exp <= parent_exp, "child TTL must not exceed parent");
}

#[test]
fn ttl_shorter_than_parent_allowed() {
    let (issuer, delegation) = setup();
    let parent = issue_delegatable(&issuer); // 3600s TTL

    let child = delegation
        .delegate(DelegationRequest {
            parent_token_id: parent.token.id(),
            new_subject: "child-agent".into(),
            actions: vec![Action::Read],
            constraints: Constraints::new(),
            delegatable: false,
            max_uses: None,
            ttl_secs: Some(60), // Much shorter
        })
        .unwrap();

    let child_exp = child.token.expires_at().unwrap();
    let issued = child.token.issued_at();
    let ttl = (child_exp - issued).num_seconds();
    assert!((58..=62).contains(&ttl), "Expected ~60s TTL, got {ttl}s");
}

// ── 5. Constraints carry forward ────────────────────────────────────────

#[test]
fn parent_constraints_carry_forward() {
    let (issuer, delegation) = setup();

    // Issue parent with constraints
    let parent = issuer
        .issue(aegis_core::TokenRequest {
            subject: "root-agent".into(),
            resource: Resource::new("file:///data/reports").unwrap(),
            actions: vec![Action::Read, Action::Write],
            constraints: Constraints::new()
                .add("format", ParamConstraint::Exact("json".into()))
                .unwrap(),
            ttl: Some(Duration::from_secs(3600)),
            delegatable: true,
            max_uses: None,
        })
        .unwrap();

    // Delegate with additional constraint
    let child = delegation
        .delegate(DelegationRequest {
            parent_token_id: parent.token.id(),
            new_subject: "child-agent".into(),
            actions: vec![Action::Read],
            constraints: Constraints::new()
                .add(
                    "limit",
                    ParamConstraint::Range {
                        min: 1.0,
                        max: 100.0,
                    },
                )
                .unwrap(),
            delegatable: false,
            max_uses: None,
            ttl_secs: None,
        })
        .unwrap();

    // Child should have both constraints
    assert!(child.token.constraints().get("format").is_some());
    assert!(child.token.constraints().get("limit").is_some());
    assert_eq!(child.token.constraints().len(), 2);
}

// ── 6. Revoked parent → delegation fails ────────────────────────────────

#[test]
fn delegation_from_revoked_parent_rejected() {
    let (issuer, delegation) = setup();
    let parent = issue_delegatable(&issuer);
    let parent_id = parent.token.id();

    // Revoke the parent
    delegation.revoke_cascade(parent_id).unwrap();

    let err = delegation
        .delegate(DelegationRequest {
            parent_token_id: parent_id,
            new_subject: "child-agent".into(),
            actions: vec![Action::Read],
            constraints: Constraints::new(),
            delegatable: false,
            max_uses: None,
            ttl_secs: None,
        })
        .unwrap_err();

    assert!(matches!(err, AegisError::ParentRevoked { .. }));
}

// ── 7. Nonexistent parent → error ──────────────────────────────────────

#[test]
fn delegation_from_nonexistent_parent_errors() {
    let (_issuer, delegation) = setup();

    let err = delegation
        .delegate(DelegationRequest {
            parent_token_id: Uuid::new_v4(),
            new_subject: "child-agent".into(),
            actions: vec![Action::Read],
            constraints: Constraints::new(),
            delegatable: false,
            max_uses: None,
            ttl_secs: None,
        })
        .unwrap_err();

    assert!(matches!(err, AegisError::TokenNotFound { .. }));
}

// ── 8. Cascading revocation: 3-level chain ──────────────────────────────

#[test]
fn cascade_revocation_3_levels() {
    let (issuer, delegation) = setup();
    let root = issue_delegatable(&issuer);
    let root_id = root.token.id();

    // Level 1: derive from root
    let level1 = delegation
        .delegate(DelegationRequest {
            parent_token_id: root_id,
            new_subject: "level-1".into(),
            actions: vec![Action::Read, Action::Write],
            constraints: Constraints::new(),
            delegatable: true,
            max_uses: Some(50),
            ttl_secs: Some(1800),
        })
        .unwrap();

    // Level 2: derive from level 1
    let level2 = delegation
        .delegate(DelegationRequest {
            parent_token_id: level1.token.id(),
            new_subject: "level-2".into(),
            actions: vec![Action::Read],
            constraints: Constraints::new(),
            delegatable: true,
            max_uses: Some(10),
            ttl_secs: Some(600),
        })
        .unwrap();

    // Level 3: derive from level 2
    let level3 = delegation
        .delegate(DelegationRequest {
            parent_token_id: level2.token.id(),
            new_subject: "level-3".into(),
            actions: vec![Action::Read],
            constraints: Constraints::new(),
            delegatable: false,
            max_uses: Some(5),
            ttl_secs: Some(300),
        })
        .unwrap();

    // Verify chain
    assert_eq!(level1.token.parent_id(), Some(root_id));
    assert_eq!(level2.token.parent_id(), Some(level1.token.id()));
    assert_eq!(level3.token.parent_id(), Some(level2.token.id()));

    // Revoke root → should cascade to all
    let revoked = delegation.revoke_cascade(root_id).unwrap();
    assert_eq!(revoked.len(), 4); // root + 3 levels

    // All should now be revoked
    assert!(delegation.store().get(root_id).unwrap().token.is_revoked());
    assert!(delegation
        .store()
        .get(level1.token.id())
        .unwrap()
        .token
        .is_revoked());
    assert!(delegation
        .store()
        .get(level2.token.id())
        .unwrap()
        .token
        .is_revoked());
    assert!(delegation
        .store()
        .get(level3.token.id())
        .unwrap()
        .token
        .is_revoked());
}

// ── 9. Cascading revocation: mid-chain ──────────────────────────────────

#[test]
fn cascade_revocation_mid_chain() {
    let (issuer, delegation) = setup();
    let root = issue_delegatable(&issuer);

    let mid = delegation
        .delegate(DelegationRequest {
            parent_token_id: root.token.id(),
            new_subject: "mid".into(),
            actions: vec![Action::Read, Action::Write],
            constraints: Constraints::new(),
            delegatable: true,
            max_uses: None,
            ttl_secs: None,
        })
        .unwrap();

    let leaf = delegation
        .delegate(DelegationRequest {
            parent_token_id: mid.token.id(),
            new_subject: "leaf".into(),
            actions: vec![Action::Read],
            constraints: Constraints::new(),
            delegatable: false,
            max_uses: None,
            ttl_secs: None,
        })
        .unwrap();

    // Revoke mid → leaf should cascade, root should NOT
    let revoked = delegation.revoke_cascade(mid.token.id()).unwrap();
    assert_eq!(revoked.len(), 2); // mid + leaf

    assert!(!delegation
        .store()
        .get(root.token.id())
        .unwrap()
        .token
        .is_revoked());
    assert!(delegation
        .store()
        .get(mid.token.id())
        .unwrap()
        .token
        .is_revoked());
    assert!(delegation
        .store()
        .get(leaf.token.id())
        .unwrap()
        .token
        .is_revoked());
}

// ── 10. Fan-out revocation ──────────────────────────────────────────────

#[test]
fn fan_out_revocation() {
    let (issuer, delegation) = setup();
    let root = issue_delegatable(&issuer);

    // Create 10 children from the same root
    let mut child_ids = Vec::new();
    for i in 0..10 {
        let child = delegation
            .delegate(DelegationRequest {
                parent_token_id: root.token.id(),
                new_subject: format!("child-{i}"),
                actions: vec![Action::Read],
                constraints: Constraints::new(),
                delegatable: false,
                max_uses: None,
                ttl_secs: None,
            })
            .unwrap();
        child_ids.push(child.token.id());
    }

    // Revoke root → all 10 children + root revoked
    let revoked = delegation.revoke_cascade(root.token.id()).unwrap();
    assert_eq!(revoked.len(), 11);

    for id in &child_ids {
        assert!(delegation.store().get(*id).unwrap().token.is_revoked());
    }
}

// ── 11. Revoking a leaf has no side effects ─────────────────────────────

#[test]
fn revoking_leaf_only_affects_leaf() {
    let (issuer, delegation) = setup();
    let root = issue_delegatable(&issuer);

    let child = delegation
        .delegate(DelegationRequest {
            parent_token_id: root.token.id(),
            new_subject: "child".into(),
            actions: vec![Action::Read],
            constraints: Constraints::new(),
            delegatable: false,
            max_uses: None,
            ttl_secs: None,
        })
        .unwrap();

    let revoked = delegation.revoke_cascade(child.token.id()).unwrap();
    assert_eq!(revoked.len(), 1);

    assert!(!delegation
        .store()
        .get(root.token.id())
        .unwrap()
        .token
        .is_revoked());
    assert!(delegation
        .store()
        .get(child.token.id())
        .unwrap()
        .token
        .is_revoked());
}

// ── 12. Double revoke is idempotent ─────────────────────────────────────

#[test]
fn double_cascade_revoke_is_idempotent() {
    let (issuer, delegation) = setup();
    let root = issue_delegatable(&issuer);

    delegation.revoke_cascade(root.token.id()).unwrap();
    let revoked = delegation.revoke_cascade(root.token.id()).unwrap();
    // Second time: already revoked, so nothing new
    assert!(revoked.is_empty());
}

// ── 13. children_of and ancestor_chain ──────────────────────────────────

#[test]
fn children_of_returns_direct_children() {
    let (issuer, delegation) = setup();
    let root = issue_delegatable(&issuer);

    for i in 0..3 {
        delegation
            .delegate(DelegationRequest {
                parent_token_id: root.token.id(),
                new_subject: format!("child-{i}"),
                actions: vec![Action::Read],
                constraints: Constraints::new(),
                delegatable: false,
                max_uses: None,
                ttl_secs: None,
            })
            .unwrap();
    }

    let children = delegation.children_of(root.token.id());
    assert_eq!(children.len(), 3);
}

#[test]
fn ancestor_chain_returns_full_path() {
    let (issuer, delegation) = setup();
    let root = issue_delegatable(&issuer);

    let mid = delegation
        .delegate(DelegationRequest {
            parent_token_id: root.token.id(),
            new_subject: "mid".into(),
            actions: vec![Action::Read],
            constraints: Constraints::new(),
            delegatable: true,
            max_uses: None,
            ttl_secs: None,
        })
        .unwrap();

    let leaf = delegation
        .delegate(DelegationRequest {
            parent_token_id: mid.token.id(),
            new_subject: "leaf".into(),
            actions: vec![Action::Read],
            constraints: Constraints::new(),
            delegatable: false,
            max_uses: None,
            ttl_secs: None,
        })
        .unwrap();

    let chain = delegation.ancestor_chain(leaf.token.id()).unwrap();
    assert_eq!(chain, vec![mid.token.id(), root.token.id()]);
}

// ── 14. Empty subject in delegation rejected ────────────────────────────

#[test]
fn delegation_empty_subject_rejected() {
    let (issuer, delegation) = setup();
    let parent = issue_delegatable(&issuer);

    let err = delegation
        .delegate(DelegationRequest {
            parent_token_id: parent.token.id(),
            new_subject: String::new(),
            actions: vec![Action::Read],
            constraints: Constraints::new(),
            delegatable: false,
            max_uses: None,
            ttl_secs: None,
        })
        .unwrap_err();

    assert!(matches!(err, AegisError::EmptySubject));
}

// ── 15. Empty actions in delegation rejected ────────────────────────────

#[test]
fn delegation_empty_actions_rejected() {
    let (issuer, delegation) = setup();
    let parent = issue_delegatable(&issuer);

    let err = delegation
        .delegate(DelegationRequest {
            parent_token_id: parent.token.id(),
            new_subject: "child".into(),
            actions: vec![],
            constraints: Constraints::new(),
            delegatable: false,
            max_uses: None,
            ttl_secs: None,
        })
        .unwrap_err();

    assert!(matches!(err, AegisError::NoActions));
}

// ── 16. Multi-level delegation with narrowing at each step ──────────────

#[test]
fn multi_level_progressive_narrowing() {
    let (issuer, delegation) = setup();

    // Root: Read + Write + Execute, delegatable, max_uses=100
    let root = issue_delegatable(&issuer);

    // Level 1: Read + Write, delegatable, max_uses=50
    let l1 = delegation
        .delegate(DelegationRequest {
            parent_token_id: root.token.id(),
            new_subject: "l1".into(),
            actions: vec![Action::Read, Action::Write],
            constraints: Constraints::new(),
            delegatable: true,
            max_uses: Some(50),
            ttl_secs: Some(1800),
        })
        .unwrap();

    // Level 2: Read only, not delegatable, max_uses=10
    let l2 = delegation
        .delegate(DelegationRequest {
            parent_token_id: l1.token.id(),
            new_subject: "l2".into(),
            actions: vec![Action::Read],
            constraints: Constraints::new(),
            delegatable: false,
            max_uses: Some(10),
            ttl_secs: Some(600),
        })
        .unwrap();

    assert_eq!(l2.token.actions(), &[Action::Read]);
    assert!(!l2.token.is_delegatable());
    assert_eq!(l2.token.max_uses(), Some(10));

    // Cannot delegate from l2 since it's not delegatable
    let err = delegation
        .delegate(DelegationRequest {
            parent_token_id: l2.token.id(),
            new_subject: "l3".into(),
            actions: vec![Action::Read],
            constraints: Constraints::new(),
            delegatable: false,
            max_uses: None,
            ttl_secs: None,
        })
        .unwrap_err();
    assert!(matches!(err, AegisError::NotDelegatable { .. }));
}

// ── 17. Resource is always inherited from parent ────────────────────────

#[test]
fn derived_token_inherits_parent_resource() {
    let (issuer, delegation) = setup();
    let parent = issue_delegatable(&issuer);

    let child = delegation
        .delegate(DelegationRequest {
            parent_token_id: parent.token.id(),
            new_subject: "child".into(),
            actions: vec![Action::Read],
            constraints: Constraints::new(),
            delegatable: false,
            max_uses: None,
            ttl_secs: None,
        })
        .unwrap();

    assert_eq!(child.token.resource(), parent.token.resource());
}
