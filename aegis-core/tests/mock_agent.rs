//! Mock Agent Simulation Harness
//!
//! Provides a `MockAgent` that holds a capability token and can make tool
//! calls through the `EnforcementEngine`, collecting audit entries.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use aegis_core::{
    Action, Constraints, Decision, DelegationRequest, DelegationService, Ed25519TokenSigner,
    EnforcementEngine, EnforcementResult, InMemoryTokenStore, IssuerConfig, ParamConstraint,
    Resource, TokenIssuer, TokenRequest, ToolCallRequest,
};
use uuid::Uuid;

// ── Test harness ────────────────────────────────────────────────────────

/// A simulated agent that presents a capability token for tool calls.
struct MockAgent {
    id: String,
    token_id: Uuid,
}

impl MockAgent {
    fn new(id: impl Into<String>, token_id: Uuid) -> Self {
        Self {
            id: id.into(),
            token_id,
        }
    }

    /// Makes a tool call through the enforcement engine.
    fn call(
        &self,
        engine: &EnforcementEngine<Ed25519TokenSigner, InMemoryTokenStore>,
        tool_name: &str,
        action: Action,
        resource: &Resource,
        parameters: HashMap<String, String>,
    ) -> EnforcementResult {
        let request = ToolCallRequest {
            agent_id: self.id.clone(),
            tool_name: tool_name.to_string(),
            action,
            resource: resource.clone(),
            parameters,
            token_id: self.token_id,
        };
        engine.enforce(&request)
    }
}

/// Shared infrastructure for all scenarios.
struct TestHarness {
    issuer: TokenIssuer<Ed25519TokenSigner, InMemoryTokenStore>,
    delegation: DelegationService<Ed25519TokenSigner, InMemoryTokenStore>,
    engine: EnforcementEngine<Ed25519TokenSigner, InMemoryTokenStore>,
}

impl TestHarness {
    fn new() -> Self {
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

        Self {
            issuer,
            delegation,
            engine,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Scenario 1: Finance — Read DB, $1000 cap, 60s TTL
//
// ALLOW read, DENY write, DENY after expiry
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn scenario_finance_read_db() {
    let h = TestHarness::new();
    let resource = Resource::new("db://finance/transactions").unwrap();

    let signed = h
        .issuer
        .issue(TokenRequest {
            subject: "finance-agent".into(),
            resource: resource.clone(),
            actions: vec![Action::Read],
            constraints: Constraints::new()
                .add(
                    "amount",
                    ParamConstraint::Range {
                        min: 0.0,
                        max: 1000.0,
                    },
                )
                .unwrap(),
            ttl: Some(Duration::from_secs(2)), // short TTL for expiry test below
            delegatable: false,
            max_uses: None,
        })
        .unwrap();

    let agent = MockAgent::new("finance-agent", signed.token.id());

    // 1. ALLOW read with amount within cap
    let r = agent.call(
        &h.engine,
        "query_db",
        Action::Read,
        &resource,
        HashMap::from([("amount".into(), "500".into())]),
    );
    assert_eq!(
        r.decision,
        Decision::Allow,
        "read within $1000 cap: {}",
        r.audit.reason
    );

    // 2. DENY write (not in actions)
    let r = agent.call(
        &h.engine,
        "query_db",
        Action::Write,
        &resource,
        HashMap::new(),
    );
    assert_eq!(r.decision, Decision::Deny, "write should be denied");
    assert!(r.audit.reason.contains("not permitted"));

    // 3. DENY amount exceeding $1000 cap
    let r = agent.call(
        &h.engine,
        "query_db",
        Action::Read,
        &resource,
        HashMap::from([("amount".into(), "1500".into())]),
    );
    assert_eq!(
        r.decision,
        Decision::Deny,
        "amount over cap should be denied"
    );
    assert!(r.audit.reason.contains("constraint violation"));

    // 4. DENY after expiry
    std::thread::sleep(Duration::from_secs(3));
    let r = agent.call(
        &h.engine,
        "query_db",
        Action::Read,
        &resource,
        HashMap::from([("amount".into(), "100".into())]),
    );
    assert_eq!(r.decision, Decision::Deny, "should deny after expiry");
    assert!(r.audit.reason.contains("expired"));
}

// ═══════════════════════════════════════════════════════════════════════
// Scenario 2: Email — Send to @company.com, 10 uses
//
// ALLOW internal, DENY external, DENY 11th
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn scenario_email_domain_and_usage() {
    let h = TestHarness::new();
    let resource = Resource::new("smtp://mail.company.com/send").unwrap();

    let signed = h
        .issuer
        .issue(TokenRequest {
            subject: "email-agent".into(),
            resource: resource.clone(),
            actions: vec![Action::custom("send").unwrap()],
            constraints: Constraints::new()
                .add(
                    "recipient_domain",
                    ParamConstraint::Exact("company.com".into()),
                )
                .unwrap(),
            ttl: Some(Duration::from_secs(3600)),
            delegatable: false,
            max_uses: Some(10),
        })
        .unwrap();

    let agent = MockAgent::new("email-agent", signed.token.id());

    // 1. ALLOW internal email (company.com)
    let r = agent.call(
        &h.engine,
        "send_email",
        Action::custom("send").unwrap(),
        &resource,
        HashMap::from([("recipient_domain".into(), "company.com".into())]),
    );
    assert_eq!(
        r.decision,
        Decision::Allow,
        "internal email: {}",
        r.audit.reason
    );

    // 2. DENY external email (gmail.com)
    let r = agent.call(
        &h.engine,
        "send_email",
        Action::custom("send").unwrap(),
        &resource,
        HashMap::from([("recipient_domain".into(), "gmail.com".into())]),
    );
    assert_eq!(
        r.decision,
        Decision::Deny,
        "external email should be denied"
    );
    assert!(r.audit.reason.contains("constraint violation"));

    // 3. Use remaining 9 allowed calls (already used 1)
    for i in 2..=10 {
        let r = agent.call(
            &h.engine,
            "send_email",
            Action::custom("send").unwrap(),
            &resource,
            HashMap::from([("recipient_domain".into(), "company.com".into())]),
        );
        assert_eq!(r.decision, Decision::Allow, "use #{i} should be allowed");
    }

    // 4. DENY 11th use
    let r = agent.call(
        &h.engine,
        "send_email",
        Action::custom("send").unwrap(),
        &resource,
        HashMap::from([("recipient_domain".into(), "company.com".into())]),
    );
    assert_eq!(r.decision, Decision::Deny, "11th use should be denied");
    assert!(r.audit.reason.contains("usage exhausted"));
}

// ═══════════════════════════════════════════════════════════════════════
// Scenario 3: Delegation — A→B→C chain, narrowing scope
//
// C has narrowest scope. Revoke A = all denied.
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn scenario_delegation_chain() {
    let h = TestHarness::new();
    let resource = Resource::new("api://internal/data").unwrap();

    // Agent A: root token, Read + Write + Execute, delegatable
    let token_a = h
        .issuer
        .issue(TokenRequest {
            subject: "agent-a".into(),
            resource: resource.clone(),
            actions: vec![Action::Read, Action::Write, Action::Execute],
            constraints: Constraints::new(),
            ttl: Some(Duration::from_secs(3600)),
            delegatable: true,
            max_uses: Some(1000),
        })
        .unwrap();

    // Agent B: delegated from A, Read + Write only, delegatable
    let token_b = h
        .delegation
        .delegate(DelegationRequest {
            parent_token_id: token_a.token.id(),
            new_subject: "agent-b".into(),
            actions: vec![Action::Read, Action::Write],
            constraints: Constraints::new(),
            delegatable: true,
            max_uses: Some(500),
            ttl_secs: Some(1800),
        })
        .unwrap();

    // Agent C: delegated from B, Read only, NOT delegatable
    let token_c = h
        .delegation
        .delegate(DelegationRequest {
            parent_token_id: token_b.token.id(),
            new_subject: "agent-c".into(),
            actions: vec![Action::Read],
            constraints: Constraints::new()
                .add("format", ParamConstraint::Exact("json".into()))
                .unwrap(),
            delegatable: false,
            max_uses: Some(100),
            ttl_secs: Some(600),
        })
        .unwrap();

    let agent_a = MockAgent::new("agent-a", token_a.token.id());
    let agent_b = MockAgent::new("agent-b", token_b.token.id());
    let agent_c = MockAgent::new("agent-c", token_c.token.id());

    // A can do everything
    let r = agent_a.call(
        &h.engine,
        "api_call",
        Action::Execute,
        &resource,
        HashMap::new(),
    );
    assert_eq!(r.decision, Decision::Allow, "A execute: {}", r.audit.reason);

    // B can read and write, but NOT execute
    let r = agent_b.call(
        &h.engine,
        "api_call",
        Action::Read,
        &resource,
        HashMap::new(),
    );
    assert_eq!(r.decision, Decision::Allow, "B read: {}", r.audit.reason);
    let r = agent_b.call(
        &h.engine,
        "api_call",
        Action::Execute,
        &resource,
        HashMap::new(),
    );
    assert_eq!(r.decision, Decision::Deny, "B execute should be denied");

    // C can only read with format=json
    let r = agent_c.call(
        &h.engine,
        "api_call",
        Action::Read,
        &resource,
        HashMap::from([("format".into(), "json".into())]),
    );
    assert_eq!(
        r.decision,
        Decision::Allow,
        "C read json: {}",
        r.audit.reason
    );
    // C's audit should have a delegation chain
    assert_eq!(r.audit.token_chain.len(), 2); // [B, A]

    // C denied for Write
    let r = agent_c.call(
        &h.engine,
        "api_call",
        Action::Write,
        &resource,
        HashMap::new(),
    );
    assert_eq!(r.decision, Decision::Deny, "C write should be denied");

    // C denied for wrong format constraint
    let r = agent_c.call(
        &h.engine,
        "api_call",
        Action::Read,
        &resource,
        HashMap::from([("format".into(), "xml".into())]),
    );
    assert_eq!(r.decision, Decision::Deny, "C xml format should be denied");

    // Revoke A → cascade → all denied
    h.delegation.revoke_cascade(token_a.token.id()).unwrap();

    let r = agent_a.call(
        &h.engine,
        "api_call",
        Action::Read,
        &resource,
        HashMap::new(),
    );
    assert_eq!(
        r.decision,
        Decision::Deny,
        "A should be denied after revoke"
    );

    let r = agent_b.call(
        &h.engine,
        "api_call",
        Action::Read,
        &resource,
        HashMap::new(),
    );
    assert_eq!(
        r.decision,
        Decision::Deny,
        "B should be denied after cascade"
    );

    let r = agent_c.call(
        &h.engine,
        "api_call",
        Action::Read,
        &resource,
        HashMap::from([("format".into(), "json".into())]),
    );
    assert_eq!(
        r.decision,
        Decision::Deny,
        "C should be denied after cascade"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Scenario 4: Budget — Stripe, max $100/call
//
// ALLOW $50, DENY $150
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn scenario_budget_stripe() {
    let h = TestHarness::new();
    let resource = Resource::new("api://stripe.com/charges").unwrap();

    let signed = h
        .issuer
        .issue(TokenRequest {
            subject: "billing-agent".into(),
            resource: resource.clone(),
            actions: vec![Action::custom("charge").unwrap()],
            constraints: Constraints::new()
                .add(
                    "amount_cents",
                    ParamConstraint::Range {
                        min: 1.0,
                        max: 10000.0, // $100.00 max
                    },
                )
                .unwrap(),
            ttl: Some(Duration::from_secs(3600)),
            delegatable: false,
            max_uses: None,
        })
        .unwrap();

    let agent = MockAgent::new("billing-agent", signed.token.id());

    // 1. ALLOW $50 charge (5000 cents)
    let r = agent.call(
        &h.engine,
        "create_charge",
        Action::custom("charge").unwrap(),
        &resource,
        HashMap::from([("amount_cents".into(), "5000".into())]),
    );
    assert_eq!(
        r.decision,
        Decision::Allow,
        "$50 charge: {}",
        r.audit.reason
    );

    // 2. ALLOW exactly $100 (boundary, 10000 cents)
    let r = agent.call(
        &h.engine,
        "create_charge",
        Action::custom("charge").unwrap(),
        &resource,
        HashMap::from([("amount_cents".into(), "10000".into())]),
    );
    assert_eq!(
        r.decision,
        Decision::Allow,
        "$100 boundary: {}",
        r.audit.reason
    );

    // 3. DENY $150 charge (15000 cents > max 10000)
    let r = agent.call(
        &h.engine,
        "create_charge",
        Action::custom("charge").unwrap(),
        &resource,
        HashMap::from([("amount_cents".into(), "15000".into())]),
    );
    assert_eq!(r.decision, Decision::Deny, "$150 should be denied");
    assert!(r.audit.reason.contains("constraint violation"));

    // 4. DENY $0 charge (0 < min of 1)
    let r = agent.call(
        &h.engine,
        "create_charge",
        Action::custom("charge").unwrap(),
        &resource,
        HashMap::from([("amount_cents".into(), "0".into())]),
    );
    assert_eq!(r.decision, Decision::Deny, "$0 should be denied");

    // 5. DENY negative amount
    let r = agent.call(
        &h.engine,
        "create_charge",
        Action::custom("charge").unwrap(),
        &resource,
        HashMap::from([("amount_cents".into(), "-100".into())]),
    );
    assert_eq!(
        r.decision,
        Decision::Deny,
        "negative amount should be denied"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Scenario 5: Concurrent — 100 agents simultaneous
//
// All correct, no races, <1ms p99
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn scenario_concurrent_100_agents() {
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
    let engine = Arc::new(EnforcementEngine::new(signer, Arc::clone(&store)));

    let resource = Resource::new("api://shared-service/data").unwrap();

    // Issue 100 unique tokens, one per agent
    let mut agent_tokens: Vec<(String, Uuid)> = Vec::new();
    for i in 0..100 {
        let agent_id = format!("agent-{i}");
        let signed = issuer
            .issue(TokenRequest {
                subject: agent_id.clone(),
                resource: resource.clone(),
                actions: vec![Action::Read],
                constraints: Constraints::new(),
                ttl: Some(Duration::from_secs(3600)),
                delegatable: false,
                max_uses: None,
            })
            .unwrap();
        agent_tokens.push((agent_id, signed.token.id()));
    }

    // All 100 agents make calls simultaneously
    let handles: Vec<_> = agent_tokens
        .into_iter()
        .map(|(agent_id, token_id)| {
            let engine = Arc::clone(&engine);
            let resource = resource.clone();
            std::thread::spawn(move || {
                let request = ToolCallRequest {
                    agent_id,
                    tool_name: "fetch_data".into(),
                    action: Action::Read,
                    resource,
                    parameters: HashMap::new(),
                    token_id,
                };
                let start = std::time::Instant::now();
                let result = engine.enforce(&request);
                let elapsed_us = start.elapsed().as_micros() as u64;
                (result, elapsed_us)
            })
        })
        .collect();

    let mut latencies = Vec::new();
    for handle in handles {
        let (result, elapsed_us) = handle.join().unwrap();
        assert_eq!(
            result.decision,
            Decision::Allow,
            "agent {} should be allowed: {}",
            result.audit.agent_id,
            result.audit.reason
        );
        latencies.push(elapsed_us);
    }

    latencies.sort();
    let p99_idx = (latencies.len() as f64 * 0.99).ceil() as usize - 1;
    let p99_us = latencies[p99_idx];
    let avg_us = latencies.iter().sum::<u64>() as f64 / latencies.len() as f64;

    eprintln!(
        "100 concurrent agents: avg={avg_us:.0}µs, p99={p99_us}µs, max={}µs",
        latencies.last().unwrap()
    );

    // In debug mode, each validation includes Ed25519 verify (~8ms).
    // The <1ms p99 target is for release builds. In debug, we just verify
    // correctness (all 100 got Allow) and no races.
    // Release check: p99 < 1ms (1000µs)
    if !cfg!(debug_assertions) {
        assert!(p99_us < 1000, "p99 latency {p99_us}µs exceeds 1ms target");
    }
}
