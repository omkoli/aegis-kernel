use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

use aegis_core::{
    Action, Constraints, Decision, DelegationRequest, DelegationService, Ed25519TokenSigner,
    EnforcementEngine, InMemoryTokenStore, IssuerConfig, ParamConstraint, Resource, TokenIssuer,
    TokenRequest, ToolCallRequest,
};

// ── Shared setup ────────────────────────────────────────────────────────

struct Harness {
    issuer: TokenIssuer<Ed25519TokenSigner, InMemoryTokenStore>,
    delegation: DelegationService<Ed25519TokenSigner, InMemoryTokenStore>,
    engine: EnforcementEngine<Ed25519TokenSigner, InMemoryTokenStore>,
}

fn make_harness() -> Harness {
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

    Harness {
        issuer,
        delegation,
        engine,
    }
}

fn base_request() -> TokenRequest {
    TokenRequest {
        subject: "bench-agent".into(),
        resource: Resource::new("file:///data/bench").unwrap(),
        actions: vec![Action::Read, Action::Write],
        constraints: Constraints::new(),
        ttl: Some(Duration::from_secs(3600)),
        delegatable: true,
        max_uses: None,
    }
}

// ── Benchmark: Token Issuance ───────────────────────────────────────────

fn bench_issuance(c: &mut Criterion) {
    let h = make_harness();

    c.bench_function("token_issuance", |b| {
        b.iter(|| {
            let req = base_request();
            black_box(h.issuer.issue(req).unwrap());
        })
    });
}

// ── Benchmark: Token Issuance with Constraints ──────────────────────────

fn bench_issuance_with_constraints(c: &mut Criterion) {
    let h = make_harness();

    c.bench_function("token_issuance_constrained", |b| {
        b.iter(|| {
            let req = TokenRequest {
                subject: "bench-agent".into(),
                resource: Resource::new("file:///data/bench").unwrap(),
                actions: vec![Action::Read],
                constraints: Constraints::new()
                    .add(
                        "amount",
                        ParamConstraint::Range {
                            min: 0.0,
                            max: 1000.0,
                        },
                    )
                    .unwrap()
                    .add("format", ParamConstraint::Exact("json".into()))
                    .unwrap(),
                ttl: Some(Duration::from_secs(600)),
                delegatable: false,
                max_uses: Some(100),
            };
            black_box(h.issuer.issue(req).unwrap());
        })
    });
}

// ── Benchmark: Validation (via EnforcementEngine) ───────────────────────

fn bench_enforcement_decision(c: &mut Criterion) {
    let h = make_harness();
    let signed = h.issuer.issue(base_request()).unwrap();
    let call = ToolCallRequest {
        agent_id: "bench-agent".into(),
        tool_name: "read_data".into(),
        action: Action::Read,
        resource: Resource::new("file:///data/bench").unwrap(),
        parameters: HashMap::new(),
        token_id: signed.token.id(),
    };

    c.bench_function("enforcement_decision", |b| {
        b.iter(|| {
            let result = h.engine.enforce(black_box(&call));
            assert_eq!(result.decision, Decision::Allow);
            black_box(result);
        })
    });
}

// ── Benchmark: Validation with Constraints ──────────────────────────────

fn bench_enforcement_with_constraints(c: &mut Criterion) {
    let h = make_harness();
    let signed = h
        .issuer
        .issue(TokenRequest {
            subject: "bench-agent".into(),
            resource: Resource::new("file:///data/bench").unwrap(),
            actions: vec![Action::Read],
            constraints: Constraints::new()
                .add(
                    "amount",
                    ParamConstraint::Range {
                        min: 0.0,
                        max: 1000.0,
                    },
                )
                .unwrap()
                .add("format", ParamConstraint::Exact("json".into()))
                .unwrap(),
            ttl: Some(Duration::from_secs(3600)),
            delegatable: false,
            max_uses: None,
        })
        .unwrap();

    let call = ToolCallRequest {
        agent_id: "bench-agent".into(),
        tool_name: "read_data".into(),
        action: Action::Read,
        resource: Resource::new("file:///data/bench").unwrap(),
        parameters: HashMap::from([
            ("amount".into(), "500".into()),
            ("format".into(), "json".into()),
        ]),
        token_id: signed.token.id(),
    };

    c.bench_function("enforcement_constrained", |b| {
        b.iter(|| {
            let result = h.engine.enforce(black_box(&call));
            assert_eq!(result.decision, Decision::Allow);
            black_box(result);
        })
    });
}

// ── Benchmark: Delegation ───────────────────────────────────────────────

fn bench_delegation(c: &mut Criterion) {
    let h = make_harness();
    let parent = h.issuer.issue(base_request()).unwrap();

    c.bench_function("delegation", |b| {
        b.iter(|| {
            let req = DelegationRequest {
                parent_token_id: parent.token.id(),
                new_subject: "delegated-agent".into(),
                actions: vec![Action::Read],
                constraints: Constraints::new(),
                delegatable: false,
                max_uses: None,
                ttl_secs: Some(600),
            };
            black_box(h.delegation.delegate(req).unwrap());
        })
    });
}

// ── Benchmark: Enforcement with delegation chain ────────────────────────

fn bench_enforcement_delegated(c: &mut Criterion) {
    let h = make_harness();
    let parent = h.issuer.issue(base_request()).unwrap();
    let child = h
        .delegation
        .delegate(DelegationRequest {
            parent_token_id: parent.token.id(),
            new_subject: "delegated-agent".into(),
            actions: vec![Action::Read],
            constraints: Constraints::new(),
            delegatable: false,
            max_uses: None,
            ttl_secs: Some(600),
        })
        .unwrap();

    let call = ToolCallRequest {
        agent_id: "delegated-agent".into(),
        tool_name: "read_data".into(),
        action: Action::Read,
        resource: Resource::new("file:///data/bench").unwrap(),
        parameters: HashMap::new(),
        token_id: child.token.id(),
    };

    c.bench_function("enforcement_delegated", |b| {
        b.iter(|| {
            let result = h.engine.enforce(black_box(&call));
            assert_eq!(result.decision, Decision::Allow);
            black_box(result);
        })
    });
}

// ── Benchmark: Concurrent (throughput) ──────────────────────────────────

fn bench_concurrent(c: &mut Criterion) {
    let mut group = c.benchmark_group("concurrent");

    for &num_agents in &[10, 100, 1000] {
        group.bench_with_input(
            BenchmarkId::new("agents", num_agents),
            &num_agents,
            |b, &n| {
                let signer = Ed25519TokenSigner::generate();
                let store = Arc::new(InMemoryTokenStore::new());
                let key_bytes = signer.signing_key_bytes();

                let issuer = TokenIssuer::new(
                    Ed25519TokenSigner::from_bytes(&key_bytes),
                    Arc::clone(&store),
                    IssuerConfig::default(),
                );
                let engine = Arc::new(EnforcementEngine::new(signer, Arc::clone(&store)));
                let resource = Resource::new("api://bench/data").unwrap();

                // Pre-issue tokens
                let agents: Vec<_> = (0..n)
                    .map(|i| {
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
                        (agent_id, signed.token.id())
                    })
                    .collect();

                b.iter(|| {
                    let handles: Vec<_> = agents
                        .iter()
                        .map(|(agent_id, token_id)| {
                            let engine = Arc::clone(&engine);
                            let agent_id = agent_id.clone();
                            let resource = resource.clone();
                            let token_id = *token_id;
                            std::thread::spawn(move || {
                                let request = ToolCallRequest {
                                    agent_id,
                                    tool_name: "fetch".into(),
                                    action: Action::Read,
                                    resource,
                                    parameters: HashMap::new(),
                                    token_id,
                                };
                                let result = engine.enforce(&request);
                                assert_eq!(result.decision, Decision::Allow);
                            })
                        })
                        .collect();

                    for h in handles {
                        h.join().unwrap();
                    }
                });
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_issuance,
    bench_issuance_with_constraints,
    bench_enforcement_decision,
    bench_enforcement_with_constraints,
    bench_delegation,
    bench_enforcement_delegated,
    bench_concurrent,
);
criterion_main!(benches);
