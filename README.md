# Aegis Kernel

A capability-based security kernel for AI agent tool-call authorization, written in Rust.

Aegis Kernel provides token-gated access control: agents must present a cryptographically signed capability token to invoke any tool. Each token encodes a subject, resource, permitted actions, parameter constraints, expiration, and optional delegation rights. An enforcement engine validates every call and produces a full audit trail.

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────────────┐
│ TokenIssuer │────▶│ InMemoryStore│◀────│ EnforcementEngine   │
│  (issue)    │     │  (DashMap)   │     │  (validate + audit) │
└─────────────┘     └──────────────┘     └─────────────────────┘
       │                   ▲                       │
       ▼                   │                       ▼
┌─────────────┐     ┌──────────────┐     ┌─────────────────────┐
│  Ed25519    │     │ Delegation   │     │  TokenValidator     │
│  Signer     │     │  Service     │     │  (9-step pipeline)  │
└─────────────┘     └──────────────┘     └─────────────────────┘
```

## Quick Start

```rust
use std::sync::Arc;
use std::time::Duration;
use aegis_core::*;

// Set up signing and storage
let signer = Ed25519TokenSigner::generate();
let store = Arc::new(InMemoryTokenStore::new());
let key_bytes = signer.signing_key_bytes();

let issuer = TokenIssuer::new(
    Ed25519TokenSigner::from_bytes(&key_bytes),
    Arc::clone(&store),
    IssuerConfig::default(),
);
let engine = EnforcementEngine::new(signer, store);

// Issue a token
let signed = issuer.issue(TokenRequest {
    subject: "agent-1".into(),
    resource: Resource::new("file:///data/reports").unwrap(),
    actions: vec![Action::Read],
    constraints: Constraints::new(),
    ttl: Some(Duration::from_secs(3600)),
    delegatable: false,
    max_uses: Some(100),
}).unwrap();

// Enforce a tool call
let result = engine.enforce(&ToolCallRequest {
    agent_id: "agent-1".into(),
    tool_name: "read_file".into(),
    action: Action::Read,
    resource: Resource::new("file:///data/reports").unwrap(),
    parameters: std::collections::HashMap::new(),
    token_id: signed.token.id(),
});

assert_eq!(result.decision, Decision::Allow);
```

## Core Concepts

| Concept | Description |
|---------|-------------|
| **CapabilityToken** | Encodes who (subject), what (actions), where (resource), and under what conditions (constraints, TTL, max uses) a tool call is permitted. |
| **Ed25519 Signing** | Every token is signed with Ed25519. Canonical JSON serialization (sorted keys) ensures deterministic signatures. |
| **TokenIssuer** | Creates and signs tokens with TTL clamping and input validation. |
| **TokenValidator** | 9-step fail-fast pipeline: lookup, signature, expiry, revocation, subject, resource, action, constraints, usage. |
| **Delegation** | Tokens marked `delegatable` can be narrowed (fewer actions, shorter TTL, tighter constraints) and issued to downstream agents. |
| **Cascading Revocation** | Revoking a parent token revokes all descendants via BFS traversal. |
| **EnforcementEngine** | Wraps validation, resolves delegation chains, and emits `AuditEntry` records with latency tracking. |

## Constraints

Tokens support four kinds of parameter constraints:

- **Exact** — parameter must equal a specific value
- **OneOf** — parameter must be one of a set of values
- **Regex** — parameter must match a regex pattern
- **Range** — numeric parameter must fall within `[min, max]`

## Running

```bash
# Run all tests (127 tests + 3 doc tests)
cargo test --workspace

# Run with release optimizations (for performance tests)
cargo test --workspace --release

# Clippy
cargo clippy --workspace --all-targets -- -D warnings

# Benchmarks
cargo bench -p aegis-core
```

## Performance

Measured on release builds with Criterion:

| Benchmark | Median |
|-----------|--------|
| Token issuance | ~24 us |
| Enforcement decision | ~43 us |
| Delegation | ~24 us |
| Enforcement (delegated) | ~44 us |
| 100 concurrent agents | ~9 ms |
| 1000 concurrent agents | ~83 ms |

## Project Structure

```
aegis-kernel/
├── Cargo.toml              # Workspace root
└── aegis-core/
    ├── Cargo.toml
    ├── src/
    │   ├── lib.rs           # Module declarations and re-exports
    │   ├── token.rs         # CapabilityToken
    │   ├── resource.rs      # Resource, Action, Constraints, ParamConstraint
    │   ├── error.rs         # AegisError (25 variants)
    │   ├── signing.rs       # Ed25519 signing and verification
    │   ├── canonical.rs     # Deterministic JSON serialization
    │   ├── store.rs         # TokenStore trait + InMemoryTokenStore
    │   ├── request.rs       # TokenRequest
    │   ├── issuer.rs        # TokenIssuer service
    │   ├── validation.rs    # TokenValidator (9-step pipeline)
    │   ├── delegation.rs    # DelegationService with cascading revocation
    │   └── enforcement.rs   # EnforcementEngine + AuditEntry
    ├── tests/               # Integration tests (127 tests)
    │   ├── core_types.rs
    │   ├── signing.rs
    │   ├── issuer.rs
    │   ├── validation.rs
    │   ├── delegation.rs
    │   ├── enforcement.rs
    │   └── mock_agent.rs
    └── benches/
        └── benchmarks.rs    # Criterion benchmarks
```

## License

MIT
