# Aegis Kernel — Architecture

## Overview

Aegis Kernel is a capability-based security kernel that gates AI agent tool calls through cryptographically signed tokens. Every tool invocation must present a valid token; the enforcement engine validates it through a 9-step pipeline and produces an audit trail.

## Design Principles

1. **Deny by default** — no token means no access. Every deny path is audited.
2. **Fail fast** — the validation pipeline short-circuits at the first failure.
3. **Cryptographic integrity** — Ed25519 signatures prevent token forgery and detect tampering.
4. **Deterministic signing** — canonical JSON (recursively sorted keys) ensures the same token always produces identical bytes for signing.
5. **Least privilege via delegation** — delegated tokens can only narrow scope, never widen it.
6. **Cascading revocation** — revoking a parent revokes the entire subtree.

## Module Map

### `token.rs` — CapabilityToken

The central data structure. Fields:

- `id: Uuid` — unique identifier
- `subject: String` — the agent identity this token is bound to
- `resource: Resource` — the target resource (URI-like path)
- `actions: Vec<Action>` — permitted operations (Read, Write, Execute, Delete, Custom)
- `constraints: Constraints` — parameter-level restrictions
- `issued_at / expires_at: DateTime<Utc>` — validity window
- `delegatable: bool` — whether this token can be delegated
- `max_uses: Option<u32>` — usage cap (None = unlimited)
- `revoked: bool` — revocation flag
- `parent_id: Option<Uuid>` — links to parent for delegation chains

### `resource.rs` — Resource, Action, Constraints

- `Resource` validates non-empty paths and provides `path()` access.
- `Action` is an enum (Read, Write, Execute, Delete, Custom).
- `Constraints` wraps `HashMap<String, ParamConstraint>` with a builder API.
- `ParamConstraint` variants: Exact, OneOf, Regex, Range.

### `error.rs` — AegisError

A single `thiserror`-derived enum with 25 variants covering all failure modes across issuance, validation, delegation, and signing.

### `signing.rs` — Ed25519 Signatures

- `TokenSigner` trait with `sign<T: Serialize>()` and `verify<T: Serialize>()`.
- `Ed25519TokenSigner` implements signing + verification (holds secret key).
- `Ed25519TokenVerifier` holds only the public key for verify-only contexts.
- `TokenSignature` wraps 64 bytes with hex serialization.
- Signing uses `canonical_json()` to produce deterministic bytes.

### `canonical.rs` — Canonical JSON

Recursively sorts all object keys before serialization. This ensures that field ordering in Rust structs or HashMap iteration order never affects the signed bytes.

### `store.rs` — Token Storage

- `TokenStore` trait: insert, get, list, delete, contains, len, is_empty.
- `InMemoryTokenStore`: `DashMap<Uuid, SignedToken>` for lock-free concurrent access.
- `SignedToken` pairs a `CapabilityToken` with its `TokenSignature`.

### `request.rs` — TokenRequest

Input struct for token issuance. TTL is expressed as `Option<Duration>` (serialized as seconds).

### `issuer.rs` — TokenIssuer

Accepts a `TokenRequest`, validates inputs (non-empty subject, non-empty actions, no duplicates), clamps TTL to `max_ttl`, creates a `CapabilityToken`, signs it, and stores the `SignedToken`. Thread-safe via `Arc<T: TokenStore>`.

### `validation.rs` — TokenValidator

9-step fail-fast pipeline:

```
1. Lookup token in store        → TokenNotFound
2. Verify Ed25519 signature     → SignatureInvalid
3. Check expiry                 → expired
4. Check revocation             → revoked
5. Match subject to agent_id    → does not match
6. Match resource               → resource mismatch
7. Check action is permitted    → not permitted
8. Validate parameter constraints → constraint violation
9. Check/increment usage count  → usage exhausted
```

Usage counts are tracked in a separate `DashMap<Uuid, AtomicU32>` within the validator, not in the token itself.

### `delegation.rs` — DelegationService

- `delegate()` enforces scope narrowing: child actions ⊆ parent actions, child TTL ≤ parent remaining TTL, child max_uses ≤ parent max_uses, child inherits parent constraints.
- `revoke_cascade()` uses BFS to find all descendants and revoke them. Revoked tokens are re-signed so the stored signature matches the updated state.
- `children_of()` and `ancestor_chain()` provide tree navigation.

### `enforcement.rs` — EnforcementEngine

Wraps `TokenValidator` and adds:

- `Decision` enum (Allow / Deny)
- `AuditEntry` with request_id, timestamp, agent/tool/action/resource, token_id, decision, reason, delegation chain, and latency measurement
- `resolve_chain()` walks parent_id links to build the full delegation chain

## Data Flow

```
Agent → ToolCallRequest → EnforcementEngine
                              │
                              ├─ TokenValidator.validate()
                              │     1. store.get(token_id)
                              │     2. signer.verify(token, sig)
                              │     3-9. policy checks
                              │
                              ├─ resolve_chain(token_id)
                              │
                              └─ EnforcementResult { decision, audit }
```

## Concurrency Model

- `InMemoryTokenStore` uses `DashMap` (sharded concurrent hash map) — no global locks.
- `TokenValidator` tracks usage counts in a separate `DashMap<Uuid, AtomicU32>`.
- All services accept `Arc<T: TokenStore>` for shared ownership.
- The enforcement engine is `Send + Sync` and safe to use from multiple threads.

## Testing Strategy

- **127 integration tests** across 7 test files covering every deny path, delegation scenarios, cascading revocation, concurrent access (1000 agents), and mock agent simulations.
- **3 unit tests** for canonical JSON sorting.
- **7 Criterion benchmarks** for performance regression tracking.
- Performance-sensitive tests use `cfg!(debug_assertions)` to set appropriate thresholds for debug vs. release builds.
