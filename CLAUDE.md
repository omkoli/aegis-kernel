# CLAUDE.md

Guidance for Claude Code when working in this repository.

## Project

**Aegis Kernel** — a capability-based security kernel for AI agent tool-call
authorization, written in Rust. Agents must present a cryptographically signed
capability token (Ed25519) to invoke any tool. An enforcement engine validates
every call through a 9-step fail-fast pipeline and emits an audit trail.

Core design principles (see `ARCHITECTURE.md` for detail):

1. **Deny by default** — no token means no access; every deny is audited.
2. **Fail fast** — validation short-circuits at the first failure.
3. **Cryptographic integrity** — Ed25519 + canonical JSON for deterministic signing.
4. **Least privilege via delegation** — delegated tokens can only narrow scope.
5. **Cascading revocation** — revoking a parent revokes its entire subtree.

## Workspace Layout

Cargo workspace (`Cargo.toml` at the root) with seven crates:

| Crate | Role |
|-------|------|
| `aegis-core` | `CapabilityToken`, signing, store, issuer, validator, delegation, enforcement engine. The heart of the kernel. |
| `aegis-policy` | Policy schema, YAML compiler, and file watcher that turns declarative policies into token issuance rules. |
| `aegis-audit` | Audit log store, query API, and JSON-Lines exporter. |
| `aegis-handle` | `KernelHandle` — the single embedding interface the MCP gateway uses to evaluate tool calls against policies. |
| `aegis-mcp` | MCP (Model Context Protocol) framing, message parsing, and translation to/from enforcement intents. Supports stdio and SSE transports. |
| `aegis-gateway` | Proxy middleware chain: identity resolution, allowlist, rate limiting, interception, metrics, and audit writer. |
| `aegis-api` | Management API (HTTP via axum; optional gRPC behind the `grpc` feature) for issuing, revoking, and inspecting tokens. |

Supporting directories:

- `dashboards/` — Grafana dashboard JSON.
- `demo/` — Python demo agents (`agent_claude.py`, `agent_openai.py`).
- `.github/workflows/ci.yml` — CI pipeline.

## Common Commands

```bash
# Run the full test suite (all crates)
cargo test --workspace

# Release-mode tests (required for perf-sensitive tests)
cargo test --workspace --release

# Lint — CI runs with -D warnings, so fix every warning
cargo clippy --workspace --all-targets --all-features -- -D warnings

# Formatting — CI runs --check
cargo fmt --all

# Benchmarks (Criterion, in aegis-core)
cargo bench -p aegis-core

# Run a single crate's tests
cargo test -p aegis-core
```

CI (`.github/workflows/ci.yml`) enforces:

- `cargo fmt --all -- --check`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo nextest run --all-features`
- Criterion benchmarks on PRs
- Docker image build + push to GHCR on `main`

Always run `cargo fmt` and `cargo clippy --all-targets --all-features -- -D warnings`
before committing — CI will fail otherwise.

## Architectural Notes for Edits

- **Canonical JSON is load-bearing.** `aegis-core/src/canonical.rs` recursively
  sorts object keys before serialization so signatures are deterministic. Do
  not bypass it when signing or verifying; any new signed payload must go
  through `canonical_json()`.
- **The 9-step validator pipeline** (`aegis-core/src/validation.rs`) is
  fail-fast and ordered: lookup → signature → expiry → revocation → subject →
  resource → action → constraints → usage. Preserve ordering when adding new
  checks, and make sure every new deny path produces an `AuditEntry`.
- **Usage counts live outside the token.** They are tracked in a
  `DashMap<Uuid, AtomicU32>` inside `TokenValidator`, not on `CapabilityToken`
  itself. Do not add mutable counters to the token struct.
- **Delegation narrows, never widens.** `DelegationService::delegate()` must
  reject any child that expands actions, extends TTL, raises `max_uses`, or
  loosens constraints relative to its parent.
- **Revocation cascades via BFS.** `revoke_cascade()` walks `parent_id` links
  and re-signs revoked children so stored signatures stay consistent.
- **Concurrency model:** `InMemoryTokenStore` uses `DashMap`; services take
  `Arc<T: TokenStore>`. The enforcement engine is `Send + Sync`. Keep new
  shared state lock-free or sharded where possible.
- **Error surface:** `AegisError` in `aegis-core/src/error.rs` is a single
  `thiserror` enum. Add new failure modes as new variants rather than stuffing
  them into existing ones.

## Coding Conventions

- Rust 2021 edition, stable toolchain.
- Prefer `Arc<dyn Trait>` / `Arc<T: Trait>` for shared services; avoid
  `RefCell`/`Mutex` in hot paths — reach for `DashMap` or atomics first.
- New public APIs need integration tests under the crate's `tests/` directory.
  `aegis-core` currently has 127 integration tests across 7 files; match that
  style (one file per subsystem, deny-path coverage for every new check).
- Criterion benchmarks go in `aegis-core/benches/benchmarks.rs` — add a case
  when you touch a hot path (issuance, validation, delegation, enforcement).
- Keep signed payloads canonical. Never reorder struct fields expecting the
  signature to survive — canonicalization handles ordering, but adding/removing
  fields changes the bytes.

## Git Workflow for This Session

- Develop on branch **`claude/general-session-ZbKeW`**. Create it if missing.
- Commit with clear, descriptive messages and push to that branch only.
- Do **not** push to `main` or any other branch without explicit permission.
- Do **not** open a pull request unless explicitly asked.

## Things to Avoid

- Don't amend published commits; create new commits instead.
- Don't use `--no-verify` or skip hooks.
- Don't introduce new top-level crates without updating the workspace
  `members` list in the root `Cargo.toml`.
- Don't add `unsafe` without a clear justification — this is a security kernel.
- Don't log raw token bytes, signing keys, or unredacted tool parameters;
  the gateway has a `redact_parameters` helper for a reason.
