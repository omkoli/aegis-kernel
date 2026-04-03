//! Prometheus-compatible metric name constants for Aegis Gateway.
//!
//! All metrics are emitted via the [`metrics`] facade crate (0.23).  A
//! compatible recorder (e.g. `metrics-exporter-prometheus`) must be installed
//! by the binary crate at startup for metrics to be exported.
//!
//! ## Counters
//!
//! | Name | Labels | Description |
//! |------|--------|-------------|
//! | [`TOOL_CALLS_TOTAL`] | `server`, `tool`, `decision`, `agent` | Total tool calls processed |
//! | [`RATE_LIMIT_TOTAL`] | `outcome`, `server`, `tool` | Total tool-call decisions by the rate limiter |
//! | [`RATE_LIMIT_REJECTIONS_TOTAL`] | `server`, `agent` | Rate-limit rejection hits |
//!
//! ## Histograms
//!
//! | Name | Labels | Description |
//! |------|--------|-------------|
//! | [`TOOL_CALL_DURATION_SECONDS`] | `server`, `tool` | End-to-end gateway latency |
//! | [`ENFORCEMENT_DURATION_SECONDS`] | `decision` | Kernel enforcement latency |
//! | [`UPSTREAM_DURATION_SECONDS`] | `server` | MCP server response latency |
//!
//! ## Gauges
//!
//! | Name | Labels | Description |
//! |------|--------|-------------|
//! | [`ACTIVE_CONNECTIONS`] | `transport` | Currently connected agents |
//! | [`TOKENS_ACTIVE`] | — | Active capability tokens in the kernel |
//! | [`RATE_LIMIT_REMAINING`] | `agent_id`, `server` | Remaining server-level tokens for an agent |

// ---------------------------------------------------------------------------
// Counters
// ---------------------------------------------------------------------------

/// Counter: total tool calls processed by the gateway.
///
/// Labels:
/// - `server`   — MCP server name
/// - `tool`     — tool name from `tools/call`
/// - `decision` — `"allow"`, `"deny"`, `"allowlist_blocked"`, or `"rate_limited"`
/// - `agent`    — agent identifier
pub const TOOL_CALLS_TOTAL: &str = "aegis_tool_calls_total";

/// Counter: total rate-limit decisions.
///
/// Labels:
/// - `outcome` — `"allowed"` or `"denied"`
/// - `server`  — MCP server name
/// - `tool`    — tool name from `tools/call`
pub const RATE_LIMIT_TOTAL: &str = "aegis_rate_limit_total";

/// Counter: rate-limit rejection hits.
///
/// Incremented once per rejected request (when `outcome = "denied"` in
/// [`RATE_LIMIT_TOTAL`]).  Labelled differently to make it easy to alert on
/// per-server or per-agent rejection spikes without joining on `outcome`.
///
/// Labels:
/// - `server` — MCP server name
/// - `agent`  — agent identifier
pub const RATE_LIMIT_REJECTIONS_TOTAL: &str = "aegis_rate_limit_rejections_total";

// ---------------------------------------------------------------------------
// Histograms
// ---------------------------------------------------------------------------

/// Histogram: end-to-end gateway latency for a `tools/call` request (seconds).
///
/// Measured from the moment the gateway starts processing the request through
/// enforcement and decision — not including upstream MCP server time.
///
/// Labels:
/// - `server` — MCP server name
/// - `tool`   — tool name
pub const TOOL_CALL_DURATION_SECONDS: &str = "aegis_tool_call_duration_seconds";

/// Histogram: kernel enforcement latency (seconds).
///
/// Sourced from [`aegis_core::AuditEntry::latency_us`] which measures the
/// time spent inside [`KernelHandle::evaluate`] (signature verification,
/// constraint evaluation, usage-count update).
///
/// Labels:
/// - `decision` — `"allow"` or `"deny"`
pub const ENFORCEMENT_DURATION_SECONDS: &str = "aegis_enforcement_duration_seconds";

/// Histogram: upstream MCP server response latency (seconds).
///
/// Measured from forwarding a request to the MCP server until the
/// corresponding response line is received.  Only emitted by transports
/// that support request/response correlation (e.g. SSE).
///
/// Labels:
/// - `server` — MCP server name
pub const UPSTREAM_DURATION_SECONDS: &str = "aegis_upstream_duration_seconds";

// ---------------------------------------------------------------------------
// Gauges
// ---------------------------------------------------------------------------

/// Gauge: currently connected agents.
///
/// Incremented when a new proxy session starts; decremented when it ends.
///
/// Labels:
/// - `transport` — `"stdio"` or `"sse"`
pub const ACTIVE_CONNECTIONS: &str = "aegis_active_connections";

/// Gauge: active capability tokens currently held in the kernel store.
///
/// Updated on every token issuance and deletion/revocation.
/// No labels.
pub const TOKENS_ACTIVE: &str = "aegis_tokens_active";

/// Gauge: remaining server-level token-bucket tokens for an agent.
///
/// Emitted only on the allowed path.
///
/// Labels:
/// - `agent_id` — agent identifier
/// - `server`   — MCP server name
pub const RATE_LIMIT_REMAINING: &str = "aegis_rate_limit_remaining";
