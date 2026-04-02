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
//! | [`RATE_LIMIT_TOTAL`] | `outcome`, `server`, `tool` | Total tool-call decisions by the rate limiter |
//!
//! ## Gauges
//!
//! | Name | Labels | Description |
//! |------|--------|-------------|
//! | [`RATE_LIMIT_REMAINING`] | `agent_id`, `server` | Remaining server-level tokens for an agent |

/// Counter: total rate-limit decisions.
///
/// Labels:
/// - `outcome` — `"allowed"` or `"denied"`
/// - `server`  — MCP server name
/// - `tool`    — tool name from `tools/call`
pub const RATE_LIMIT_TOTAL: &str = "aegis_rate_limit_total";

/// Gauge: remaining server-level token-bucket tokens for an agent.
///
/// Emitted only on the allowed path.
///
/// Labels:
/// - `agent_id` — agent identifier
/// - `server`   — MCP server name
pub const RATE_LIMIT_REMAINING: &str = "aegis_rate_limit_remaining";
