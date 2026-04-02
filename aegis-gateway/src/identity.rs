//! Agent identity resolution for the Aegis Gateway.
//!
//! MCP itself carries no built-in authentication or agent identification.
//! Aegis overlays lightweight identity by inspecting the **connection
//! context** — information available when a session is first established —
//! rather than requiring changes to the agent or the MCP server.
//!
//! ## Strategies
//!
//! Three strategies are provided; choose based on your deployment:
//!
//! | Strategy | Type | Best For |
//! |---|---|---|
//! | [`ProcessAgentIdentifier`] | stdio | Local dev, single-user |
//! | [`HeaderAgentIdentifier`] | SSE | Multi-agent SSE deployments |
//! | [`TokenAgentIdentifier`] | SSE | Production (Phase 2) |
//!
//! ## Usage
//!
//! ```rust,ignore
//! use aegis_gateway::identity::{ConnectionContext, HeaderAgentIdentifier, AgentIdentifier};
//!
//! // At SSE connection time:
//! let ctx = ConnectionContext::for_sse(headers, Some(peer_addr));
//! let identifier = HeaderAgentIdentifier::new();
//! let agent_id = identifier.identify(&ctx);
//!
//! // agent_id is now the resolved identity — pass it to middleware:
//! let mw = RateLimiterMiddleware::new(agent_id, limiter);
//! ```

use std::collections::HashMap;

use crate::ratelimit::AgentId;

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

/// The transport mechanism over which an agent connected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transport {
    /// The agent connected via a stdio-wrapped child process.
    Stdio,
    /// The agent connected over HTTP Server-Sent Events.
    Sse,
}

// ---------------------------------------------------------------------------
// ConnectionContext
// ---------------------------------------------------------------------------

/// Information available at connection establishment time.
///
/// Passed to [`AgentIdentifier::identify`] to resolve the agent's identity.
/// Build with [`ConnectionContext::for_stdio`] or [`ConnectionContext::for_sse`].
#[derive(Debug, Clone)]
pub struct ConnectionContext {
    /// Which transport carried the connection.
    pub transport: Transport,
    /// HTTP headers from the initial request (SSE connections).
    ///
    /// Keys are lower-cased header names (e.g. `"x-aegis-agent-id"`).
    pub headers: HashMap<String, String>,
    /// PID of the parent process (stdio connections on Unix).
    pub parent_pid: Option<u32>,
    /// Executable name of the parent process (stdio connections).
    pub parent_process_name: Option<String>,
    /// Peer address of the connecting client (SSE connections).
    pub peer_addr: Option<String>,
}

impl ConnectionContext {
    /// Build a context for a stdio connection.
    ///
    /// On Linux, reads the parent PID from `/proc/self/status` and the
    /// process name from `/proc/{ppid}/comm`. On other platforms these
    /// fields are `None`.
    pub fn for_stdio() -> Self {
        let (parent_pid, parent_process_name) = read_parent_process_info();
        Self {
            transport: Transport::Stdio,
            headers: HashMap::new(),
            parent_pid,
            parent_process_name,
            peer_addr: None,
        }
    }

    /// Build a context for an SSE connection.
    ///
    /// `headers` should have lower-cased header names.
    pub fn for_sse(headers: HashMap<String, String>, peer_addr: Option<String>) -> Self {
        Self {
            transport: Transport::Sse,
            headers,
            parent_pid: None,
            parent_process_name: None,
            peer_addr,
        }
    }
}

// ---------------------------------------------------------------------------
// Platform helpers
// ---------------------------------------------------------------------------

/// Read the parent process PID and name from the OS.
///
/// Returns `(pid, name)`. Either may be `None` if unavailable.
#[cfg(target_os = "linux")]
fn read_parent_process_info() -> (Option<u32>, Option<String>) {
    // Parse PPid from /proc/self/status
    let ppid: Option<u32> = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("PPid:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|v| v.parse().ok())
        });

    // Read the process name from /proc/{ppid}/comm (single-line, trailing \n)
    let name = ppid.and_then(|pid| {
        std::fs::read_to_string(format!("/proc/{}/comm", pid))
            .ok()
            .map(|s| s.trim().to_string())
    });

    (ppid, name)
}

#[cfg(not(target_os = "linux"))]
fn read_parent_process_info() -> (Option<u32>, Option<String>) {
    (None, None)
}

// ---------------------------------------------------------------------------
// AgentIdentifier trait
// ---------------------------------------------------------------------------

/// Resolve an agent's identity from connection context.
///
/// Implementors are `Send + Sync` so they can be stored in `Arc` and shared
/// across sessions for the same server.
pub trait AgentIdentifier: Send + Sync {
    /// Return the [`AgentId`] for the connecting agent.
    ///
    /// Must be deterministic for the same connection context and must not
    /// block the async runtime (no I/O inside this method beyond in-memory
    /// reads of `ctx`).
    fn identify(&self, ctx: &ConnectionContext) -> AgentId;
}

// ---------------------------------------------------------------------------
// ProcessAgentIdentifier
// ---------------------------------------------------------------------------

/// Identify agents by their parent process name and PID.
///
/// Suitable for local development and single-user stdio setups where each
/// agent is launched as a distinct OS process. No agent-side changes needed.
///
/// ## Format
///
/// Returns an id of the form `process:<name>:<pid>` where `<name>` is the
/// executable name (trimmed comm value on Linux) and `<pid>` is the parent
/// PID. Falls back to `process:pid-<pid>` when the name is unavailable, or
/// `process:unknown` when neither is known.
pub struct ProcessAgentIdentifier;

impl AgentIdentifier for ProcessAgentIdentifier {
    fn identify(&self, ctx: &ConnectionContext) -> AgentId {
        match (&ctx.parent_process_name, &ctx.parent_pid) {
            (Some(name), Some(pid)) => format!("process:{}:{}", name, pid),
            (Some(name), None) => format!("process:{}", name),
            (None, Some(pid)) => format!("process:pid-{}", pid),
            (None, None) => "process:unknown".to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// HeaderAgentIdentifier
// ---------------------------------------------------------------------------

/// Identify agents by the value of an HTTP header (default: `X-Aegis-Agent-Id`).
///
/// The agent sends a custom header on its SSE connection. The gateway reads
/// it and uses its value verbatim as the `AgentId`.
///
/// Header name matching is **case-insensitive** (keys are normalised to
/// lowercase before storage, matching HTTP/2 conventions).
///
/// ## Fallback
///
/// When the header is absent, `fallback` is used (default: `"header:unknown"`).
/// Configure a descriptive fallback so that traffic from unidentified agents
/// is still tracked and distinguishable in logs and metrics.
pub struct HeaderAgentIdentifier {
    /// Lower-cased header name to inspect.
    header_name: String,
    /// Returned when the header is absent.
    fallback: AgentId,
}

impl Default for HeaderAgentIdentifier {
    fn default() -> Self {
        Self::new()
    }
}

impl HeaderAgentIdentifier {
    /// Create an identifier that reads `X-Aegis-Agent-Id` (lower-cased:
    /// `x-aegis-agent-id`).
    pub fn new() -> Self {
        Self {
            header_name: "x-aegis-agent-id".to_string(),
            fallback: "header:unknown".to_string(),
        }
    }

    /// Override the header name. The value is lower-cased automatically.
    pub fn with_header_name(mut self, name: impl Into<String>) -> Self {
        self.header_name = name.into().to_lowercase();
        self
    }

    /// Override the fallback returned when the header is absent.
    pub fn with_fallback(mut self, fallback: impl Into<AgentId>) -> Self {
        self.fallback = fallback.into();
        self
    }
}

impl AgentIdentifier for HeaderAgentIdentifier {
    fn identify(&self, ctx: &ConnectionContext) -> AgentId {
        // Headers are already lower-cased in ConnectionContext::for_sse.
        ctx.headers
            .get(&self.header_name)
            .filter(|v| !v.is_empty())
            .cloned()
            .unwrap_or_else(|| self.fallback.clone())
    }
}

// ---------------------------------------------------------------------------
// TokenAgentIdentifier
// ---------------------------------------------------------------------------

/// Identify agents by an Aegis session token (Phase 2 stub).
///
/// In the full implementation (Phase 2) the token is validated against the
/// Aegis kernel's session store and the associated agent identity is returned.
/// This stub extracts the token value from the `X-Aegis-Token` header and
/// returns it as the identity prefix, enabling end-to-end testing of the
/// token flow before the validation logic is wired up.
///
/// ## Phase 2 note
///
/// Replace [`TokenAgentIdentifier::identify`] with an async token-validation
/// call to the kernel gRPC endpoint once `aegis-handle` exposes it.  Until
/// then, unrecognised tokens are treated as anonymous but still tracked.
pub struct TokenAgentIdentifier;

/// HTTP header carrying the Aegis session token.
pub const AEGIS_TOKEN_HEADER: &str = "x-aegis-token";

impl AgentIdentifier for TokenAgentIdentifier {
    fn identify(&self, ctx: &ConnectionContext) -> AgentId {
        match ctx.headers.get(AEGIS_TOKEN_HEADER) {
            Some(token) if !token.is_empty() => {
                // Use the first 8 chars as a prefix so the id is readable in
                // logs without leaking the full token.
                let prefix = &token[..token.len().min(8)];
                format!("token:{}", prefix)
            }
            _ => "token:anonymous".to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn sse_ctx(headers: &[(&str, &str)]) -> ConnectionContext {
        ConnectionContext::for_sse(
            headers
                .iter()
                .map(|(k, v)| (k.to_lowercase(), v.to_string()))
                .collect(),
            None,
        )
    }

    // -----------------------------------------------------------------------
    // 1. ConnectionContext::for_stdio populates parent process info
    // -----------------------------------------------------------------------

    #[test]
    fn stdio_context_transport_is_stdio() {
        let ctx = ConnectionContext::for_stdio();
        assert_eq!(ctx.transport, Transport::Stdio);
        assert!(ctx.headers.is_empty());
        assert!(ctx.peer_addr.is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stdio_context_has_parent_pid() {
        let ctx = ConnectionContext::for_stdio();
        // The test process has a parent (the test runner)
        assert!(ctx.parent_pid.is_some(), "parent_pid must be set on Linux");
        // Parent PID must be a plausible value (> 1, != current pid)
        let ppid = ctx.parent_pid.unwrap();
        assert!(ppid > 1, "parent_pid must be > 1, got {}", ppid);
        assert_ne!(ppid, std::process::id(), "parent_pid must differ from current pid");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stdio_context_has_parent_process_name() {
        let ctx = ConnectionContext::for_stdio();
        let name = ctx.parent_process_name.as_deref().unwrap_or("");
        // Process name should be non-empty and not contain newlines
        assert!(!name.is_empty(), "parent_process_name must be non-empty on Linux");
        assert!(!name.contains('\n'), "process name must not contain newlines");
    }

    // -----------------------------------------------------------------------
    // 2. ConnectionContext::for_sse stores headers correctly
    // -----------------------------------------------------------------------

    #[test]
    fn sse_context_transport_is_sse() {
        let ctx = ConnectionContext::for_sse(HashMap::new(), None);
        assert_eq!(ctx.transport, Transport::Sse);
    }

    #[test]
    fn sse_context_stores_headers() {
        let ctx = sse_ctx(&[("x-aegis-agent-id", "my-agent"), ("content-type", "text/event-stream")]);
        assert_eq!(ctx.headers.get("x-aegis-agent-id").map(String::as_str), Some("my-agent"));
        assert_eq!(ctx.headers.get("content-type").map(String::as_str), Some("text/event-stream"));
    }

    #[test]
    fn sse_context_peer_addr() {
        let ctx = ConnectionContext::for_sse(HashMap::new(), Some("127.0.0.1:9000".to_string()));
        assert_eq!(ctx.peer_addr.as_deref(), Some("127.0.0.1:9000"));
    }

    // -----------------------------------------------------------------------
    // 3. ProcessAgentIdentifier
    // -----------------------------------------------------------------------

    #[test]
    fn process_id_with_name_and_pid() {
        let ctx = ConnectionContext {
            transport: Transport::Stdio,
            headers: HashMap::new(),
            parent_pid: Some(1234),
            parent_process_name: Some("python3".to_string()),
            peer_addr: None,
        };
        assert_eq!(ProcessAgentIdentifier.identify(&ctx), "process:python3:1234");
    }

    #[test]
    fn process_id_name_only() {
        let ctx = ConnectionContext {
            transport: Transport::Stdio,
            headers: HashMap::new(),
            parent_pid: None,
            parent_process_name: Some("claude".to_string()),
            peer_addr: None,
        };
        assert_eq!(ProcessAgentIdentifier.identify(&ctx), "process:claude");
    }

    #[test]
    fn process_id_pid_only() {
        let ctx = ConnectionContext {
            transport: Transport::Stdio,
            headers: HashMap::new(),
            parent_pid: Some(5678),
            parent_process_name: None,
            peer_addr: None,
        };
        assert_eq!(ProcessAgentIdentifier.identify(&ctx), "process:pid-5678");
    }

    #[test]
    fn process_id_unknown() {
        let ctx = ConnectionContext {
            transport: Transport::Stdio,
            headers: HashMap::new(),
            parent_pid: None,
            parent_process_name: None,
            peer_addr: None,
        };
        assert_eq!(ProcessAgentIdentifier.identify(&ctx), "process:unknown");
    }

    // -----------------------------------------------------------------------
    // 4. HeaderAgentIdentifier
    // -----------------------------------------------------------------------

    #[test]
    fn header_id_returns_header_value() {
        let ctx = sse_ctx(&[("x-aegis-agent-id", "agent-alpha")]);
        assert_eq!(HeaderAgentIdentifier::new().identify(&ctx), "agent-alpha");
    }

    #[test]
    fn header_id_returns_fallback_when_absent() {
        let ctx = sse_ctx(&[]);
        let id = HeaderAgentIdentifier::new().identify(&ctx);
        assert_eq!(id, "header:unknown");
    }

    #[test]
    fn header_id_custom_fallback() {
        let ctx = sse_ctx(&[]);
        let id = HeaderAgentIdentifier::new()
            .with_fallback("anon-sse")
            .identify(&ctx);
        assert_eq!(id, "anon-sse");
    }

    #[test]
    fn header_id_custom_header_name() {
        let ctx = sse_ctx(&[("x-my-agent", "bot-007")]);
        let id = HeaderAgentIdentifier::new()
            .with_header_name("X-My-Agent")  // mixed case — should still work
            .identify(&ctx);
        assert_eq!(id, "bot-007");
    }

    #[test]
    fn header_id_empty_value_uses_fallback() {
        let ctx = sse_ctx(&[("x-aegis-agent-id", "")]);
        let id = HeaderAgentIdentifier::new().identify(&ctx);
        assert_eq!(id, "header:unknown");
    }

    #[test]
    fn header_id_case_insensitive_key() {
        // Headers normalised to lowercase in ConnectionContext::for_sse
        let ctx = sse_ctx(&[("X-Aegis-Agent-Id", "agent-beta")]);
        assert_eq!(HeaderAgentIdentifier::new().identify(&ctx), "agent-beta");
    }

    // -----------------------------------------------------------------------
    // 5. TokenAgentIdentifier
    // -----------------------------------------------------------------------

    #[test]
    fn token_id_returns_prefix_of_token() {
        let ctx = sse_ctx(&[("x-aegis-token", "abcdef1234567890")]);
        let id = TokenAgentIdentifier.identify(&ctx);
        assert_eq!(id, "token:abcdef12");
    }

    #[test]
    fn token_id_short_token() {
        let ctx = sse_ctx(&[("x-aegis-token", "abc")]);
        let id = TokenAgentIdentifier.identify(&ctx);
        assert_eq!(id, "token:abc");
    }

    #[test]
    fn token_id_anonymous_when_absent() {
        let ctx = sse_ctx(&[]);
        assert_eq!(TokenAgentIdentifier.identify(&ctx), "token:anonymous");
    }

    #[test]
    fn token_id_anonymous_for_empty_token() {
        let ctx = sse_ctx(&[("x-aegis-token", "")]);
        assert_eq!(TokenAgentIdentifier.identify(&ctx), "token:anonymous");
    }

    // -----------------------------------------------------------------------
    // 6. Integration: two agents resolve distinct identities, tracked independently
    // -----------------------------------------------------------------------

    #[test]
    fn two_agents_tracked_independently() {
        use crate::config::RateLimitConfig;
        use crate::proxy::RateLimiter;
        use std::collections::HashMap;
        use std::sync::Arc;

        let identifier = HeaderAgentIdentifier::new();

        // Two separate SSE connections with different agent IDs
        let ctx_alpha = sse_ctx(&[("x-aegis-agent-id", "agent-alpha")]);
        let ctx_beta = sse_ctx(&[("x-aegis-agent-id", "agent-beta")]);

        let id_alpha = identifier.identify(&ctx_alpha);
        let id_beta = identifier.identify(&ctx_beta);

        assert_eq!(id_alpha, "agent-alpha");
        assert_eq!(id_beta, "agent-beta");
        assert_ne!(id_alpha, id_beta, "two agents must have distinct identities");

        // Shared rate limiter (one per server, shared across all sessions)
        let limiter = Arc::new(RateLimiter::new(
            "github",
            Some(RateLimitConfig { max_calls: 2, window_seconds: 60, burst_size: None }),
            HashMap::new(),
        ));

        // Exhaust agent-alpha's quota
        assert!(limiter.check_and_consume(&id_alpha, "search").is_none(), "alpha call 1");
        assert!(limiter.check_and_consume(&id_alpha, "search").is_none(), "alpha call 2");
        assert!(
            limiter.check_and_consume(&id_alpha, "search").is_some(),
            "alpha call 3 should be rate-limited"
        );

        // agent-beta still has its full quota
        assert!(
            limiter.check_and_consume(&id_beta, "search").is_none(),
            "beta call 1 must not be affected by alpha's exhaustion"
        );
        assert!(
            limiter.check_and_consume(&id_beta, "search").is_none(),
            "beta call 2 must pass"
        );
        assert!(
            limiter.check_and_consume(&id_beta, "search").is_some(),
            "beta call 3 should be rate-limited"
        );
    }

    // -----------------------------------------------------------------------
    // 7. Integration: ProcessAgentIdentifier with real stdio context
    // -----------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    fn process_identifier_resolves_real_parent() {
        let ctx = ConnectionContext::for_stdio();
        let id = ProcessAgentIdentifier.identify(&ctx);
        // ID must start with "process:" and not be "process:unknown"
        assert!(id.starts_with("process:"), "id must start with process:, got: {id}");
        assert_ne!(id, "process:unknown", "real process context should resolve a name or PID");
    }
}
