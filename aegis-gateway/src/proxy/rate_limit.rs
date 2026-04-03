//! Sliding window rate limiter using a token bucket algorithm.
//!
//! Rate limits are tracked **per-agent** so one misbehaving agent cannot
//! exhaust the quota for others. Limits are configurable at two granularities:
//!
//! * **Server-level** — a single bucket shared across all tools on the server.
//! * **Tool-level** — an additional bucket for a specific named tool, checked
//!   after the server-level one (both must pass).
//!
//! ## Algorithm
//!
//! The [`TokenBucket`] uses a continuous-refill (token bucket / leaky-bucket
//! hybrid) model:
//!
//! * Each bucket holds up to `max_calls` tokens.
//! * Tokens refill continuously at `max_calls / window_seconds` per second.
//! * Every `tools/call` consumes one token.
//! * When the bucket is empty the wait time until the next token arrives is
//!   returned as `retry_after_ms`.
//!
//! ## Wire format for rejected requests
//!
//! Blocked requests return JSON-RPC error **-32009** (`AEGIS_ERROR_RATE_LIMITED`)
//! with structured `data`:
//!
//! ```json
//! {
//!   "aegis": true,
//!   "decision": "rate_limited",
//!   "server": "github",
//!   "tool": "search_repositories",
//!   "agent": "my-agent",
//!   "retry_after_ms": 1500
//! }
//! ```
//!
//! The `retry_after_ms` field is used directly by stdio transports. SSE
//! transports should additionally translate this into a `Retry-After` HTTP
//! response header at the HTTP layer.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use std::{collections::HashMap, sync::Arc};
//! use aegis_gateway::proxy::{RateLimiter, RateLimiterMiddleware, StdioProxy, StdioProxyConfig};
//!
//! // One RateLimiter per server, shared across all sessions for that server.
//! let limiter = Arc::new(RateLimiter::new(
//!     "github",
//!     server_config.rate_limit.clone(),
//!     server_config.tool_rate_limits.clone(),
//! ));
//!
//! // One middleware per session; each session supplies its own agent_id.
//! let middleware = RateLimiterMiddleware::new("my-agent", Arc::clone(&limiter));
//! let proxy = StdioProxy::new(proxy_config).with_middleware(Arc::new(middleware));
//! ```

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aegis_mcp::translate::{translate_to_intent, AgentContext, IntentKind};
use aegis_mcp::{JsonRpcError, McpMessage};

use crate::config::RateLimitConfig;

use super::middleware::{InterceptionMiddleware, InterceptionResult};

// ---------------------------------------------------------------------------
// Error code
// ---------------------------------------------------------------------------

pub use aegis_mcp::translate::AEGIS_ERROR_RATE_LIMITED;

// ---------------------------------------------------------------------------
// TokenBucket (internal)
// ---------------------------------------------------------------------------

/// A continuous-refill token bucket.
///
/// Tokens accumulate at `refill_rate` per second (capped at `capacity`).
/// Requests consume one token; when empty, the exact wait until the next
/// token refills is returned.
struct TokenBucket {
    /// Maximum number of tokens (= configured `max_calls`).
    capacity: f64,
    /// Current token count; may be fractional due to sub-second refills.
    tokens: f64,
    /// Tokens added per second = `capacity / window_seconds`.
    refill_rate: f64,
    /// Monotonic clock reading of the last refill.
    last_refill: Instant,
}

impl TokenBucket {
    /// Create a new full bucket for `max_calls` calls per `window_seconds`.
    ///
    /// `burst_size` extra tokens are added on top of `max_calls` as the initial
    /// (and maximum) capacity, allowing short bursts above the steady-state rate.
    fn new(max_calls: u64, window_seconds: u64, burst_size: u64) -> Self {
        let capacity = (max_calls + burst_size) as f64;
        // Refill is based on the steady-state rate only (max_calls / window).
        // Guard against zero window (already validated by config, but be safe).
        let refill_rate = max_calls.max(1) as f64 / window_seconds.max(1) as f64;
        Self {
            capacity,
            tokens: capacity, // start full
            refill_rate,
            last_refill: Instant::now(),
        }
    }

    /// Accumulate tokens earned since the last call.
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.capacity);
        self.last_refill = now;
    }

    /// Inspect the wait time without consuming a token.
    ///
    /// Returns `None` if at least one token is available, or `Some(Duration)`
    /// if the bucket is empty.
    fn peek_wait(&mut self) -> Option<Duration> {
        self.refill();
        if self.tokens >= 1.0 {
            None
        } else {
            // How many more seconds until we reach 1.0 tokens?
            let needed = 1.0 - self.tokens;
            let wait_secs = needed / self.refill_rate;
            Some(Duration::from_millis(
                (wait_secs * 1000.0).ceil() as u64,
            ))
        }
    }

    /// Try to consume one token.
    ///
    /// Returns `None` if the token was consumed (request allowed), or
    /// `Some(Duration)` with the wait time until the next token (request
    /// rate-limited).
    fn try_consume(&mut self) -> Option<Duration> {
        if let Some(wait) = self.peek_wait() {
            return Some(wait);
        }
        self.tokens -= 1.0;
        None
    }

    /// Current remaining tokens (after a refill tick), clamped to zero.
    ///
    /// This value is advisory — it may change between the call and any
    /// subsequent `try_consume`. Use it only for metrics / observability.
    fn remaining_tokens(&mut self) -> f64 {
        self.refill();
        self.tokens.max(0.0)
    }

    /// Force-set the token count (test helper only).
    #[cfg(test)]
    fn set_tokens(&mut self, tokens: f64) {
        self.tokens = tokens.clamp(0.0, self.capacity);
    }
}

// ---------------------------------------------------------------------------
// RateLimiter (shared, one per server)
// ---------------------------------------------------------------------------

/// Shared rate-limit state for a single MCP server.
///
/// Maintains one token bucket per agent (server-level) and one per
/// `(agent, tool)` pair (tool-level). Instantiate once per server and
/// share via `Arc` across all sessions so per-agent accounting is global.
pub struct RateLimiter {
    server_name: String,
    server_limit: Option<RateLimitConfig>,
    tool_limits: HashMap<String, RateLimitConfig>,
    /// agent_id → server-level bucket
    agent_buckets: Mutex<HashMap<String, TokenBucket>>,
    /// (agent_id, tool_name) → tool-level bucket
    agent_tool_buckets: Mutex<HashMap<(String, String), TokenBucket>>,
}

impl RateLimiter {
    /// Create a new `RateLimiter`.
    ///
    /// - `server_name`  — used in log messages and error data.
    /// - `server_limit` — server-wide rate limit (applies to every tool call).
    /// - `tool_limits`  — optional per-tool rate limits (applied after server-level).
    pub fn new(
        server_name: impl Into<String>,
        server_limit: Option<RateLimitConfig>,
        tool_limits: HashMap<String, RateLimitConfig>,
    ) -> Self {
        Self {
            server_name: server_name.into(),
            server_limit,
            tool_limits,
            agent_buckets: Mutex::new(HashMap::new()),
            agent_tool_buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Check rate limits and consume a token if the call is permitted.
    ///
    /// Checks are in priority order: server-level first, then tool-level.
    /// Returns `None` on success (call allowed) or `Some(Duration)` with the
    /// minimum wait before the next call will be permitted.
    ///
    /// If the server-level limit is exhausted the tool-level bucket is not
    /// touched, avoiding unnecessary token consumption for rejected calls.
    pub fn check_and_consume(&self, agent_id: &str, tool_name: &str) -> Option<Duration> {
        // ── Phase 1: peek at both buckets (no tokens consumed yet) ──────────
        let server_wait = self.server_limit.as_ref().and_then(|limit| {
            let burst = limit.burst_size.unwrap_or(0);
            let mut guard = self.agent_buckets.lock().unwrap();
            let bucket = guard
                .entry(agent_id.to_string())
                .or_insert_with(|| TokenBucket::new(limit.max_calls, limit.window_seconds, burst));
            bucket.peek_wait()
        });

        if let Some(wait) = server_wait {
            return Some(wait);
        }

        let tool_wait = self.tool_limits.get(tool_name).and_then(|limit| {
            let burst = limit.burst_size.unwrap_or(0);
            let mut guard = self.agent_tool_buckets.lock().unwrap();
            let bucket = guard
                .entry((agent_id.to_string(), tool_name.to_string()))
                .or_insert_with(|| TokenBucket::new(limit.max_calls, limit.window_seconds, burst));
            bucket.peek_wait()
        });

        if let Some(wait) = tool_wait {
            return Some(wait);
        }

        // ── Phase 2: both buckets have tokens — consume from each ────────────
        if let Some(ref limit) = self.server_limit {
            let burst = limit.burst_size.unwrap_or(0);
            let mut guard = self.agent_buckets.lock().unwrap();
            let bucket = guard
                .entry(agent_id.to_string())
                .or_insert_with(|| TokenBucket::new(limit.max_calls, limit.window_seconds, burst));
            bucket.try_consume();
        }

        if let Some(limit) = self.tool_limits.get(tool_name) {
            let burst = limit.burst_size.unwrap_or(0);
            let mut guard = self.agent_tool_buckets.lock().unwrap();
            let bucket = guard
                .entry((agent_id.to_string(), tool_name.to_string()))
                .or_insert_with(|| TokenBucket::new(limit.max_calls, limit.window_seconds, burst));
            bucket.try_consume();
        }

        None
    }

    /// Returns `true` when no rate limits are configured (all calls pass through).
    pub fn is_unconstrained(&self) -> bool {
        self.server_limit.is_none() && self.tool_limits.is_empty()
    }

    /// Current remaining server-level tokens for `agent_id`, or `None` if
    /// there is no server-level limit configured.
    ///
    /// The value is advisory (it may change before the next call) and is
    /// intended for metrics / observability only.
    pub fn remaining_server_tokens(&self, agent_id: &str) -> Option<f64> {
        let limit = self.server_limit.as_ref()?;
        let burst = limit.burst_size.unwrap_or(0);
        let mut guard = self.agent_buckets.lock().unwrap();
        let bucket = guard
            .entry(agent_id.to_string())
            .or_insert_with(|| TokenBucket::new(limit.max_calls, limit.window_seconds, burst));
        Some(bucket.remaining_tokens())
    }

    /// The server name this limiter is associated with.
    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    /// Directly manipulate an agent's server-level token count (test helper).
    #[cfg(test)]
    pub fn set_agent_tokens(&self, agent_id: &str, tokens: f64) {
        if let Some(ref limit) = self.server_limit {
            let burst = limit.burst_size.unwrap_or(0);
            let mut guard = self.agent_buckets.lock().unwrap();
            let bucket = guard
                .entry(agent_id.to_string())
                .or_insert_with(|| TokenBucket::new(limit.max_calls, limit.window_seconds, burst));
            bucket.set_tokens(tokens);
        }
    }

    /// Directly manipulate an agent+tool token count (test helper).
    #[cfg(test)]
    pub fn set_agent_tool_tokens(&self, agent_id: &str, tool_name: &str, tokens: f64) {
        if let Some(limit) = self.tool_limits.get(tool_name) {
            let burst = limit.burst_size.unwrap_or(0);
            let mut guard = self.agent_tool_buckets.lock().unwrap();
            let bucket = guard
                .entry((agent_id.to_string(), tool_name.to_string()))
                .or_insert_with(|| TokenBucket::new(limit.max_calls, limit.window_seconds, burst));
            bucket.set_tokens(tokens);
        }
    }
}

// ---------------------------------------------------------------------------
// RateLimiterMiddleware
// ---------------------------------------------------------------------------

/// Middleware that applies per-agent token-bucket rate limiting to tool calls.
///
/// Create one `RateLimiterMiddleware` per session, backed by a shared
/// `Arc<RateLimiter>` that spans all sessions for the same server.
/// Non-`tools/call` messages (initialize, tools/list, notifications) are
/// always forwarded without consuming any tokens.
pub struct RateLimiterMiddleware {
    limiter: Arc<RateLimiter>,
    agent_id: String,
}

impl RateLimiterMiddleware {
    /// Create a new middleware for the given agent session.
    ///
    /// - `agent_id` — unique identity of the connecting agent (used as the
    ///   bucket key so each agent has an independent quota).
    /// - `limiter`  — shared rate-limit state for the server.
    pub fn new(agent_id: impl Into<String>, limiter: Arc<RateLimiter>) -> Self {
        Self {
            limiter,
            agent_id: agent_id.into(),
        }
    }
}

impl InterceptionMiddleware for RateLimiterMiddleware {
    /// Gate agent→server requests: apply rate limiting to `tools/call` only.
    fn on_request(&self, message: McpMessage) -> InterceptionResult {
        // Extract tool name from tools/call; everything else passes through.
        let tool_name = if let McpMessage::Request(ref req) = message {
            let ctx = AgentContext {
                agent_id: self.agent_id.clone(),
                token_id: String::new(),
            };
            match translate_to_intent(req, &ctx) {
                Some(IntentKind::ToolCall(tc)) => tc.tool_name,
                _ => return InterceptionResult::Forward(message),
            }
        } else {
            return InterceptionResult::Forward(message);
        };

        // Fast path: no limits configured — skip the lock entirely.
        if self.limiter.is_unconstrained() {
            return InterceptionResult::Forward(message);
        }

        let server = self.limiter.server_name().to_string();

        match self.limiter.check_and_consume(&self.agent_id, &tool_name) {
            None => {
                tracing::debug!(
                    agent_id = %self.agent_id,
                    server_name = %server,
                    tool_name = %tool_name,
                    "rate_limiter: allowed"
                );
                metrics::counter!(
                    crate::metrics::RATE_LIMIT_TOTAL,
                    "outcome" => "allowed",
                    "server" => server.clone(),
                    "tool" => tool_name.clone(),
                )
                .increment(1);
                if let Some(remaining) = self.limiter.remaining_server_tokens(&self.agent_id) {
                    metrics::gauge!(
                        crate::metrics::RATE_LIMIT_REMAINING,
                        "agent_id" => self.agent_id.clone(),
                        "server" => server.clone(),
                    )
                    .set(remaining as f64);
                }
                InterceptionResult::Forward(message)
            }
            Some(wait) => {
                let retry_after_ms = wait.as_millis() as u64;
                tracing::warn!(
                    agent_id = %self.agent_id,
                    server_name = %server,
                    tool_name = %tool_name,
                    retry_after_ms = retry_after_ms,
                    "rate_limiter: rate limited"
                );
                metrics::counter!(
                    crate::metrics::RATE_LIMIT_TOTAL,
                    "outcome" => "denied",
                    "server" => server.clone(),
                    "tool" => tool_name.clone(),
                )
                .increment(1);
                metrics::counter!(
                    crate::metrics::RATE_LIMIT_REJECTIONS_TOTAL,
                    "server" => server.clone(),
                    "agent"  => self.agent_id.clone(),
                )
                .increment(1);
                // Also count as a tool call with decision="rate_limited" for unified dashboard queries.
                metrics::counter!(
                    crate::metrics::TOOL_CALLS_TOTAL,
                    "server"   => server.clone(),
                    "tool"     => tool_name.clone(),
                    "decision" => "rate_limited",
                    "agent"    => self.agent_id.clone(),
                )
                .increment(1);
                InterceptionResult::Block(JsonRpcError {
                    code: AEGIS_ERROR_RATE_LIMITED,
                    message: format!(
                        "rate limit exceeded for agent '{}' on '{}::{}'; retry after {}ms",
                        self.agent_id,
                        server,
                        tool_name,
                        retry_after_ms
                    ),
                    data: Some(serde_json::json!({
                        "aegis": true,
                        "decision": "rate_limited",
                        "server": server,
                        "tool": tool_name,
                        "agent": self.agent_id,
                        "retry_after_ms": retry_after_ms,
                    })),
                })
            }
        }
    }

    /// Server→agent responses are always forwarded unchanged.
    fn on_response(&self, message: McpMessage) -> InterceptionResult {
        InterceptionResult::Forward(message)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_mcp::{McpMessage, McpNotification, McpRequest, McpResponse, RequestId};

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn make_tool_call(id: i64, tool: &str) -> McpMessage {
        McpMessage::Request(McpRequest {
            jsonrpc: "2.0".into(),
            id: RequestId::Number(id),
            method: "tools/call".into(),
            params: Some(serde_json::json!({ "name": tool, "arguments": {} })),
        })
    }

    fn server_limiter(max_calls: u64, window_seconds: u64) -> Arc<RateLimiter> {
        Arc::new(RateLimiter::new(
            "test-server",
            Some(RateLimitConfig { max_calls, window_seconds, burst_size: None }),
            HashMap::new(),
        ))
    }

    fn tool_limiter(
        server_max: u64,
        server_window: u64,
        tool: &str,
        tool_max: u64,
        tool_window: u64,
    ) -> Arc<RateLimiter> {
        let mut tool_limits = HashMap::new();
        tool_limits.insert(
            tool.to_string(),
            RateLimitConfig { max_calls: tool_max, window_seconds: tool_window, burst_size: None },
        );
        Arc::new(RateLimiter::new(
            "test-server",
            Some(RateLimitConfig { max_calls: server_max, window_seconds: server_window, burst_size: None }),
            tool_limits,
        ))
    }

    fn no_limit_limiter() -> Arc<RateLimiter> {
        Arc::new(RateLimiter::new("test-server", None, HashMap::new()))
    }

    // -----------------------------------------------------------------------
    // 1. TokenBucket: new bucket starts full
    // -----------------------------------------------------------------------

    #[test]
    fn token_bucket_starts_full() {
        let mut b = TokenBucket::new(5, 60, 0);
        // First 5 calls should all succeed
        for _ in 0..5 {
            assert!(b.try_consume().is_none(), "expected None (allowed)");
        }
    }

    // -----------------------------------------------------------------------
    // 2. TokenBucket: exhausted bucket returns a positive wait
    // -----------------------------------------------------------------------

    #[test]
    fn token_bucket_exhausted_returns_wait() {
        let mut b = TokenBucket::new(3, 60, 0);
        for _ in 0..3 {
            b.try_consume();
        }
        let wait = b.try_consume();
        assert!(wait.is_some(), "expected Some(wait) when bucket is empty");
        let ms = wait.unwrap().as_millis();
        assert!(ms > 0, "wait must be > 0ms");
        // 1 token at rate 3/60 = 0.05 tokens/s → ~20 000 ms wait
        assert!(ms <= 60_000, "wait must not exceed the window");
    }

    // -----------------------------------------------------------------------
    // 3. TokenBucket: peek_wait does not consume
    // -----------------------------------------------------------------------

    #[test]
    fn token_bucket_peek_does_not_consume() {
        let mut b = TokenBucket::new(2, 60, 0);
        assert!(b.peek_wait().is_none());
        assert!(b.peek_wait().is_none()); // still none after two peeks
        b.try_consume();
        b.try_consume();
        assert!(b.peek_wait().is_some()); // now empty
        // Another peek still returns Some without changing state
        assert!(b.peek_wait().is_some());
    }

    // -----------------------------------------------------------------------
    // 4. TokenBucket: refills after waiting (time-sensitive, uses real sleep)
    // -----------------------------------------------------------------------

    #[test]
    fn token_bucket_refills_over_time() {
        // 1 call / 1 second → refill rate = 1 token/s
        let mut b = TokenBucket::new(1, 1, 0);
        b.try_consume(); // drain
        assert!(b.try_consume().is_some(), "should be exhausted");
        // After 1.1 s the bucket should have refilled to ≥ 1 token
        std::thread::sleep(Duration::from_millis(1_100));
        assert!(b.try_consume().is_none(), "should be available after refill");
    }

    // -----------------------------------------------------------------------
    // 5. Unconstrained limiter always allows
    // -----------------------------------------------------------------------

    #[test]
    fn unconstrained_limiter_always_allows() {
        let limiter = no_limit_limiter();
        assert!(limiter.is_unconstrained());
        // Calling thousands of times should always succeed
        for i in 0..1000 {
            assert!(
                limiter.check_and_consume("agent", &format!("tool_{i}")).is_none(),
                "unconstrained limiter must always allow"
            );
        }
    }

    // -----------------------------------------------------------------------
    // 6. Server-level limit: blocks after max_calls
    // -----------------------------------------------------------------------

    #[test]
    fn server_limit_blocks_after_max_calls() {
        let limiter = server_limiter(3, 60);
        for i in 0..3 {
            assert!(
                limiter.check_and_consume("agent-a", "read_file").is_none(),
                "call {} should be allowed",
                i + 1
            );
        }
        let wait = limiter.check_and_consume("agent-a", "read_file");
        assert!(wait.is_some(), "4th call should be rate limited");
    }

    // -----------------------------------------------------------------------
    // 7. Server-level limit: retry_after_ms is reasonable
    // -----------------------------------------------------------------------

    #[test]
    fn server_limit_retry_after_ms_is_positive() {
        let limiter = server_limiter(1, 60);
        limiter.check_and_consume("agent", "read_file");
        let wait = limiter.check_and_consume("agent", "read_file").unwrap();
        let ms = wait.as_millis();
        assert!(ms > 0 && ms <= 60_000, "retry_after must be in (0, 60_000]ms, got {ms}");
    }

    // -----------------------------------------------------------------------
    // 8. Per-agent isolation: agent B is unaffected when agent A is throttled
    // -----------------------------------------------------------------------

    #[test]
    fn per_agent_isolation() {
        let limiter = server_limiter(2, 60);

        // Exhaust agent-a's quota
        limiter.check_and_consume("agent-a", "read_file");
        limiter.check_and_consume("agent-a", "read_file");
        assert!(
            limiter.check_and_consume("agent-a", "read_file").is_some(),
            "agent-a should be rate limited"
        );

        // Agent-b should still have its full quota
        assert!(
            limiter.check_and_consume("agent-b", "read_file").is_none(),
            "agent-b should be unaffected by agent-a's exhaustion"
        );
        assert!(
            limiter.check_and_consume("agent-b", "read_file").is_none(),
            "agent-b second call should also pass"
        );
    }

    // -----------------------------------------------------------------------
    // 9. Tool-level limit: blocks specific tool independently of server limit
    // -----------------------------------------------------------------------

    #[test]
    fn tool_limit_blocks_specific_tool() {
        // Server allows 10/min, but 'expensive_op' only allows 2/min
        let limiter = tool_limiter(10, 60, "expensive_op", 2, 60);

        assert!(limiter.check_and_consume("agent", "expensive_op").is_none());
        assert!(limiter.check_and_consume("agent", "expensive_op").is_none());
        assert!(
            limiter.check_and_consume("agent", "expensive_op").is_some(),
            "expensive_op should be tool-limited after 2 calls"
        );

        // Other tools on the same server are unaffected
        assert!(
            limiter.check_and_consume("agent", "cheap_op").is_none(),
            "cheap_op must not be affected by expensive_op limit"
        );
    }

    // -----------------------------------------------------------------------
    // 10. Server limit takes priority over tool limit
    // -----------------------------------------------------------------------

    #[test]
    fn server_limit_takes_priority() {
        // Server allows only 1/min; tool allows 5/min
        let limiter = tool_limiter(1, 60, "read_file", 5, 60);

        assert!(limiter.check_and_consume("agent", "read_file").is_none());
        let wait = limiter.check_and_consume("agent", "read_file");
        assert!(
            wait.is_some(),
            "server quota exhausted — should block even though tool limit not reached"
        );
    }

    // -----------------------------------------------------------------------
    // 11. set_agent_tokens test helper allows manual bucket manipulation
    // -----------------------------------------------------------------------

    #[test]
    fn set_agent_tokens_helper() {
        let limiter = server_limiter(5, 60);
        // Drain the bucket
        for _ in 0..5 {
            limiter.check_and_consume("agent", "tool");
        }
        assert!(limiter.check_and_consume("agent", "tool").is_some(), "should be exhausted");

        // Manually refill via test helper
        limiter.set_agent_tokens("agent", 5.0);
        assert!(
            limiter.check_and_consume("agent", "tool").is_none(),
            "should be allowed after manual refill"
        );
    }

    // -----------------------------------------------------------------------
    // Middleware tests
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // 12. burst_size allows calls above max_calls
    // -----------------------------------------------------------------------

    #[test]
    fn burst_size_allows_extra_calls() {
        // max_calls=2, burst=1 → capacity=3
        let limiter = Arc::new(RateLimiter::new(
            "test-server",
            Some(RateLimitConfig { max_calls: 2, window_seconds: 60, burst_size: Some(1) }),
            HashMap::new(),
        ));
        // First 3 calls (max+burst) should pass
        assert!(limiter.check_and_consume("agent", "tool").is_none(), "call 1 must pass");
        assert!(limiter.check_and_consume("agent", "tool").is_none(), "call 2 must pass");
        assert!(limiter.check_and_consume("agent", "tool").is_none(), "call 3 (burst) must pass");
        // 4th call must be blocked
        assert!(
            limiter.check_and_consume("agent", "tool").is_some(),
            "call 4 must be rate-limited"
        );
    }

    // -----------------------------------------------------------------------
    // 13. remaining_server_tokens reflects consumed tokens
    // -----------------------------------------------------------------------

    #[test]
    fn remaining_server_tokens_decrements() {
        let limiter = server_limiter(5, 60);
        let initial = limiter.remaining_server_tokens("agent").unwrap();
        assert!(initial >= 4.9, "bucket should start nearly full, got {initial}");

        limiter.check_and_consume("agent", "tool");
        limiter.check_and_consume("agent", "tool");
        let after = limiter.remaining_server_tokens("agent").unwrap();
        assert!(after < initial, "remaining must decrease after consumption");
    }

    #[test]
    fn remaining_server_tokens_none_when_unconstrained() {
        let limiter = no_limit_limiter();
        assert!(limiter.remaining_server_tokens("agent").is_none());
    }

    // -----------------------------------------------------------------------
    // 14. Middleware: non-tool-call messages always pass through
    // -----------------------------------------------------------------------

    #[test]
    fn middleware_passes_non_tool_calls() {
        let limiter = server_limiter(1, 60);
        // Exhaust the one-call budget first
        limiter.check_and_consume("agent", "any_tool");

        let mw = RateLimiterMiddleware::new("agent", limiter);

        // initialize
        let init = McpMessage::Request(McpRequest {
            jsonrpc: "2.0".into(),
            id: RequestId::Number(1),
            method: "initialize".into(),
            params: Some(serde_json::json!({"capabilities": {}})),
        });
        assert!(matches!(mw.on_request(init), InterceptionResult::Forward(_)));

        // notification
        let notif = McpMessage::Notification(McpNotification {
            jsonrpc: "2.0".into(),
            method: "notifications/initialized".into(),
            params: None,
        });
        assert!(matches!(mw.on_request(notif), InterceptionResult::Forward(_)));

        // tools/list
        let list = McpMessage::Request(McpRequest {
            jsonrpc: "2.0".into(),
            id: RequestId::Number(2),
            method: "tools/list".into(),
            params: None,
        });
        assert!(matches!(mw.on_request(list), InterceptionResult::Forward(_)));
    }

    // -----------------------------------------------------------------------
    // 13. Middleware: responses always pass through
    // -----------------------------------------------------------------------

    #[test]
    fn middleware_passes_responses() {
        let limiter = server_limiter(0, 60); // effectively no quota
        let mw = RateLimiterMiddleware::new("agent", limiter);
        let resp = McpMessage::Response(McpResponse {
            jsonrpc: "2.0".into(),
            id: RequestId::Number(1),
            result: Some(serde_json::json!({})),
            error: None,
        });
        assert!(matches!(mw.on_response(resp), InterceptionResult::Forward(_)));
    }

    // -----------------------------------------------------------------------
    // 14. Middleware: unconstrained limiter never blocks
    // -----------------------------------------------------------------------

    #[test]
    fn middleware_unconstrained_never_blocks() {
        let limiter = no_limit_limiter();
        let mw = RateLimiterMiddleware::new("agent", limiter);
        for i in 0..100 {
            let result = mw.on_request(make_tool_call(i, "any_tool"));
            assert!(
                matches!(result, InterceptionResult::Forward(_)),
                "unconstrained middleware must never block"
            );
        }
    }

    // -----------------------------------------------------------------------
    // 15. Middleware: blocks when budget exhausted, returns -32009
    // -----------------------------------------------------------------------

    #[test]
    fn middleware_blocks_with_correct_error_code() {
        let limiter = server_limiter(2, 60);
        let mw = RateLimiterMiddleware::new("agent-x", Arc::clone(&limiter));

        // First two calls pass
        assert!(matches!(
            mw.on_request(make_tool_call(1, "read_file")),
            InterceptionResult::Forward(_)
        ));
        assert!(matches!(
            mw.on_request(make_tool_call(2, "read_file")),
            InterceptionResult::Forward(_)
        ));

        // Third call is blocked
        let result = mw.on_request(make_tool_call(3, "read_file"));
        match result {
            InterceptionResult::Block(err) => {
                assert_eq!(
                    err.code, AEGIS_ERROR_RATE_LIMITED,
                    "expected -32009, got {}",
                    err.code
                );
            }
            other => panic!("expected Block, got {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // 16. Middleware: error data has all required fields
    // -----------------------------------------------------------------------

    #[test]
    fn middleware_error_data_fields() {
        let limiter = server_limiter(1, 60);
        let mw = RateLimiterMiddleware::new("my-agent", Arc::clone(&limiter));

        mw.on_request(make_tool_call(1, "search_repos")); // consume quota
        let result = mw.on_request(make_tool_call(2, "search_repos"));

        match result {
            InterceptionResult::Block(err) => {
                let data = err.data.expect("error must have structured data");
                assert_eq!(data["aegis"], true, "data.aegis must be true");
                assert_eq!(data["decision"], "rate_limited");
                assert_eq!(data["server"], "test-server");
                assert_eq!(data["tool"], "search_repos");
                assert_eq!(data["agent"], "my-agent");
                let retry_ms = data["retry_after_ms"].as_u64().expect("retry_after_ms must be u64");
                assert!(retry_ms > 0, "retry_after_ms must be positive");
            }
            other => panic!("expected Block, got {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // 17. Middleware: error message mentions tool, server, and retry time
    // -----------------------------------------------------------------------

    #[test]
    fn middleware_error_message_content() {
        let limiter = server_limiter(1, 60);
        let mw = RateLimiterMiddleware::new("agent", Arc::clone(&limiter));

        mw.on_request(make_tool_call(1, "delete_file")); // drain
        let result = mw.on_request(make_tool_call(2, "delete_file"));

        if let InterceptionResult::Block(err) = result {
            assert!(
                err.message.contains("delete_file"),
                "message should name the tool: {}",
                err.message
            );
            assert!(
                err.message.contains("test-server"),
                "message should name the server: {}",
                err.message
            );
            assert!(
                err.message.contains("ms"),
                "message should include retry time: {}",
                err.message
            );
        } else {
            panic!("expected Block");
        }
    }

    // -----------------------------------------------------------------------
    // 18. Middleware: different tools share the server budget
    // -----------------------------------------------------------------------

    #[test]
    fn different_tools_share_server_budget() {
        let limiter = server_limiter(2, 60);
        let mw = RateLimiterMiddleware::new("agent", limiter);

        // One call to each of two different tools exhausts the server budget
        assert!(matches!(
            mw.on_request(make_tool_call(1, "tool_a")),
            InterceptionResult::Forward(_)
        ));
        assert!(matches!(
            mw.on_request(make_tool_call(2, "tool_b")),
            InterceptionResult::Forward(_)
        ));
        // Third call to any tool should be blocked
        assert!(matches!(
            mw.on_request(make_tool_call(3, "tool_c")),
            InterceptionResult::Block(_)
        ));
    }

    // -----------------------------------------------------------------------
    // 19. Middleware: tool-level limit blocks that tool but not others
    // -----------------------------------------------------------------------

    #[test]
    fn middleware_tool_limit_isolation() {
        let limiter = tool_limiter(100, 60, "expensive_op", 1, 60);
        let mw = RateLimiterMiddleware::new("agent", limiter);

        assert!(matches!(
            mw.on_request(make_tool_call(1, "expensive_op")),
            InterceptionResult::Forward(_)
        ));
        assert!(matches!(
            mw.on_request(make_tool_call(2, "expensive_op")),
            InterceptionResult::Block(_)
        ));
        // Other tools are unaffected
        assert!(matches!(
            mw.on_request(make_tool_call(3, "cheap_op")),
            InterceptionResult::Forward(_)
        ));
    }

    // -----------------------------------------------------------------------
    // 20. Integration: rate-limited call returns -32009 via stdio proxy
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn integration_rate_limited_call_returns_error() {
        use std::process::Stdio;
        use tokio::process::Command;

        use crate::proxy::stdio::{StdioProxy, StdioProxyConfig};

        // 1-call budget, so the second call will be blocked
        let limiter = server_limiter(1, 60);

        // Pre-consume the single token so the very first call in the proxy is blocked
        limiter.check_and_consume("test-agent", "read_file");

        let mw = RateLimiterMiddleware::new("test-agent", limiter);
        let proxy = StdioProxy::new(StdioProxyConfig {
            command: "cat".into(),
            args: vec![],
            env: vec![],
        })
        .with_middleware(Arc::new(mw));

        let input = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\
                     \"params\":{\"name\":\"read_file\",\"arguments\":{}}}\n";

        let mut output = Vec::new();
        let child = Command::new("cat")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .expect("failed to spawn cat");

        proxy
            .run_with_child(input.as_bytes(), &mut output, child)
            .await
            .unwrap();

        let output_str = String::from_utf8(output).unwrap();
        let msg = aegis_mcp::parse_message(output_str.trim().as_bytes()).unwrap();
        match msg {
            McpMessage::Response(resp) => {
                let err = resp.error.expect("rate-limited call must return error");
                assert_eq!(
                    err.code, AEGIS_ERROR_RATE_LIMITED,
                    "expected AEGIS_ERROR_RATE_LIMITED (-32009), got {}",
                    err.code
                );
                let data = err.data.unwrap();
                assert!(
                    data["retry_after_ms"].as_u64().unwrap() > 0,
                    "retry_after_ms must be positive"
                );
            }
            other => panic!("expected error Response, got: {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // 21. Integration: allowed call still reaches server after partial use
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn integration_allowed_call_after_partial_use() {
        use std::process::Stdio;
        use tokio::process::Command;

        use crate::proxy::stdio::{StdioProxy, StdioProxyConfig};

        // 2-call budget; we pre-consume 1, so the proxy call (1 call) still fits
        let limiter = server_limiter(2, 60);
        limiter.check_and_consume("test-agent", "read_file");

        let mw = RateLimiterMiddleware::new("test-agent", limiter);
        let proxy = StdioProxy::new(StdioProxyConfig {
            command: "cat".into(),
            args: vec![],
            env: vec![],
        })
        .with_middleware(Arc::new(mw));

        let input = "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\
                     \"params\":{\"name\":\"read_file\",\"arguments\":{}}}\n";

        let mut output = Vec::new();
        let child = Command::new("cat")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .expect("failed to spawn cat");

        proxy
            .run_with_child(input.as_bytes(), &mut output, child)
            .await
            .unwrap();

        let output_str = String::from_utf8(output).unwrap();
        let msg = aegis_mcp::parse_message(output_str.trim().as_bytes()).unwrap();
        // cat echoes back a Request (not an error)
        assert!(
            matches!(msg, McpMessage::Request(_)),
            "allowed call should be forwarded to server, got: {}",
            output_str.trim()
        );
    }
}
