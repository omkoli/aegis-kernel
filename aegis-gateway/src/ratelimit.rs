//! Sliding-window rate limiter for per-agent, per-server call tracking.
//!
//! [`SlidingWindowCounter`] maintains one [`WindowState`] per `(agent_id,
//! server_name)` pair inside a [`DashMap`], giving lock-free concurrent access
//! without a global mutex.
//!
//! ## Algorithm
//!
//! Each window is a fixed-width time slot of `window_seconds` duration.
//! When the first call arrives for a pair the window starts.  Every
//! subsequent call within the same window increments the counter.  Once the
//! window expires (the current time is past `window_start + window_seconds`)
//! the counter resets and a new window begins.
//!
//! ```text
//! t=0   t=30s          t=60s  t=90s
//! |___window 1_________|___window 2___|
//!  ^call ^call ^call    ^reset, call 1
//! ```
//!
//! ## Usage
//!
//! ```rust,ignore
//! use aegis_gateway::ratelimit::SlidingWindowCounter;
//!
//! // One counter per server (shared across agents via Arc).
//! let counter = SlidingWindowCounter::new(100, 60);   // 100 calls / 60 s
//!
//! match counter.check_rate_limit("agent-42", "github") {
//!     Ok(()) => { /* forward the tool call */ }
//!     Err(e) => { /* return -32009 with retry_after_ms = e.retry_after_ms */ }
//! }
//! ```

use std::time::{Duration, Instant};

use dashmap::DashMap;
use thiserror::Error;

// ---------------------------------------------------------------------------
// Type aliases
// ---------------------------------------------------------------------------

/// Unique identity string for an agent session.
pub type AgentId = String;

/// Name of an MCP server as declared in `aegis.toml`.
pub type ServerName = String;

// ---------------------------------------------------------------------------
// WindowState
// ---------------------------------------------------------------------------

/// Per-`(AgentId, ServerName)` sliding-window state.
///
/// Stored inside the [`SlidingWindowCounter`]'s [`DashMap`] and updated
/// in-place on every call to [`SlidingWindowCounter::check_rate_limit`].
#[derive(Debug, Clone)]
pub struct WindowState {
    /// Monotonic timestamp of when the current window started.
    pub window_start: Instant,
    /// Number of calls recorded in the current window.
    pub call_count: u64,
    /// Maximum calls allowed per window.
    pub max_calls: u64,
    /// Width of each window in seconds.
    pub window_seconds: u64,
}

impl WindowState {
    fn new(max_calls: u64, window_seconds: u64) -> Self {
        Self {
            window_start: Instant::now(),
            call_count: 0,
            max_calls,
            window_seconds,
        }
    }

    /// Returns `true` when the current window has expired relative to `now`.
    fn is_expired(&self, now: Instant) -> bool {
        now.duration_since(self.window_start) >= Duration::from_secs(self.window_seconds)
    }

    /// Reset the window, starting a fresh one at `now`.
    fn reset(&mut self, now: Instant) {
        self.window_start = now;
        self.call_count = 0;
    }

    /// Milliseconds remaining until this window closes.
    fn ms_until_reset(&self, now: Instant) -> u64 {
        let window_end = self.window_start + Duration::from_secs(self.window_seconds);
        if window_end > now {
            (window_end - now).as_millis() as u64
        } else {
            0
        }
    }
}

// ---------------------------------------------------------------------------
// RateLimitExceeded
// ---------------------------------------------------------------------------

/// Error returned when an agent has exceeded its call quota for the window.
#[derive(Debug, Error)]
#[error(
    "rate limit exceeded: agent='{agent_id}' server='{server_name}' \
     {call_count}/{max_calls} calls in {window_seconds}s window, \
     retry after {retry_after_ms}ms"
)]
pub struct RateLimitExceeded {
    /// The agent that was throttled.
    pub agent_id: String,
    /// The server the agent tried to call.
    pub server_name: String,
    /// Calls already recorded in the current window (equals `max_calls`).
    pub call_count: u64,
    /// The configured maximum.
    pub max_calls: u64,
    /// Width of the window in seconds.
    pub window_seconds: u64,
    /// How many milliseconds until the window resets and calls are permitted
    /// again.  Use this as `retry_after_ms` in the JSON-RPC error data.
    pub retry_after_ms: u64,
}

// ---------------------------------------------------------------------------
// SlidingWindowCounter
// ---------------------------------------------------------------------------

/// Concurrent per-agent, per-server sliding-window rate limiter.
///
/// Uses a [`DashMap`] keyed by `(AgentId, ServerName)` so individual agent
/// buckets never contend with each other.  The map grows lazily as new
/// `(agent, server)` pairs are seen.
///
/// Create one `SlidingWindowCounter` per server and share it via `Arc` across
/// all concurrent sessions for that server.
pub struct SlidingWindowCounter {
    windows: DashMap<(AgentId, ServerName), WindowState>,
    max_calls: u64,
    window_seconds: u64,
}

impl SlidingWindowCounter {
    /// Create a new counter enforcing `max_calls` per `window_seconds`.
    ///
    /// # Panics
    ///
    /// Panics if `max_calls == 0` or `window_seconds == 0` (both must be
    /// positive, matching the validation applied to `aegis.toml`).
    pub fn new(max_calls: u64, window_seconds: u64) -> Self {
        assert!(max_calls > 0, "max_calls must be > 0");
        assert!(window_seconds > 0, "window_seconds must be > 0");
        Self {
            windows: DashMap::new(),
            max_calls,
            window_seconds,
        }
    }

    /// Record one call attempt for `(agent_id, server_name)`.
    ///
    /// ## Semantics
    ///
    /// 1. If no window exists for the pair, a new one is created and the call
    ///    is counted (always succeeds on the first call).
    /// 2. If the existing window has expired, it is reset and the call is
    ///    counted in the new window.
    /// 3. If the window is current and `call_count < max_calls`, the call is
    ///    counted (`Ok(())`).
    /// 4. If the window is current and `call_count == max_calls`, the call is
    ///    rejected (`Err(RateLimitExceeded)`); the counter is **not**
    ///    incremented beyond `max_calls`.
    pub fn check_rate_limit(
        &self,
        agent_id: &str,
        server_name: &str,
    ) -> Result<(), RateLimitExceeded> {
        let key = (agent_id.to_string(), server_name.to_string());
        let now = Instant::now();

        let mut state = self
            .windows
            .entry(key)
            .or_insert_with(|| WindowState::new(self.max_calls, self.window_seconds));

        // Window expired → start a fresh one
        if state.is_expired(now) {
            state.reset(now);
        }

        if state.call_count >= state.max_calls {
            return Err(RateLimitExceeded {
                agent_id: agent_id.to_string(),
                server_name: server_name.to_string(),
                call_count: state.call_count,
                max_calls: state.max_calls,
                window_seconds: state.window_seconds,
                retry_after_ms: state.ms_until_reset(now),
            });
        }

        state.call_count += 1;
        Ok(())
    }

    /// Number of distinct `(agent, server)` pairs currently tracked.
    pub fn tracked_pairs(&self) -> usize {
        self.windows.len()
    }

    /// Snapshot of the window state for a specific pair, if it exists.
    pub fn state_for(&self, agent_id: &str, server_name: &str) -> Option<WindowState> {
        self.windows
            .get(&(agent_id.to_string(), server_name.to_string()))
            .map(|r| r.clone())
    }

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

    /// Back-date the window start for a pair so it appears expired.
    ///
    /// Only compiled in `#[cfg(test)]` — production code must not bypass
    /// the window clock.
    #[cfg(test)]
    pub fn expire_window_for(&self, agent_id: &str, server_name: &str) {
        let key = (agent_id.to_string(), server_name.to_string());
        if let Some(mut entry) = self.windows.get_mut(&key) {
            // Backdate by window_seconds + 1 s to ensure `is_expired` returns true.
            entry.window_start =
                Instant::now() - Duration::from_secs(entry.window_seconds + 1);
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
    // 1. Under the limit — every call succeeds
    // -----------------------------------------------------------------------

    #[test]
    fn under_limit_all_calls_pass() {
        let c = SlidingWindowCounter::new(5, 60);
        for i in 0..4 {
            assert!(
                c.check_rate_limit("agent", "github").is_ok(),
                "call {} should pass",
                i + 1
            );
        }
    }

    // -----------------------------------------------------------------------
    // 2. At the limit — the max_calls-th call still succeeds
    // -----------------------------------------------------------------------

    #[test]
    fn at_limit_last_call_passes() {
        let c = SlidingWindowCounter::new(3, 60);
        // first two
        c.check_rate_limit("agent", "srv").unwrap();
        c.check_rate_limit("agent", "srv").unwrap();
        // third — exactly at max_calls → must succeed
        assert!(
            c.check_rate_limit("agent", "srv").is_ok(),
            "the max_calls-th call must still return Ok"
        );
    }

    // -----------------------------------------------------------------------
    // 3. Over the limit — calls beyond max_calls are rejected
    // -----------------------------------------------------------------------

    #[test]
    fn over_limit_rejects() {
        let c = SlidingWindowCounter::new(3, 60);
        for _ in 0..3 {
            c.check_rate_limit("agent", "srv").unwrap();
        }
        // 4th call — over limit
        let err = c
            .check_rate_limit("agent", "srv")
            .expect_err("4th call must be rejected");

        assert_eq!(err.call_count, 3);
        assert_eq!(err.max_calls, 3);
        assert_eq!(err.window_seconds, 60);
        assert_eq!(err.agent_id, "agent");
        assert_eq!(err.server_name, "srv");
        // retry_after_ms should be in (0, 60_000]
        assert!(err.retry_after_ms > 0);
        assert!(err.retry_after_ms <= 60_000);
    }

    // -----------------------------------------------------------------------
    // 4. Window expiry — counter resets, calls succeed again
    // -----------------------------------------------------------------------

    #[test]
    fn window_expiry_resets_counter() {
        let c = SlidingWindowCounter::new(2, 60);

        // Exhaust the window
        c.check_rate_limit("agent", "srv").unwrap();
        c.check_rate_limit("agent", "srv").unwrap();
        assert!(c.check_rate_limit("agent", "srv").is_err(), "should be limited");

        // Force the window to expire
        c.expire_window_for("agent", "srv");

        // Counter has reset — both calls should pass again
        assert!(
            c.check_rate_limit("agent", "srv").is_ok(),
            "first call after window reset must succeed"
        );
        assert!(
            c.check_rate_limit("agent", "srv").is_ok(),
            "second call after window reset must succeed"
        );
        // Third is over limit again
        assert!(c.check_rate_limit("agent", "srv").is_err());
    }

    // -----------------------------------------------------------------------
    // 5. Per-agent isolation — exhausting one agent does not affect another
    // -----------------------------------------------------------------------

    #[test]
    fn per_agent_isolation() {
        let c = SlidingWindowCounter::new(2, 60);

        // Exhaust agent-a
        c.check_rate_limit("agent-a", "github").unwrap();
        c.check_rate_limit("agent-a", "github").unwrap();
        assert!(c.check_rate_limit("agent-a", "github").is_err());

        // agent-b is completely unaffected
        assert!(c.check_rate_limit("agent-b", "github").is_ok());
        assert!(c.check_rate_limit("agent-b", "github").is_ok());
        assert!(c.check_rate_limit("agent-b", "github").is_err());
    }

    // -----------------------------------------------------------------------
    // 6. Per-server isolation — same agent on different servers is independent
    // -----------------------------------------------------------------------

    #[test]
    fn per_server_isolation() {
        let c = SlidingWindowCounter::new(1, 60);

        // Exhaust "github" server for this agent
        c.check_rate_limit("agent", "github").unwrap();
        assert!(c.check_rate_limit("agent", "github").is_err());

        // Same agent on "slack" server still has a full quota
        assert!(
            c.check_rate_limit("agent", "slack").is_ok(),
            "different server must have its own independent window"
        );
    }

    // -----------------------------------------------------------------------
    // 7. New (agent, server) pair gets its own fresh window
    // -----------------------------------------------------------------------

    #[test]
    fn new_pair_starts_with_fresh_window() {
        let c = SlidingWindowCounter::new(3, 60);
        // A pair never seen before — all three calls must succeed
        assert!(c.check_rate_limit("brand-new", "server").is_ok());
        assert!(c.check_rate_limit("brand-new", "server").is_ok());
        assert!(c.check_rate_limit("brand-new", "server").is_ok());
        assert!(c.check_rate_limit("brand-new", "server").is_err()); // now over
    }

    // -----------------------------------------------------------------------
    // 8. tracked_pairs grows and state_for returns correct snapshot
    // -----------------------------------------------------------------------

    #[test]
    fn tracked_pairs_and_state_for() {
        let c = SlidingWindowCounter::new(10, 60);
        assert_eq!(c.tracked_pairs(), 0);

        c.check_rate_limit("agent-1", "s1").unwrap();
        c.check_rate_limit("agent-2", "s1").unwrap();
        c.check_rate_limit("agent-1", "s2").unwrap();

        assert_eq!(c.tracked_pairs(), 3);

        let st = c.state_for("agent-1", "s1").expect("should exist");
        assert_eq!(st.call_count, 1);
        assert_eq!(st.max_calls, 10);
        assert_eq!(st.window_seconds, 60);

        // A pair that was never seen returns None
        assert!(c.state_for("nobody", "nowhere").is_none());
    }

    // -----------------------------------------------------------------------
    // 9. RateLimitExceeded error message contains all relevant fields
    // -----------------------------------------------------------------------

    #[test]
    fn error_message_contains_fields() {
        let c = SlidingWindowCounter::new(1, 30);
        c.check_rate_limit("my-agent", "my-server").unwrap();
        let err = c.check_rate_limit("my-agent", "my-server").unwrap_err();

        let msg = err.to_string();
        assert!(msg.contains("my-agent"), "message: {msg}");
        assert!(msg.contains("my-server"), "message: {msg}");
        assert!(msg.contains("1/1"), "message: {msg}");
        assert!(msg.contains("30s"), "message: {msg}");
        assert!(msg.contains("retry after"), "message: {msg}");
    }

    // -----------------------------------------------------------------------
    // 10. Window expiry with real sleep (1-second window)
    // -----------------------------------------------------------------------

    #[test]
    fn window_expiry_real_time() {
        // 1-second window so we can sleep briefly
        let c = SlidingWindowCounter::new(1, 1);

        c.check_rate_limit("a", "s").unwrap();
        assert!(c.check_rate_limit("a", "s").is_err(), "should be limited");

        // Wait for window to expire naturally
        std::thread::sleep(Duration::from_millis(1_100));

        assert!(
            c.check_rate_limit("a", "s").is_ok(),
            "should be allowed after real window expiry"
        );
    }

    // -----------------------------------------------------------------------
    // 11. Repeated window expiry — multiple cycles work correctly
    // -----------------------------------------------------------------------

    #[test]
    fn multiple_window_cycles() {
        let c = SlidingWindowCounter::new(3, 60);

        // Cycle 1
        for _ in 0..3 {
            c.check_rate_limit("agent", "srv").unwrap();
        }
        assert!(c.check_rate_limit("agent", "srv").is_err());

        // Cycle 2
        c.expire_window_for("agent", "srv");
        for _ in 0..3 {
            c.check_rate_limit("agent", "srv").unwrap();
        }
        assert!(c.check_rate_limit("agent", "srv").is_err());

        // Cycle 3
        c.expire_window_for("agent", "srv");
        assert!(c.check_rate_limit("agent", "srv").is_ok());
    }

    // -----------------------------------------------------------------------
    // 12. High-concurrency: many agents simultaneously (basic smoke test)
    // -----------------------------------------------------------------------

    #[test]
    fn concurrent_agents_do_not_interfere() {
        use std::sync::Arc;
        use std::thread;

        let c = Arc::new(SlidingWindowCounter::new(10, 60));
        let mut handles = Vec::new();

        for i in 0..20 {
            let c2 = Arc::clone(&c);
            handles.push(thread::spawn(move || {
                let agent = format!("agent-{i}");
                // Each agent makes exactly 10 calls — all should succeed
                for _ in 0..10 {
                    c2.check_rate_limit(&agent, "shared-server").unwrap();
                }
                // The 11th must fail
                assert!(c2.check_rate_limit(&agent, "shared-server").is_err());
            }));
        }

        for h in handles {
            h.join().expect("thread panicked");
        }
    }
}
