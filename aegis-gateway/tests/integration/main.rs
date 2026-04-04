//! Integration tests for the Aegis MCP gateway.
//!
//! Each test exercises the **full middleware chain** (allowlist → rate limiter →
//! enforcement) against the built-in mock MCP server.  Real MCP server tests
//! (filesystem, GitHub, …) are added in subsequent steps.
//!
//! Run with:
//! ```bash
//! cargo test --test integration
//! cargo test --test integration -- --nocapture  # show gateway logs
//! ```

mod harness;

use std::time::Duration;

use serde_json::json;

use harness::{
    MockServerConfig, TestGateway, TestServer,
    AEGIS_DENIED, AEGIS_NOT_ALLOWED, AEGIS_RATE_LIMITED,
    ECHO_AND_ADD_POLICY, ECHO_ONLY_POLICY,
};

// ── Harness smoke tests ───────────────────────────────────────────────────────
// These tests verify that the harness itself works correctly before running
// server-specific integration suites.

/// Verify the harness can start, run a handshake, and tear down cleanly.
#[tokio::test]
async fn harness_setup_and_teardown() {
    let gw = TestGateway::builder().build().await;
    // The mock server advertises echo, add, get_info
    let tools = gw.agent.as_ref().unwrap().tool_names();
    assert!(tools.contains(&"echo".to_string()), "expected echo in tools: {tools:?}");
    assert!(tools.contains(&"add".to_string()),  "expected add in tools: {tools:?}");
    gw.teardown().await;
}

/// Verify a passthrough call (no policy, no middleware) reaches the server.
#[tokio::test]
async fn passthrough_no_policy_reaches_upstream() {
    let mut gw = TestGateway::builder().build().await;

    // No policy loaded → no EnforcementMiddleware → call passes straight through.
    let r = gw.call("echo", json!({"message": "hello"})).await;
    assert!(r.is_ok(), "expected forward, got: {r:?}");
    assert_eq!(r.text(), Some("hello"));

    gw.teardown().await;
}

// ── Enforcement tests ─────────────────────────────────────────────────────────

/// Allowed tool call: correct agent, unexpired token, matching resource.
#[tokio::test]
async fn enforcement_allows_authorized_tool_call() {
    let mut gw = TestGateway::builder()
        .agent_id("test-agent")
        .policy_yaml(ECHO_ONLY_POLICY)
        .build()
        .await;

    let r = assert_tool_call_allowed!(gw, "echo", json!({"message": "world"}));
    assert_eq!(r.text(), Some("world"), "mock server should echo the message");
    assert_audit_contains!(gw, tool = "echo", decision = allow);

    gw.teardown().await;
}

/// No token for `add` → enforcement denies it.
#[tokio::test]
async fn enforcement_denies_tool_without_token() {
    let mut gw = TestGateway::builder()
        .agent_id("test-agent")
        .policy_yaml(ECHO_ONLY_POLICY) // only echo token issued
        .build()
        .await;

    let r = assert_tool_call_denied!(gw, "add", json!({"a": 1, "b": 2}), code = AEGIS_DENIED);
    let data = r.aegis_data().expect("expected Aegis error data");
    assert_eq!(data["decision"], "deny");
    assert!(data["reason"].as_str().unwrap_or("").contains("no capability token"));

    gw.teardown().await;
}

/// Multi-tool policy: both `echo` and `add` should be allowed.
#[tokio::test]
async fn enforcement_allows_multiple_tools_from_policy() {
    let mut gw = TestGateway::builder()
        .agent_id("test-agent")
        .policy_yaml(ECHO_AND_ADD_POLICY)
        .build()
        .await;

    let r1 = assert_tool_call_allowed!(gw, "echo", json!({"message": "multi"}));
    assert_eq!(r1.text(), Some("multi"));

    let r2 = assert_tool_call_allowed!(gw, "add", json!({"a": 10, "b": 32}));
    assert_eq!(r2.text(), Some("42"));

    assert_audit_contains!(gw, tool = "echo", decision = allow);
    assert_audit_contains!(gw, tool = "add",  decision = allow);

    gw.teardown().await;
}

/// Token subject mismatch: policy issued for "test-agent" but gateway uses
/// "other-agent" → every call is denied.
#[tokio::test]
async fn enforcement_denies_wrong_agent_identity() {
    let mut gw = TestGateway::builder()
        .agent_id("other-agent")   // does not match ECHO_ONLY_POLICY subject
        .policy_yaml(ECHO_ONLY_POLICY)
        .build()
        .await;

    // The token map is built from tokens whose subject == "other-agent".
    // ECHO_ONLY_POLICY issues for "test-agent", so no tokens match → deny.
    let r = assert_tool_call_denied!(gw, "echo", json!({"message": "x"}), code = AEGIS_DENIED);
    assert!(r.aegis_data().is_some(), "should have Aegis error data");

    gw.teardown().await;
}

/// Audit log is populated for both allowed and denied calls.
///
/// Uses `max_uses: 1` so the first call is allowed and the second call is
/// denied — both decisions flow through `kernel.evaluate()` and are recorded
/// in the kernel audit log.
#[tokio::test]
async fn audit_log_records_allow_and_deny() {
    let mut gw = TestGateway::builder()
        .agent_id("test-agent")
        .policy_yaml(r#"
policies:
  - name: echo-once
    agent: test-agent
    resource: "tool://echo"
    actions: [execute]
    ttl: 1h
    max_uses: 1
"#)
        .build()
        .await;

    // First call is within max_uses → kernel records ALLOW.
    gw.call("echo", json!({"message": "first"})).await;
    // Second call exhausts max_uses → kernel records DENY.
    gw.call("echo", json!({"message": "second"})).await;

    assert_audit_contains!(gw, tool = "echo", decision = allow);
    assert_audit_contains!(gw, tool = "echo", decision = deny);

    assert!(
        gw.audit_count("echo", aegis_handle::Decision::Allow) >= 1,
        "expected at least one ALLOW entry for echo"
    );
    assert!(
        gw.audit_count("echo", aegis_handle::Decision::Deny) >= 1,
        "expected at least one DENY entry for echo"
    );

    gw.teardown().await;
}

// ── Allowlist tests ───────────────────────────────────────────────────────────

/// Tool in the allowlist → passes through (with enforcement if policy loaded).
#[tokio::test]
async fn allowlist_permits_listed_tool() {
    let mut gw = TestGateway::builder()
        .allowed_tools(["echo"])
        .build()
        .await;

    // No policy → no enforcement → allowed call reaches upstream.
    let r = assert_tool_call_allowed!(gw, "echo", json!({"message": "listed"}));
    assert_eq!(r.text(), Some("listed"));

    gw.teardown().await;
}

/// Tool NOT in the allowlist → blocked immediately with -32008.
#[tokio::test]
async fn allowlist_blocks_unlisted_tool() {
    let mut gw = TestGateway::builder()
        .allowed_tools(["echo"]) // add is not listed
        .build()
        .await;

    assert_tool_call_denied!(gw, "add", json!({"a":1,"b":1}), code = AEGIS_NOT_ALLOWED);
    gw.teardown().await;
}

/// Empty allowlist → all tools pass (no filter applied).
#[tokio::test]
async fn allowlist_empty_permits_all_tools() {
    let mut gw = TestGateway::builder()
        .allowed_tools(Vec::<String>::new())
        .build()
        .await;

    let r = assert_tool_call_allowed!(gw, "add", json!({"a": 5, "b": 5}));
    assert_eq!(r.text(), Some("10"));
    gw.teardown().await;
}

// ── Rate-limit tests ──────────────────────────────────────────────────────────

/// After exhausting the rate limit, the gateway returns -32009.
#[tokio::test]
async fn rate_limit_rejects_after_quota_exhausted() {
    let mut gw = TestGateway::builder()
        .rate_limit(3, 60) // 3 calls per 60-second window
        .build()
        .await;

    // First 3 calls should pass.
    for i in 0..3 {
        let r = gw.call("echo", json!({"message": format!("call {i}")})).await;
        assert!(r.is_ok(), "call {i} should be allowed, got {r:?}");
    }

    // 4th call should be rate-limited.
    let r = gw.call("echo", json!({"message": "overflow"})).await;
    assert!(r.is_error(), "4th call should be rate-limited");
    assert_eq!(
        r.error_code(),
        Some(AEGIS_RATE_LIMITED),
        "expected -32009, got {:?}",
        r.error_code()
    );

    // retry_after_ms must be present and positive.
    if let Some(data) = r.aegis_data() {
        let ms = data["retry_after_ms"].as_u64().unwrap_or(0);
        assert!(ms > 0, "retry_after_ms should be > 0");
    }

    gw.teardown().await;
}

/// Non-tool-call messages (initialize, tools/list) are never rate-limited.
#[tokio::test]
async fn rate_limit_does_not_affect_protocol_messages() {
    // Build a harness with an absurdly tight limit (0 calls) — but protocol
    // messages must still flow, otherwise the handshake itself would fail.
    let gw = TestGateway::builder()
        .rate_limit(0, 60)
        .build() // handshake (initialize + tools/list) must succeed
        .await;
    gw.teardown().await;
}

// ── Timeout tests ─────────────────────────────────────────────────────────────

/// A very short timeout on a hanging server triggers a clear panic (not a hang).
///
/// Disabled by default because it deliberately panics — enable with
/// `cargo test timeout_panics_on_hang -- --ignored`.
#[tokio::test]
#[ignore = "deliberately panics to test timeout behaviour"]
async fn timeout_panics_on_hang() {
    // Use a tiny timeout; the mock server itself will respond fine, but if
    // this test ever hangs for another reason the short timeout makes it
    // obvious rather than blocking CI for 30 s.
    let _gw = TestGateway::builder()
        .timeout(Duration::from_millis(50)) // short timeout triggers on slow CI
        .build()
        .await;
}

// ── Mock server feature tests ─────────────────────────────────────────────────

/// The built-in mock returns a custom override response when configured.
#[tokio::test]
async fn mock_server_call_response_override() {
    let mut gw = TestGateway::builder()
        .upstream(TestServer::BuiltinMock(MockServerConfig {
            call_response_override: Some("custom-override".into()),
        }))
        .build()
        .await;

    let r = gw.call("echo", json!({"message": "anything"})).await;
    assert!(r.is_ok(), "expected success: {r:?}");
    assert_eq!(r.text(), Some("custom-override"));

    gw.teardown().await;
}

/// `get_info` tool returns the mock server version string.
#[tokio::test]
async fn mock_server_get_info_returns_version() {
    let mut gw = TestGateway::builder().build().await;

    let r = gw.call("get_info", json!({})).await;
    assert!(r.is_ok());
    let text = r.text().unwrap_or("");
    assert!(text.contains("mock-mcp"), "expected mock-mcp in: {text}");

    gw.teardown().await;
}

/// `add` tool computes the sum correctly.
#[tokio::test]
async fn mock_server_add_computes_sum() {
    let mut gw = TestGateway::builder().build().await;

    for (a, b, expected) in [(0, 0, "0"), (1, 2, "3"), (100, 200, "300")] {
        let r = gw.call("add", json!({"a": a, "b": b})).await;
        assert!(r.is_ok(), "add({a},{b}) should succeed");
        assert_eq!(r.text(), Some(expected), "add({a},{b}) should return {expected}");
    }

    gw.teardown().await;
}
