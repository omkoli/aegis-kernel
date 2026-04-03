//! Integration test: verifies that Prometheus metrics are populated correctly
//! as tool calls flow through the Aegis proxy pipeline.
//!
//! Each test creates an isolated `PrometheusRecorder` (without global installation)
//! and uses `metrics::with_local_recorder` to scope emissions to that recorder,
//! then renders the snapshot and asserts expected metric names/labels appear.

use std::sync::Arc;

use aegis_gateway::proxy::{
    AllowlistMiddleware, EnforcementMiddleware, InterceptionMiddleware, InterceptionResult,
    RateLimiter, RateLimiterMiddleware, AEGIS_ERROR_NOT_ALLOWED,
};
use aegis_handle::{Action, Constraints, KernelHandle, Resource, TokenRequest};
use aegis_mcp::{McpMessage, McpRequest, RequestId};
use metrics_exporter_prometheus::PrometheusBuilder;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn tool_call_msg(tool: &str) -> McpMessage {
    McpMessage::Request(McpRequest {
        jsonrpc: "2.0".into(),
        id: RequestId::Number(1),
        method: "tools/call".into(),
        params: Some(serde_json::json!({ "name": tool, "arguments": {} })),
    })
}

fn issue_token(kernel: &KernelHandle, agent: &str, tool: &str) -> Uuid {
    let resource = Resource::new(format!("tool://{tool}")).unwrap();
    kernel
        .issue_token(TokenRequest {
            subject: agent.into(),
            resource,
            actions: vec![Action::Execute],
            constraints: Constraints::new(),
            ttl: None,
            delegatable: false,
            max_uses: None,
        })
        .unwrap()
        .token
        .id()
}

// ---------------------------------------------------------------------------
// Test 1: enforcement allow + deny → counters and duration histograms
// ---------------------------------------------------------------------------

#[test]
fn enforcement_metrics_allow_and_deny() {
    let recorder = PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();

    let kernel = Arc::new(KernelHandle::new());
    let token_id = issue_token(&kernel, "test-agent", "read_file");
    let mw = EnforcementMiddleware::new(Arc::clone(&kernel), "test-agent", token_id)
        .with_server_name("test-server");

    metrics::with_local_recorder(&recorder, || {
        // Allowed
        let r = mw.on_request(tool_call_msg("read_file"));
        assert!(matches!(r, InterceptionResult::Forward(_)), "read_file should be allowed");

        // Denied (wrong tool)
        let r = mw.on_request(tool_call_msg("delete_file"));
        assert!(matches!(r, InterceptionResult::Block(_)), "delete_file should be denied");
    });

    let snap = handle.render();

    assert!(snap.contains("aegis_tool_calls_total"), "missing aegis_tool_calls_total\n{snap}");
    assert!(snap.contains(r#"decision="allow""#), "missing allow label\n{snap}");
    assert!(snap.contains(r#"decision="deny""#), "missing deny label\n{snap}");
    assert!(snap.contains(r#"server="test-server""#), "missing server label\n{snap}");
    assert!(snap.contains("aegis_tool_call_duration_seconds"), "missing tool_call_duration\n{snap}");
    assert!(snap.contains("aegis_enforcement_duration_seconds"), "missing enforcement_duration\n{snap}");
}

// ---------------------------------------------------------------------------
// Test 2: allowlist block → tool_calls_total{decision="allowlist_blocked"}
// ---------------------------------------------------------------------------

#[test]
fn allowlist_metrics_blocked() {
    let recorder = PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();

    use aegis_gateway::config::ServerConfig;
    use aegis_gateway::IdentityStrategy;
    use std::collections::HashMap;

    let config = ServerConfig {
        command: Some("npx some-server".into()),
        url: None,
        transport: "stdio".into(),
        env: HashMap::new(),
        allowed_tools: vec!["safe_tool".to_string()],
        rate_limit: None,
        identity_strategy: IdentityStrategy::default(),
        tool_rate_limits: HashMap::new(),
        tools: HashMap::new(),
    };

    let mw = AllowlistMiddleware::new("my-server", "my-agent", config);

    metrics::with_local_recorder(&recorder, || {
        let result = mw.on_request(tool_call_msg("forbidden_tool"));
        assert!(
            matches!(&result, InterceptionResult::Block(e) if e.code == AEGIS_ERROR_NOT_ALLOWED),
            "forbidden_tool should be blocked"
        );
    });

    let snap = handle.render();

    assert!(
        snap.contains(r#"decision="allowlist_blocked""#),
        "missing allowlist_blocked decision\n{snap}"
    );
    assert!(snap.contains(r#"server="my-server""#), "missing server label\n{snap}");
}

// ---------------------------------------------------------------------------
// Test 3: rate limit rejection → dedicated counter + rate_limited decision
// ---------------------------------------------------------------------------

#[test]
fn rate_limit_rejection_metrics() {
    let recorder = PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();

    use aegis_gateway::config::RateLimitConfig;
    use std::collections::HashMap;

    let limit = RateLimitConfig { max_calls: 1, window_seconds: 60, burst_size: None };
    let limiter = Arc::new(RateLimiter::new("rate-server", Some(limit), HashMap::new()));
    let mw = RateLimiterMiddleware::new("rate-agent", Arc::clone(&limiter));

    metrics::with_local_recorder(&recorder, || {
        // First call: consumes the single token (allowed)
        let r1 = mw.on_request(tool_call_msg("my_tool"));
        assert!(matches!(r1, InterceptionResult::Forward(_)));

        // Second call: rate limited
        let r2 = mw.on_request(tool_call_msg("my_tool"));
        assert!(matches!(r2, InterceptionResult::Block(_)));
    });

    let snap = handle.render();

    assert!(
        snap.contains("aegis_rate_limit_rejections_total"),
        "missing rate_limit_rejections_total\n{snap}"
    );
    assert!(snap.contains(r#"server="rate-server""#), "missing server label\n{snap}");
    assert!(
        snap.contains(r#"decision="rate_limited""#),
        "missing rate_limited in tool_calls_total\n{snap}"
    );
}

// ---------------------------------------------------------------------------
// Test 4: active_connections gauge key appears in snapshot
// ---------------------------------------------------------------------------

#[test]
fn active_connections_gauge_recorded() {
    let recorder = PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();

    metrics::with_local_recorder(&recorder, || {
        // Simulate a session starting and ending.
        metrics::gauge!(aegis_gateway::metrics::ACTIVE_CONNECTIONS, "transport" => "stdio")
            .increment(1.0);
        metrics::gauge!(aegis_gateway::metrics::ACTIVE_CONNECTIONS, "transport" => "stdio")
            .decrement(1.0);
    });

    let snap = handle.render();
    assert!(
        snap.contains("aegis_active_connections"),
        "missing active_connections gauge\n{snap}"
    );
    assert!(snap.contains(r#"transport="stdio""#), "missing transport label\n{snap}");
}

// ---------------------------------------------------------------------------
// Test 5: load simulation — 20 allowed + 5 denied, verify cumulative counts
// ---------------------------------------------------------------------------

#[test]
fn load_simulation_counter_values() {
    let recorder = PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();

    let kernel = Arc::new(KernelHandle::new());
    let token_id = issue_token(&kernel, "load-agent", "read_file");
    let mw = EnforcementMiddleware::new(Arc::clone(&kernel), "load-agent", token_id)
        .with_server_name("load-server");

    metrics::with_local_recorder(&recorder, || {
        for _ in 0..20 {
            mw.on_request(tool_call_msg("read_file"));   // allowed
        }
        for _ in 0..5 {
            mw.on_request(tool_call_msg("write_file"));  // denied
        }
    });

    let snap = handle.render();

    // Both decisions must appear
    assert!(snap.contains(r#"decision="allow""#), "missing allow\n{snap}");
    assert!(snap.contains(r#"decision="deny""#), "missing deny\n{snap}");

    // The histogram sum/count lines must be present for duration metrics
    assert!(
        snap.contains("aegis_tool_call_duration_seconds_sum"),
        "missing duration sum\n{snap}"
    );
    assert!(
        snap.contains("aegis_enforcement_duration_seconds_sum"),
        "missing enforcement sum\n{snap}"
    );
}
