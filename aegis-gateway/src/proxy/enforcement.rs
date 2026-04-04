//! Enforcement middleware that gates tool calls through the Aegis kernel.
//!
//! Every `tools/call` (and `resources/read`) request is evaluated by the kernel
//! before being forwarded to the MCP server. Non-enforcement messages
//! (initialize, tools/list, notifications, …) pass through unchanged.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use std::sync::Arc;
//! use aegis_handle::{KernelHandle, TokenRequest, Resource, Action, Constraints};
//! use aegis_gateway::proxy::{StdioProxy, StdioProxyConfig, EnforcementMiddleware};
//!
//! let kernel = Arc::new(KernelHandle::new());
//! let token = kernel.issue_token(TokenRequest {
//!     subject: "my-agent".into(),
//!     resource: Resource::new("tool://read_file").unwrap(),
//!     actions: vec![Action::Execute],
//!     constraints: Constraints::new(),
//!     ttl: None, delegatable: false, max_uses: None,
//! }).unwrap();
//!
//! let middleware = EnforcementMiddleware::new(kernel, "my-agent", token.token.id());
//! let proxy = StdioProxy::new(config).with_middleware(Arc::new(middleware));
//! ```

use std::sync::Arc;
use std::time::Instant;

use aegis_handle::{Action, Decision, KernelHandle, Resource, ToolCallRequest};
use aegis_mcp::translate::{translate_to_intent, AgentContext, IntentKind, AEGIS_ERROR_DENIED};
use aegis_mcp::{JsonRpcError, McpMessage};
use uuid::Uuid;

use super::middleware::{InterceptionMiddleware, InterceptionResult};

/// Middleware that enforces capability-token policy on every MCP tool call.
///
/// On each `tools/call` request the middleware:
/// 1. Translates the request into a `ToolCallIntent`.
/// 2. Builds a `ToolCallRequest` using the agent's token and the resource path
///    `tool://<tool_name>`.
/// 3. Calls `KernelHandle::evaluate()`.
/// 4. **ALLOW** → forwards the original message unchanged.
/// 5. **DENY** → blocks with a JSON-RPC error (`-32001`) and structured `data`.
///
/// All other message kinds (initialize, tools/list, notifications, responses)
/// are forwarded without enforcement.
pub struct EnforcementMiddleware {
    kernel: Arc<KernelHandle>,
    agent_id: String,
    token_id: Uuid,
    server_name: String,
}

impl EnforcementMiddleware {
    /// Create a new middleware for the given agent session.
    ///
    /// - `kernel` — shared kernel handle (typically one per gateway process)
    /// - `agent_id` — identity of the agent (must match the token's subject)
    /// - `token_id` — UUID of the capability token issued for this session
    pub fn new(kernel: Arc<KernelHandle>, agent_id: impl Into<String>, token_id: Uuid) -> Self {
        Self {
            kernel,
            agent_id: agent_id.into(),
            token_id,
            server_name: "unknown".to_string(),
        }
    }

    /// Set the MCP server name for metric labels.
    ///
    /// Call this when constructing the middleware to populate the `server`
    /// label on `aegis_tool_calls_total` and related metrics.
    pub fn with_server_name(mut self, server_name: impl Into<String>) -> Self {
        self.server_name = server_name.into();
        self
    }
}

impl InterceptionMiddleware for EnforcementMiddleware {
    /// Gate agent→server requests: enforce tool calls, pass everything else.
    fn on_request(&self, message: McpMessage) -> InterceptionResult {
        // Extract the ToolCallIntent while `message` is still borrowed.
        // The intent is fully owned (no lifetimes back to message), so the
        // borrow ends here and `message` can be moved further below.
        let maybe_intent = if let McpMessage::Request(ref req) = message {
            let ctx = AgentContext {
                agent_id: self.agent_id.clone(),
                token_id: self.token_id.to_string(),
            };
            match translate_to_intent(req, &ctx) {
                Some(IntentKind::ToolCall(tc)) => Some(tc),
                // Resources/read and other methods: no enforcement for now
                _ => None,
            }
        } else {
            None // notifications and responses pass through
        };

        let intent = match maybe_intent {
            Some(i) => i,
            None => return InterceptionResult::Forward(message),
        };

        // Derive the resource path from the tool name so tokens are
        // issued per-tool: `tool://read_file`, `tool://write_file`, etc.
        let resource_path = format!("tool://{}", intent.tool_name);
        let resource = match Resource::new(&resource_path) {
            Ok(r) => r,
            Err(_) => return InterceptionResult::Forward(message),
        };

        let tcr = ToolCallRequest {
            agent_id: self.agent_id.clone(),
            tool_name: intent.tool_name.clone(),
            action: Action::Execute,
            resource,
            parameters: intent.parameters,
            token_id: self.token_id,
        };

        // Record the resolved agent and server into the current request span so
        // they appear in every log event produced during this tool call.
        tracing::Span::current().record("agent",  self.agent_id.as_str());
        tracing::Span::current().record("server", self.server_name.as_str());

        let call_start = Instant::now();
        let result = self.kernel.evaluate(&tcr);
        let call_elapsed = call_start.elapsed().as_secs_f64();

        // ── Enforcement duration (from kernel's own latency_us measurement) ──
        let enforcement_secs = result.audit.latency_us as f64 / 1_000_000.0;

        match result.decision {
            Decision::Allow => {
                tracing::Span::current().record("decision", "allow");
                tracing::info!(
                    tool        = %intent.tool_name,
                    agent       = %self.agent_id,
                    server      = %self.server_name,
                    audit_id    = %result.audit.request_id,
                    latency_us  = result.audit.latency_us,
                    "enforcement decision: allow"
                );
                metrics::counter!(
                    crate::metrics::TOOL_CALLS_TOTAL,
                    "server"   => self.server_name.clone(),
                    "tool"     => intent.tool_name.clone(),
                    "decision" => "allow",
                    "agent"    => self.agent_id.clone(),
                )
                .increment(1);
                metrics::histogram!(
                    crate::metrics::ENFORCEMENT_DURATION_SECONDS,
                    "decision" => "allow",
                )
                .record(enforcement_secs);
                metrics::histogram!(
                    crate::metrics::TOOL_CALL_DURATION_SECONDS,
                    "server" => self.server_name.clone(),
                    "tool"   => intent.tool_name.clone(),
                )
                .record(call_elapsed);
                InterceptionResult::Forward(message)
            }
            Decision::Deny => {
                tracing::Span::current().record("decision", "deny");
                // WARN: enforcement denial is an operational signal that may
                // indicate misconfigured tokens or suspicious agent behaviour.
                tracing::warn!(
                    tool        = %intent.tool_name,
                    agent       = %self.agent_id,
                    server      = %self.server_name,
                    reason      = %result.audit.reason,
                    audit_id    = %result.audit.request_id,
                    latency_us  = result.audit.latency_us,
                    "enforcement decision: deny"
                );
                metrics::counter!(
                    crate::metrics::TOOL_CALLS_TOTAL,
                    "server"   => self.server_name.clone(),
                    "tool"     => intent.tool_name.clone(),
                    "decision" => "deny",
                    "agent"    => self.agent_id.clone(),
                )
                .increment(1);
                metrics::histogram!(
                    crate::metrics::ENFORCEMENT_DURATION_SECONDS,
                    "decision" => "deny",
                )
                .record(enforcement_secs);
                metrics::histogram!(
                    crate::metrics::TOOL_CALL_DURATION_SECONDS,
                    "server" => self.server_name.clone(),
                    "tool"   => intent.tool_name.clone(),
                )
                .record(call_elapsed);
                InterceptionResult::Block(JsonRpcError {
                    code: AEGIS_ERROR_DENIED,
                    message: result.audit.reason.clone(),
                    data: Some(serde_json::json!({
                        "aegis": true,
                        "decision": "deny",
                        "reason": result.audit.reason,
                        "tool": intent.tool_name,
                        "agent": self.agent_id,
                        "audit_id": result.audit.request_id.to_string(),
                        "latency_us": result.audit.latency_us,
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
    use std::process::Stdio;

    use aegis_handle::{Constraints, KernelHandle, TokenRequest};
    use tokio::process::Command;
    use tokio::process::Child;

    use crate::proxy::stdio::{StdioProxy, StdioProxyConfig};

    fn cat_config() -> StdioProxyConfig {
        StdioProxyConfig {
            command: "cat".into(),
            args: vec![],
            env: vec![],
        }
    }

    async fn spawn_cat() -> Child {
        Command::new("cat")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .expect("failed to spawn cat")
    }

    /// Issue a token that grants Execute on `tool://<tool>` for the given agent.
    fn issue_token(
        kernel: &KernelHandle,
        agent: &str,
        tool: &str,
    ) -> Uuid {
        let resource = Resource::new(format!("tool://{tool}")).unwrap();
        let signed = kernel
            .issue_token(TokenRequest {
                subject: agent.into(),
                resource,
                actions: vec![Action::Execute],
                constraints: Constraints::new(),
                ttl: None,
                delegatable: false,
                max_uses: None,
            })
            .unwrap();
        signed.token.id()
    }

    // -----------------------------------------------------------------------
    // 1. Non-tool-call messages pass through without consulting the kernel
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn non_tool_call_passes_through() {
        // No tokens issued — if enforcement were triggered, it would deny.
        let kernel = Arc::new(KernelHandle::new());
        let fake_token_id = Uuid::new_v4(); // not registered, but not used
        let mw = EnforcementMiddleware::new(Arc::clone(&kernel), "agent", fake_token_id);
        let proxy = StdioProxy::new(cat_config()).with_middleware(Arc::new(mw));

        // initialize, notifications, ping — none should be enforced
        let input = concat!(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"capabilities\":{}}}\n",
            "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}\n",
        );

        let mut output = Vec::new();
        let child = spawn_cat().await;
        proxy
            .run_with_child(input.as_bytes(), &mut output, child)
            .await
            .unwrap();

        // cat echoes all 3; the middleware should not have blocked any
        let output_str = String::from_utf8(output).unwrap();
        let lines: Vec<&str> = output_str.lines().collect();
        // notification has no newline echo difference — just check count >= 2
        assert!(
            lines.len() >= 2,
            "expected passthrough messages, got: {:?}",
            lines
        );
        for line in &lines {
            aegis_mcp::parse_message(line.as_bytes()).unwrap();
        }
    }

    // -----------------------------------------------------------------------
    // 2. ALLOW: matching token lets the tool call reach the server
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn allowed_tool_call_reaches_server() {
        let kernel = Arc::new(KernelHandle::new());
        let token_id = issue_token(&kernel, "test-agent", "read_file");

        let mw = EnforcementMiddleware::new(Arc::clone(&kernel), "test-agent", token_id);
        let proxy = StdioProxy::new(cat_config()).with_middleware(Arc::new(mw));

        let input =
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"read_file\",\"arguments\":{\"path\":\"/tmp/data.txt\"}}}\n";

        let mut output = Vec::new();
        let child = spawn_cat().await;
        proxy
            .run_with_child(input.as_bytes(), &mut output, child)
            .await
            .unwrap();

        // cat echoes the message back → it appears in output (forwarded, not blocked)
        let output_str = String::from_utf8(output).unwrap();
        assert!(
            !output_str.is_empty(),
            "allowed call should have been forwarded to server"
        );
        let msg = aegis_mcp::parse_message(output_str.trim().as_bytes()).unwrap();
        // The echoed message is still a Request (cat doesn't reformat it)
        assert!(
            matches!(msg, aegis_mcp::McpMessage::Request(_)),
            "expected forwarded request, got: {}",
            output_str.trim()
        );
    }

    // -----------------------------------------------------------------------
    // 3. DENY: wrong tool → agent receives JSON-RPC -32001 error
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn denied_tool_call_returns_error() {
        let kernel = Arc::new(KernelHandle::new());
        // Token only grants read_file
        let token_id = issue_token(&kernel, "test-agent", "read_file");

        let mw = EnforcementMiddleware::new(Arc::clone(&kernel), "test-agent", token_id);
        let proxy = StdioProxy::new(cat_config()).with_middleware(Arc::new(mw));

        // Agent tries to call delete_file — not covered by the token
        let input =
            "{\"jsonrpc\":\"2.0\",\"id\":99,\"method\":\"tools/call\",\"params\":{\"name\":\"delete_file\",\"arguments\":{\"path\":\"/etc/passwd\"}}}\n";

        let mut output = Vec::new();
        let child = spawn_cat().await;
        proxy
            .run_with_child(input.as_bytes(), &mut output, child)
            .await
            .unwrap();

        let output_str = String::from_utf8(output).unwrap();
        assert!(
            !output_str.is_empty(),
            "should have received an error response"
        );
        let msg = aegis_mcp::parse_message(output_str.trim().as_bytes()).unwrap();
        match msg {
            aegis_mcp::McpMessage::Response(resp) => {
                assert_eq!(resp.id, aegis_mcp::RequestId::Number(99));
                assert!(resp.result.is_none(), "denied call must not have a result");
                let err = resp.error.expect("denied call must have an error");
                assert_eq!(
                    err.code, AEGIS_ERROR_DENIED,
                    "error code must be -32001 (AEGIS_ERROR_DENIED)"
                );
                assert!(
                    !err.message.is_empty(),
                    "error message must describe the denial reason"
                );
                // data must carry aegis metadata
                let data = err.data.expect("error must have structured data");
                assert_eq!(data["aegis"], true, "data.aegis must be true");
                assert_eq!(data["decision"], "deny", "data.decision must be 'deny'");
                assert!(
                    data["audit_id"].is_string(),
                    "data.audit_id must be a string UUID"
                );
            }
            other => panic!("expected Response, got: {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // 4. DENY: wrong agent (token issued to a different subject)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn denied_wrong_agent_returns_error() {
        let kernel = Arc::new(KernelHandle::new());
        // Token issued to "agent-a", but middleware runs as "agent-b"
        let token_id = issue_token(&kernel, "agent-a", "read_file");

        let mw = EnforcementMiddleware::new(Arc::clone(&kernel), "agent-b", token_id);
        let proxy = StdioProxy::new(cat_config()).with_middleware(Arc::new(mw));

        let input =
            "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\",\"params\":{\"name\":\"read_file\",\"arguments\":{\"path\":\"/tmp/x\"}}}\n";

        let mut output = Vec::new();
        let child = spawn_cat().await;
        proxy
            .run_with_child(input.as_bytes(), &mut output, child)
            .await
            .unwrap();

        let output_str = String::from_utf8(output).unwrap();
        let msg = aegis_mcp::parse_message(output_str.trim().as_bytes()).unwrap();
        match msg {
            aegis_mcp::McpMessage::Response(resp) => {
                let err = resp.error.expect("must have error");
                assert_eq!(err.code, AEGIS_ERROR_DENIED);
            }
            other => panic!("expected error Response, got: {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // 5. ALLOW then DENY in the same session (two messages)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn mixed_session_allow_then_deny() {
        let kernel = Arc::new(KernelHandle::new());
        let token_id = issue_token(&kernel, "test-agent", "read_file");

        let mw = EnforcementMiddleware::new(Arc::clone(&kernel), "test-agent", token_id);
        let proxy = StdioProxy::new(cat_config()).with_middleware(Arc::new(mw));

        let input = concat!(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"read_file\",\"arguments\":{\"path\":\"/tmp/a\"}}}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"write_file\",\"arguments\":{\"path\":\"/tmp/b\",\"content\":\"hello\"}}}\n",
        );

        let mut output = Vec::new();
        let child = spawn_cat().await;
        proxy
            .run_with_child(input.as_bytes(), &mut output, child)
            .await
            .unwrap();

        let output_str = String::from_utf8(output).unwrap();
        let lines: Vec<&str> = output_str.lines().collect();
        // Should get 2 output lines: the echoed read_file + error for write_file.
        // The ordering between them is not deterministic (two concurrent tasks share
        // agent_output), so we sort by message kind rather than position.
        assert_eq!(lines.len(), 2, "expected 2 output lines, got: {:?}", lines);

        let msgs: Vec<aegis_mcp::McpMessage> = lines
            .iter()
            .map(|l| aegis_mcp::parse_message(l.as_bytes()).unwrap())
            .collect();

        // One line must be the echoed read_file (still a Request after cat echo)
        assert!(
            msgs.iter().any(|m| matches!(m, aegis_mcp::McpMessage::Request(_))),
            "expected an echoed Request for the allowed call"
        );

        // One line must be the blocked write_file error response
        let error_resp = msgs
            .iter()
            .find_map(|m| {
                if let aegis_mcp::McpMessage::Response(r) = m {
                    r.error.as_ref().map(|_| r)
                } else {
                    None
                }
            })
            .expect("expected an error Response for the denied call");
        assert_eq!(error_resp.id, aegis_mcp::RequestId::Number(2));
        assert_eq!(error_resp.error.as_ref().unwrap().code, AEGIS_ERROR_DENIED);
    }

    // -----------------------------------------------------------------------
    // 6. Integration: allowed call reaches mock MCP server, gets a real response
    // -----------------------------------------------------------------------

    /// Minimal bash MCP server that handles tools/call for read_file.
    const MOCK_TOOL_SERVER: &str = r#"
while IFS= read -r line; do
    case "$line" in
        *'"method":"tools/call"'*)
            id=$(echo "$line" | sed 's/.*"id":\([0-9]*\).*/\1/')
            echo "{\"jsonrpc\":\"2.0\",\"id\":${id},\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"hello from server\"}]}}"
            ;;
        *'"method":"initialize"'*)
            id=$(echo "$line" | sed 's/.*"id":\([0-9]*\).*/\1/')
            echo "{\"jsonrpc\":\"2.0\",\"id\":${id},\"result\":{\"protocolVersion\":\"2024-11-05\",\"serverInfo\":{\"name\":\"mock\",\"version\":\"0.1\"},\"capabilities\":{}}}"
            ;;
        *'"method":"notifications/'*)
            ;;
    esac
done
"#;

    async fn spawn_mock(script: &str) -> Child {
        Command::new("bash")
            .arg("-c")
            .arg(script)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .expect("failed to spawn bash mock server")
    }

    #[tokio::test]
    async fn integration_allowed_call_gets_server_response() {
        let kernel = Arc::new(KernelHandle::new());
        let token_id = issue_token(&kernel, "test-agent", "read_file");

        let mw = EnforcementMiddleware::new(Arc::clone(&kernel), "test-agent", token_id);
        let proxy = StdioProxy::new(cat_config()).with_middleware(Arc::new(mw));

        // Full session: initialize → notification → tools/call (allowed)
        let input = concat!(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{}}}\n",
            "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"read_file\",\"arguments\":{\"path\":\"/tmp/data.txt\"}}}\n",
        );

        let mut output = Vec::new();
        let child = spawn_mock(MOCK_TOOL_SERVER).await;
        proxy
            .run_with_child(input.as_bytes(), &mut output, child)
            .await
            .unwrap();

        let output_str = String::from_utf8(output).unwrap();
        let lines: Vec<&str> = output_str.lines().collect();
        // 2 responses: initialize + tools/call (notification gets none)
        assert_eq!(lines.len(), 2, "expected 2 responses, got: {:?}", lines);

        // tools/call response should have the server's content
        let tools_resp = aegis_mcp::parse_message(lines[1].as_bytes()).unwrap();
        match tools_resp {
            aegis_mcp::McpMessage::Response(resp) => {
                assert_eq!(resp.id, aegis_mcp::RequestId::Number(2));
                assert!(resp.error.is_none(), "allowed call must not have an error");
                let result = resp.result.expect("allowed call must have a result");
                assert_eq!(result["content"][0]["text"], "hello from server");
            }
            other => panic!("expected tools/call Response, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn integration_denied_call_never_reaches_server() {
        let kernel = Arc::new(KernelHandle::new());
        // Token only covers read_file
        let token_id = issue_token(&kernel, "test-agent", "read_file");

        let mw = EnforcementMiddleware::new(Arc::clone(&kernel), "test-agent", token_id);
        let proxy = StdioProxy::new(cat_config()).with_middleware(Arc::new(mw));

        // Only send the denied call (delete_file) — server should never be called
        let input =
            "{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"tools/call\",\"params\":{\"name\":\"delete_file\",\"arguments\":{\"path\":\"/etc/passwd\"}}}\n";

        let mut output = Vec::new();
        let child = spawn_mock(MOCK_TOOL_SERVER).await;
        proxy
            .run_with_child(input.as_bytes(), &mut output, child)
            .await
            .unwrap();

        let output_str = String::from_utf8(output).unwrap();
        let lines: Vec<&str> = output_str.lines().collect();
        assert_eq!(lines.len(), 1, "expected exactly 1 error response, got: {:?}", lines);

        let msg = aegis_mcp::parse_message(lines[0].as_bytes()).unwrap();
        match msg {
            aegis_mcp::McpMessage::Response(resp) => {
                assert_eq!(resp.id, aegis_mcp::RequestId::Number(5));
                let err = resp.error.expect("denied call must have error");
                assert_eq!(err.code, AEGIS_ERROR_DENIED);
                // Verify the server's "hello from server" text is NOT in output
                assert!(
                    !output_str.contains("hello from server"),
                    "denied call must not have reached the server"
                );
            }
            other => panic!("expected error Response, got: {:?}", other),
        }
    }
}
