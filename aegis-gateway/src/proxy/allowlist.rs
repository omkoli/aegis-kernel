//! Allowlist middleware: enforces domain allowlisting for MCP servers.
//!
//! Only MCP servers explicitly listed in `aegis.toml` can be reached, and
//! only tools present in their `allowed_tools` list are forwarded to the
//! upstream server. All other requests are blocked and logged.
//!
//! ## Allowlist semantics
//!
//! | `allowed_tools` value | Behavior                    |
//! |-----------------------|-----------------------------|
//! | `[]` (empty/absent)   | All tools pass (no filter)  |
//! | `["*"]`               | All tools pass (wildcard)   |
//! | `["a", "b"]`          | Only `a` and `b` pass       |
//!
//! ## Usage
//!
//! ```rust,ignore
//! use std::sync::Arc;
//! use aegis_gateway::proxy::{StdioProxy, StdioProxyConfig, AllowlistMiddleware};
//! use aegis_gateway::config::ServerConfig;
//!
//! // config loaded from aegis.toml
//! let server_config: ServerConfig = /* ... */;
//!
//! let middleware = AllowlistMiddleware::new("github", "my-agent", server_config);
//! let proxy = StdioProxy::new(config).with_middleware(Arc::new(middleware));
//! ```

use aegis_mcp::translate::{translate_to_intent, AgentContext, IntentKind};
use aegis_mcp::{JsonRpcError, McpMessage};

use crate::config::ServerConfig;

use super::middleware::{InterceptionMiddleware, InterceptionResult};

// ---------------------------------------------------------------------------
// Error code
// ---------------------------------------------------------------------------

/// JSON-RPC server error code for allowlist violations.
///
/// Sits in the Aegis reserved range (-32000 to -32099).
pub const AEGIS_ERROR_NOT_ALLOWED: i64 = -32008;

// ---------------------------------------------------------------------------
// Log reason strings (also surfaced in the JSON-RPC error data)
// ---------------------------------------------------------------------------

const REASON_SERVER_NOT_CONFIGURED: &str = "server not configured";
const REASON_TOOL_NOT_IN_ALLOWLIST: &str = "tool not in allowlist";

// ---------------------------------------------------------------------------
// AllowlistMiddleware
// ---------------------------------------------------------------------------

/// Middleware that enforces the per-server domain allowlist from `aegis.toml`.
///
/// Instantiate one per server per session. The `server_name` and `agent_id`
/// are carried in every blocked-request log entry.
///
/// For **unconfigured** servers (not present in `aegis.toml`), use
/// [`AllowlistMiddleware::server_not_configured`] — every `tools/call` will
/// be blocked with reason `"server not configured"`.
pub struct AllowlistMiddleware {
    server_name: String,
    agent_id: String,
    /// `None` when the server is not present in the config — all requests blocked.
    config: Option<ServerConfig>,
}

impl AllowlistMiddleware {
    /// Create middleware for a **configured** server.
    ///
    /// - `server_name` — key from the `[servers]` table in `aegis.toml`.
    /// - `agent_id`    — identity of the agent for structured log output.
    /// - `config`      — the parsed `ServerConfig` for this server.
    pub fn new(
        server_name: impl Into<String>,
        agent_id: impl Into<String>,
        config: ServerConfig,
    ) -> Self {
        Self {
            server_name: server_name.into(),
            agent_id: agent_id.into(),
            config: Some(config),
        }
    }

    /// Create middleware for an **unconfigured** server.
    ///
    /// Every `tools/call` will be blocked and logged with reason
    /// `"server not configured"`.
    pub fn server_not_configured(
        server_name: impl Into<String>,
        agent_id: impl Into<String>,
    ) -> Self {
        Self {
            server_name: server_name.into(),
            agent_id: agent_id.into(),
            config: None,
        }
    }

    /// Verify that the command used to spawn a stdio server matches the
    /// `command` field in `aegis.toml`.
    ///
    /// For stdio servers this provides a defence-in-depth check that the
    /// process being proxied is actually the one that was configured. Non-
    /// stdio servers always return `Ok`.
    ///
    /// # Errors
    ///
    /// Returns an `Err` string when:
    /// - The server has no config (not in `aegis.toml`).
    /// - The server is a stdio server and `actual_command != config.command`.
    pub fn verify_stdio_command(&self, actual_command: &str) -> Result<(), String> {
        let config = match &self.config {
            Some(c) => c,
            None => {
                return Err(format!(
                    "server '{}' is not in the allowlist (no config)",
                    self.server_name
                ))
            }
        };
        if config.transport != "stdio" {
            return Ok(());
        }
        match &config.command {
            Some(expected) if expected != actual_command => Err(format!(
                "server '{}': spawned command '{}' does not match configured command '{}'",
                self.server_name, actual_command, expected
            )),
            _ => Ok(()),
        }
    }

    /// Verify that the upstream URL of an SSE server matches the `url` field
    /// in `aegis.toml`, preventing URL-manipulation attacks.
    ///
    /// If an agent attempts to redirect traffic to a different URL via
    /// manipulated parameters, this check will reject the connection before
    /// any messages are exchanged. Non-SSE servers always return `Ok`.
    ///
    /// # Errors
    ///
    /// Returns an `Err` string when:
    /// - The server has no config (not in `aegis.toml`).
    /// - The server is an SSE server and `actual_url != config.url`.
    pub fn verify_sse_url(&self, actual_url: &str) -> Result<(), String> {
        let config = match &self.config {
            Some(c) => c,
            None => {
                return Err(format!(
                    "server '{}' is not in the allowlist (no config)",
                    self.server_name
                ))
            }
        };
        if config.transport != "sse" {
            return Ok(());
        }
        match &config.url {
            Some(expected) if expected != actual_url => Err(format!(
                "server '{}': upstream URL '{}' does not match configured URL '{}'",
                self.server_name, actual_url, expected
            )),
            _ => Ok(()),
        }
    }

    /// Returns `true` if `tool_name` is permitted by the server's allowlist.
    fn is_tool_allowed(&self, tool_name: &str) -> bool {
        let config = match &self.config {
            Some(c) => c,
            None => return false,
        };
        // Empty list → no filtering; all tools pass
        if config.allowed_tools.is_empty() {
            return true;
        }
        // ["*"] → wildcard; all tools pass
        if config.allowed_tools.iter().any(|t| t == "*") {
            return true;
        }
        // Explicit list → exact name match required
        config.allowed_tools.iter().any(|t| t == tool_name)
    }

    /// Emit a structured warning log and return a `Block` result.
    ///
    /// Logged fields: `agent_id`, `server_name`, `tool_name`, `reason`.
    /// The logging subscriber (configured by the embedding application) adds
    /// the timestamp automatically.
    fn block_with_reason(&self, tool_name: &str, reason: &'static str) -> InterceptionResult {
        tracing::warn!(
            agent_id = %self.agent_id,
            server_name = %self.server_name,
            tool_name = %tool_name,
            reason = reason,
            "allowlist: blocked request"
        );
        InterceptionResult::Block(JsonRpcError {
            code: AEGIS_ERROR_NOT_ALLOWED,
            message: format!(
                "aegis allowlist blocked: {} (server='{}', tool='{}')",
                reason, self.server_name, tool_name
            ),
            data: Some(serde_json::json!({
                "aegis": true,
                "decision": "block",
                "reason": reason,
                "server": self.server_name,
                "tool": tool_name,
                "agent": self.agent_id,
            })),
        })
    }
}

// ---------------------------------------------------------------------------
// InterceptionMiddleware impl
// ---------------------------------------------------------------------------

impl InterceptionMiddleware for AllowlistMiddleware {
    /// Gate agent→server requests.
    ///
    /// For `tools/call` requests:
    /// 1. If the server is not in `aegis.toml` → block (`"server not configured"`).
    /// 2. If the tool is not in `allowed_tools` → block (`"tool not in allowlist"`).
    ///
    /// All other message kinds (initialize, tools/list, notifications, …)
    /// are forwarded without inspection.
    fn on_request(&self, message: McpMessage) -> InterceptionResult {
        // Extract tool name from `tools/call` only; everything else passes through.
        let tool_name = if let McpMessage::Request(ref req) = message {
            let ctx = AgentContext {
                agent_id: self.agent_id.clone(),
                token_id: String::new(), // token not needed for allowlist checks
            };
            match translate_to_intent(req, &ctx) {
                Some(IntentKind::ToolCall(tc)) => tc.tool_name,
                _ => return InterceptionResult::Forward(message),
            }
        } else {
            return InterceptionResult::Forward(message);
        };

        // 1. Server-level check
        if self.config.is_none() {
            return self.block_with_reason(&tool_name, REASON_SERVER_NOT_CONFIGURED);
        }

        // 2. Tool-level check
        if !self.is_tool_allowed(&tool_name) {
            return self.block_with_reason(&tool_name, REASON_TOOL_NOT_IN_ALLOWLIST);
        }

        InterceptionResult::Forward(message)
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
    use std::collections::HashMap;

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn make_tool_call(tool: &str) -> McpMessage {
        McpMessage::Request(McpRequest {
            jsonrpc: "2.0".into(),
            id: RequestId::Number(1),
            method: "tools/call".into(),
            params: Some(serde_json::json!({ "name": tool, "arguments": {} })),
        })
    }

    fn stdio_config(allowed_tools: Vec<&str>) -> ServerConfig {
        ServerConfig {
            command: Some("npx some-server".into()),
            url: None,
            transport: "stdio".into(),
            env: HashMap::new(),
            allowed_tools: allowed_tools.into_iter().map(String::from).collect(),
            rate_limit: None,
            tool_rate_limits: HashMap::new(),
        }
    }

    fn sse_config(url: &str, allowed_tools: Vec<&str>) -> ServerConfig {
        ServerConfig {
            command: None,
            url: Some(url.into()),
            transport: "sse".into(),
            env: HashMap::new(),
            allowed_tools: allowed_tools.into_iter().map(String::from).collect(),
            rate_limit: None,
            tool_rate_limits: HashMap::new(),
        }
    }

    // -----------------------------------------------------------------------
    // 1. Server not configured → all tool calls blocked
    // -----------------------------------------------------------------------

    #[test]
    fn server_not_configured_blocks_all() {
        let mw = AllowlistMiddleware::server_not_configured("ghost", "agent-1");
        let result = mw.on_request(make_tool_call("read_file"));
        match result {
            InterceptionResult::Block(err) => {
                assert_eq!(err.code, AEGIS_ERROR_NOT_ALLOWED);
                let data = err.data.unwrap();
                assert_eq!(data["reason"], REASON_SERVER_NOT_CONFIGURED);
                assert_eq!(data["server"], "ghost");
                assert_eq!(data["agent"], "agent-1");
            }
            other => panic!("expected Block, got {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // 2. Wildcard allowed_tools passes every tool
    // -----------------------------------------------------------------------

    #[test]
    fn wildcard_allows_all_tools() {
        let mw = AllowlistMiddleware::new("s1", "agent-1", stdio_config(vec!["*"]));
        let result = mw.on_request(make_tool_call("any_tool_whatsoever"));
        assert!(matches!(result, InterceptionResult::Forward(_)));
    }

    // -----------------------------------------------------------------------
    // 3. Empty allowed_tools passes every tool (no filter)
    // -----------------------------------------------------------------------

    #[test]
    fn empty_allowlist_passes_all_tools() {
        let mw = AllowlistMiddleware::new("s1", "agent-1", stdio_config(vec![]));
        let result = mw.on_request(make_tool_call("read_file"));
        assert!(matches!(result, InterceptionResult::Forward(_)));
    }

    // -----------------------------------------------------------------------
    // 4. Explicit list: listed tools pass
    // -----------------------------------------------------------------------

    #[test]
    fn explicit_list_allows_listed_tools() {
        let mw = AllowlistMiddleware::new(
            "s1",
            "agent-1",
            stdio_config(vec!["read_file", "list_files"]),
        );
        assert!(matches!(
            mw.on_request(make_tool_call("read_file")),
            InterceptionResult::Forward(_)
        ));
        assert!(matches!(
            mw.on_request(make_tool_call("list_files")),
            InterceptionResult::Forward(_)
        ));
    }

    // -----------------------------------------------------------------------
    // 5. Explicit list: unlisted tool is blocked
    // -----------------------------------------------------------------------

    #[test]
    fn explicit_list_blocks_unlisted_tool() {
        let mw =
            AllowlistMiddleware::new("s1", "agent-1", stdio_config(vec!["read_file"]));
        let result = mw.on_request(make_tool_call("delete_file"));
        match result {
            InterceptionResult::Block(err) => {
                assert_eq!(err.code, AEGIS_ERROR_NOT_ALLOWED);
                let data = err.data.unwrap();
                assert_eq!(data["reason"], REASON_TOOL_NOT_IN_ALLOWLIST);
                assert_eq!(data["tool"], "delete_file");
                assert_eq!(data["server"], "s1");
                assert_eq!(data["agent"], "agent-1");
            }
            other => panic!("expected Block, got {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // 6. Non-tool-call messages pass through regardless of allowlist
    // -----------------------------------------------------------------------

    #[test]
    fn non_tool_call_passes_through() {
        let mw = AllowlistMiddleware::new("s1", "agent-1", stdio_config(vec!["read_file"]));

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
        assert!(matches!(
            mw.on_request(notif),
            InterceptionResult::Forward(_)
        ));

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
    // 7. Responses always pass through
    // -----------------------------------------------------------------------

    #[test]
    fn responses_pass_through() {
        let mw = AllowlistMiddleware::server_not_configured("ghost", "agent");
        let resp = McpMessage::Response(McpResponse {
            jsonrpc: "2.0".into(),
            id: RequestId::Number(1),
            result: Some(serde_json::json!({})),
            error: None,
        });
        assert!(matches!(mw.on_response(resp), InterceptionResult::Forward(_)));
    }

    // -----------------------------------------------------------------------
    // 8. verify_stdio_command: matching command passes
    // -----------------------------------------------------------------------

    #[test]
    fn verify_stdio_command_ok() {
        let mw = AllowlistMiddleware::new("s1", "agent", stdio_config(vec!["*"]));
        // config has command = "npx some-server"
        assert!(mw.verify_stdio_command("npx some-server").is_ok());
    }

    // -----------------------------------------------------------------------
    // 9. verify_stdio_command: mismatched command returns error
    // -----------------------------------------------------------------------

    #[test]
    fn verify_stdio_command_mismatch() {
        let mw = AllowlistMiddleware::new("s1", "agent", stdio_config(vec!["*"]));
        let err = mw.verify_stdio_command("malicious-binary").unwrap_err();
        assert!(
            err.contains("does not match"),
            "expected 'does not match' in: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // 10. verify_sse_url: matching URL passes
    // -----------------------------------------------------------------------

    #[test]
    fn verify_sse_url_ok() {
        let mw = AllowlistMiddleware::new(
            "slack",
            "agent",
            sse_config("https://mcp.slack.example.com/sse", vec!["*"]),
        );
        assert!(mw
            .verify_sse_url("https://mcp.slack.example.com/sse")
            .is_ok());
    }

    // -----------------------------------------------------------------------
    // 11. verify_sse_url: different URL returns error
    // -----------------------------------------------------------------------

    #[test]
    fn verify_sse_url_mismatch() {
        let mw = AllowlistMiddleware::new(
            "slack",
            "agent",
            sse_config("https://mcp.slack.example.com/sse", vec!["*"]),
        );
        let err = mw
            .verify_sse_url("https://evil.example.com/sse")
            .unwrap_err();
        assert!(
            err.contains("does not match"),
            "expected 'does not match' in: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // 12. verify_sse_url is a no-op for stdio servers
    // -----------------------------------------------------------------------

    #[test]
    fn verify_sse_url_ignored_for_stdio() {
        let mw = AllowlistMiddleware::new("s1", "agent", stdio_config(vec!["*"]));
        assert!(mw.verify_sse_url("https://anything.com").is_ok());
    }

    // -----------------------------------------------------------------------
    // 13. verify_stdio_command is a no-op for SSE servers
    // -----------------------------------------------------------------------

    #[test]
    fn verify_stdio_command_ignored_for_sse() {
        let mw = AllowlistMiddleware::new(
            "slack",
            "agent",
            sse_config("https://mcp.slack.example.com/sse", vec!["*"]),
        );
        assert!(mw.verify_stdio_command("anything").is_ok());
    }

    // -----------------------------------------------------------------------
    // 14. verify_* on unconfigured server returns error
    // -----------------------------------------------------------------------

    #[test]
    fn verify_on_unconfigured_server_errors() {
        let mw = AllowlistMiddleware::server_not_configured("ghost", "agent");
        assert!(mw.verify_stdio_command("any").is_err());
        assert!(mw.verify_sse_url("https://any.com").is_err());
    }

    // -----------------------------------------------------------------------
    // 15. Blocked error response carries expected structured data fields
    // -----------------------------------------------------------------------

    #[test]
    fn block_error_has_expected_fields() {
        let mw = AllowlistMiddleware::new(
            "github",
            "my-agent",
            stdio_config(vec!["search_repos"]),
        );
        let result = mw.on_request(make_tool_call("delete_everything"));
        match result {
            InterceptionResult::Block(err) => {
                assert_eq!(err.code, AEGIS_ERROR_NOT_ALLOWED);
                assert!(
                    err.message.contains("delete_everything"),
                    "message should name the tool"
                );
                let data = err.data.unwrap();
                assert_eq!(data["aegis"], true);
                assert_eq!(data["decision"], "block");
                assert_eq!(data["server"], "github");
                assert_eq!(data["agent"], "my-agent");
                assert_eq!(data["tool"], "delete_everything");
            }
            other => panic!("expected Block, got {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // 16. Integration: allowlist + stdio proxy (blocked call returns -32008)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn integration_blocked_tool_returns_not_allowed() {
        use std::process::Stdio;
        use tokio::process::Command;

        use crate::proxy::stdio::{StdioProxy, StdioProxyConfig};

        let mw = AllowlistMiddleware::new(
            "test-server",
            "test-agent",
            stdio_config(vec!["allowed_tool"]),
        );

        let proxy = StdioProxy::new(StdioProxyConfig {
            command: "cat".into(),
            args: vec![],
            env: vec![],
        })
        .with_middleware(std::sync::Arc::new(mw));

        let input = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"forbidden_tool\",\"arguments\":{}}}\n";

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
                let err = resp.error.expect("blocked call must have error");
                assert_eq!(
                    err.code, AEGIS_ERROR_NOT_ALLOWED,
                    "expected -32008, got {}",
                    err.code
                );
                let data = err.data.unwrap();
                assert_eq!(data["reason"], REASON_TOOL_NOT_IN_ALLOWLIST);
            }
            other => panic!("expected error Response, got: {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // 17. Integration: allowlist + stdio proxy (allowed call reaches server)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn integration_allowed_tool_reaches_server() {
        use std::process::Stdio;
        use tokio::process::Command;

        use crate::proxy::stdio::{StdioProxy, StdioProxyConfig};

        let mw = AllowlistMiddleware::new(
            "test-server",
            "test-agent",
            stdio_config(vec!["read_file"]),
        );

        let proxy = StdioProxy::new(StdioProxyConfig {
            command: "cat".into(),
            args: vec![],
            env: vec![],
        })
        .with_middleware(std::sync::Arc::new(mw));

        let input = "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"read_file\",\"arguments\":{\"path\":\"/tmp/x\"}}}\n";

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
        // cat echoes the request back → it arrives as a Request (not an error)
        assert!(
            matches!(msg, McpMessage::Request(_)),
            "allowed tool should be forwarded to server, got: {}",
            output_str.trim()
        );
    }
}
