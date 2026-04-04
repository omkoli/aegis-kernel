//! Integration test harness for the Aegis MCP gateway.
//!
//! Provides [`TestGateway`], [`MockAgent`], and assertion macros for
//! end-to-end tests that spin up a real `StdioProxy` against a real (or
//! built-in mock) MCP server.
//!
//! # Quickstart
//!
//! ```rust,ignore
//! #[tokio::test]
//! async fn test_allowed_echo() {
//!     let mut gw = TestGateway::builder()
//!         .agent_id("my-agent")
//!         .policy_yaml(ECHO_POLICY)
//!         .build()
//!         .await;
//!
//!     let r = assert_tool_call_allowed!(gw, "echo", json!({"message": "hi"}));
//!     assert_eq!(r.text(), Some("hi"));
//!     assert_audit_contains!(gw, tool = "echo", decision = allow);
//!
//!     gw.teardown().await;
//! }
//! ```

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use uuid::Uuid;

use aegis_gateway::{
    config::{RateLimitConfig, ServerConfig},
    IdentityStrategy,
    proxy::{
        AllowlistMiddleware, InterceptionMiddleware, InterceptionResult,
        MiddlewareChain, RateLimiter, RateLimiterMiddleware,
        StdioProxy,
    },
};
use aegis_gateway::proxy::stdio::StdioProxyConfig;
use aegis_handle::{Action, AuditEntry, Decision, KernelHandle, Resource, ToolCallRequest};
use aegis_mcp::{
    translate::{translate_to_intent, AgentContext, IntentKind},
    JsonRpcError, McpMessage,
};

// ── Public error-code constants ───────────────────────────────────────────────

/// JSON-RPC error code returned when enforcement denies a tool call.
pub const AEGIS_DENIED: i64 = -32001;
/// JSON-RPC error code returned when the allowlist blocks a tool call.
pub const AEGIS_NOT_ALLOWED: i64 = -32008;
/// JSON-RPC error code returned when rate limiting rejects a tool call.
pub const AEGIS_RATE_LIMITED: i64 = -32009;

/// Default per-operation timeout applied throughout the harness.
pub const DEFAULT_TEST_TIMEOUT: Duration = Duration::from_secs(30);

// ── HarnessError ──────────────────────────────────────────────────────────────

/// Error type for harness operations.
#[derive(Debug)]
pub enum HarnessError {
    Io(std::io::Error),
    Serialization(String),
    /// An operation exceeded `DEFAULT_TEST_TIMEOUT`.
    Timeout(String),
    McpProtocol(String),
}

impl std::fmt::Display for HarnessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HarnessError::Io(e) => write!(f, "I/O: {e}"),
            HarnessError::Serialization(s) => write!(f, "serialization: {s}"),
            HarnessError::Timeout(op) => write!(
                f, "timed out in `{op}` (>{} s)", DEFAULT_TEST_TIMEOUT.as_secs()
            ),
            HarnessError::McpProtocol(s) => write!(f, "MCP protocol: {s}"),
        }
    }
}

impl From<std::io::Error> for HarnessError {
    fn from(e: std::io::Error) -> Self { HarnessError::Io(e) }
}

// ── McpResult ─────────────────────────────────────────────────────────────────

/// The outcome of one `tools/call` round-trip through the gateway.
#[derive(Debug, Clone)]
pub enum McpResult {
    /// The call was forwarded and the upstream server returned a result.
    Ok { result: Value },
    /// The call was blocked (by Aegis or the upstream) and returned an error.
    Error { code: i64, message: String, data: Option<Value> },
}

impl McpResult {
    pub fn is_ok(&self) -> bool { matches!(self, McpResult::Ok { .. }) }
    pub fn is_error(&self) -> bool { matches!(self, McpResult::Error { .. }) }

    /// Extract the first text content item from a success response.
    pub fn text(&self) -> Option<&str> {
        if let McpResult::Ok { result } = self {
            result["content"].as_array()?.first()?["text"].as_str()
        } else {
            None
        }
    }

    /// The JSON-RPC error code, if this is an error response.
    pub fn error_code(&self) -> Option<i64> {
        match self { McpResult::Error { code, .. } => Some(*code), _ => None }
    }

    /// The structured Aegis `data` block when the error came from a middleware.
    ///
    /// Returns `None` if this is a success or a non-Aegis error.
    pub fn aegis_data(&self) -> Option<&Value> {
        match self {
            McpResult::Error { data, .. } => data.as_ref()
                .filter(|d| d["aegis"].as_bool().unwrap_or(false)),
            McpResult::Ok { .. } => None,
        }
    }

    /// Panic with a clear message if this is an error; return the `result` value.
    #[track_caller]
    pub fn unwrap(self) -> Value {
        match self {
            McpResult::Ok { result } => result,
            McpResult::Error { code, message, .. } =>
                panic!("expected Ok, got Error: code={code} message={message}"),
        }
    }

    /// Panic if this is not an error; return `(code, message)`.
    #[track_caller]
    pub fn unwrap_err(self) -> (i64, String) {
        match self {
            McpResult::Error { code, message, .. } => (code, message),
            McpResult::Ok { result } => panic!("expected Error, got Ok: {result}"),
        }
    }
}

fn parse_mcp_result(resp: Value) -> McpResult {
    if let Some(err) = resp.get("error") {
        McpResult::Error {
            code: err["code"].as_i64().unwrap_or(0),
            message: err["message"].as_str().unwrap_or("unknown").to_string(),
            data: err.get("data").cloned(),
        }
    } else {
        McpResult::Ok { result: resp["result"].clone() }
    }
}

// ── MockAgent ─────────────────────────────────────────────────────────────────

/// A minimal MCP client that communicates with the gateway over an in-process
/// duplex channel.
///
/// `MockAgent` simulates an AI agent sending `tools/call` requests. Use
/// [`MockAgent::call_tool`] to issue a request and receive the raw response,
/// or the macro helpers ([`assert_tool_call_allowed!`],
/// [`assert_tool_call_denied!`]) for assertion-first testing.
pub struct MockAgent {
    reader: Lines<BufReader<tokio::io::ReadHalf<tokio::io::DuplexStream>>>,
    writer: tokio::io::WriteHalf<tokio::io::DuplexStream>,
    next_id: u64,
    /// Tools advertised by the upstream server, populated during handshake.
    pub tools: Vec<Value>,
    timeout: Duration,
}

impl MockAgent {
    fn new(stream: tokio::io::DuplexStream, timeout: Duration) -> Self {
        let (r, w) = tokio::io::split(stream);
        Self {
            reader: BufReader::new(r).lines(),
            writer: w,
            next_id: 1,
            tools: vec![],
            timeout,
        }
    }

    fn alloc_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    /// Write one JSON-RPC message to the gateway.
    pub async fn send(&mut self, msg: Value) -> Result<(), HarnessError> {
        let line = serde_json::to_string(&msg)
            .map_err(|e| HarnessError::Serialization(e.to_string()))?;
        timeout(self.timeout, async {
            self.writer.write_all(line.as_bytes()).await?;
            self.writer.write_all(b"\n").await?;
            self.writer.flush().await
        })
        .await
        .map_err(|_| HarnessError::Timeout("send".into()))?
        .map_err(HarnessError::Io)
    }

    /// Read the next JSON-RPC line from the gateway.
    pub async fn recv(&mut self) -> Result<Value, HarnessError> {
        let line = timeout(self.timeout, self.reader.next_line())
            .await
            .map_err(|_| HarnessError::Timeout("recv".into()))?
            .map_err(HarnessError::Io)?
            .ok_or_else(|| {
                HarnessError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "gateway closed the connection",
                ))
            })?;
        serde_json::from_str(&line)
            .map_err(|e| HarnessError::Serialization(format!("bad JSON: {e} — raw: {line}")))
    }

    /// Run the MCP initialize / initialized / tools/list handshake.
    ///
    /// Must be called before any `call_tool` invocations.  Called automatically
    /// by [`TestGatewayBuilder::build`].
    pub async fn handshake(&mut self) -> Result<(), HarnessError> {
        // 1. initialize
        let id = self.alloc_id();
        self.send(json!({
            "jsonrpc": "2.0", "id": id, "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "aegis-test-harness", "version": "0.1.0"}
            }
        })).await?;

        let resp = self.recv().await?;
        if resp.get("error").is_some() {
            return Err(HarnessError::McpProtocol(
                format!("initialize failed: {}", resp["error"])
            ));
        }

        // 2. notifications/initialized (no response expected)
        self.send(json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        })).await?;

        // 3. tools/list
        let id = self.alloc_id();
        self.send(json!({
            "jsonrpc": "2.0", "id": id, "method": "tools/list", "params": {}
        })).await?;

        let resp = self.recv().await?;
        if let Some(err) = resp.get("error") {
            return Err(HarnessError::McpProtocol(format!("tools/list failed: {err}")));
        }
        self.tools = resp["result"]["tools"]
            .as_array()
            .cloned()
            .unwrap_or_default();

        Ok(())
    }

    /// Send a `tools/call` request and return the structured response.
    ///
    /// This is the primary method for exercising the gateway under test.
    /// Every call goes through the full middleware chain (allowlist →
    /// rate-limiter → enforcement) before reaching the upstream server.
    pub async fn call_tool(
        &mut self,
        tool_name: &str,
        arguments: Value,
    ) -> Result<McpResult, HarnessError> {
        let id = self.alloc_id();
        self.send(json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments}
        })).await?;
        let resp = self.recv().await?;
        Ok(parse_mcp_result(resp))
    }

    /// Names of tools advertised by the upstream server.
    pub fn tool_names(&self) -> Vec<String> {
        self.tools.iter()
            .filter_map(|t| t["name"].as_str().map(String::from))
            .collect()
    }
}

// ── PolicyEnforcementMiddleware ───────────────────────────────────────────────

/// Test-only middleware that enforces policy for **multiple tools** in a single
/// session.
///
/// Production `EnforcementMiddleware` is 1-token / 1-tool; this variant holds
/// a full `tool_name → token_id` map built from the kernel's issued tokens and
/// dispatches each `tools/call` to the matching token.
///
/// If no token covers the requested tool the call is denied with
/// `AEGIS_DENIED` and reason `"no capability token for tool '<name>'"`.
struct PolicyEnforcementMiddleware {
    kernel: Arc<KernelHandle>,
    agent_id: String,
    server_name: String,
    /// tool_name → token UUID
    tool_tokens: HashMap<String, Uuid>,
}

impl PolicyEnforcementMiddleware {
    fn new(
        kernel: Arc<KernelHandle>,
        agent_id: impl Into<String>,
        server_name: impl Into<String>,
        tool_tokens: HashMap<String, Uuid>,
    ) -> Self {
        Self {
            kernel,
            agent_id: agent_id.into(),
            server_name: server_name.into(),
            tool_tokens,
        }
    }
}

impl InterceptionMiddleware for PolicyEnforcementMiddleware {
    fn on_request(&self, message: McpMessage) -> InterceptionResult {
        // Only intercept tools/call; everything else passes through.
        let intent = match &message {
            McpMessage::Request(req) => {
                let ctx = AgentContext {
                    agent_id: self.agent_id.clone(),
                    token_id: String::new(),
                };
                match translate_to_intent(req, &ctx) {
                    Some(IntentKind::ToolCall(tc)) => tc,
                    _ => return InterceptionResult::Forward(message),
                }
            }
            _ => return InterceptionResult::Forward(message),
        };

        let token_id = match self.tool_tokens.get(&intent.tool_name) {
            Some(&id) => id,
            None => {
                let reason = format!("no capability token for tool '{}'", intent.tool_name);
                tracing::warn!(
                    tool   = %intent.tool_name,
                    agent  = %self.agent_id,
                    server = %self.server_name,
                    %reason,
                    "enforcement decision: deny (no token)"
                );
                return InterceptionResult::Block(JsonRpcError {
                    code: AEGIS_DENIED,
                    message: reason.clone(),
                    data: Some(json!({
                        "aegis":    true,
                        "decision": "deny",
                        "reason":   reason,
                        "tool":     intent.tool_name,
                        "agent":    self.agent_id,
                        "server":   self.server_name,
                    })),
                });
            }
        };

        let resource = match Resource::new(&format!("tool://{}", intent.tool_name)) {
            Ok(r) => r,
            Err(_) => return InterceptionResult::Forward(message),
        };

        let tcr = ToolCallRequest {
            agent_id: self.agent_id.clone(),
            tool_name: intent.tool_name.clone(),
            action: Action::Execute,
            resource,
            parameters: intent.parameters,
            token_id,
        };

        let result = self.kernel.evaluate(&tcr);

        match result.decision {
            Decision::Allow => {
                tracing::info!(
                    tool     = %intent.tool_name,
                    agent    = %self.agent_id,
                    server   = %self.server_name,
                    audit_id = %result.audit.request_id,
                    latency_us = result.audit.latency_us,
                    "enforcement decision: allow"
                );
                InterceptionResult::Forward(message)
            }
            Decision::Deny => {
                tracing::warn!(
                    tool     = %intent.tool_name,
                    agent    = %self.agent_id,
                    server   = %self.server_name,
                    reason   = %result.audit.reason,
                    audit_id = %result.audit.request_id,
                    "enforcement decision: deny"
                );
                InterceptionResult::Block(JsonRpcError {
                    code: AEGIS_DENIED,
                    message: result.audit.reason.clone(),
                    data: Some(json!({
                        "aegis":    true,
                        "decision": "deny",
                        "reason":   result.audit.reason,
                        "tool":     intent.tool_name,
                        "agent":    self.agent_id,
                        "server":   self.server_name,
                        "audit_id": result.audit.request_id.to_string(),
                        "latency_us": result.audit.latency_us,
                    })),
                })
            }
        }
    }

    fn on_response(&self, message: McpMessage) -> InterceptionResult {
        InterceptionResult::Forward(message)
    }
}

/// Build a `tool_name → token_id` map by scanning tokens issued for `agent_id`.
///
/// Tokens with resources matching `tool://<name>` are mapped to their UUID.
fn build_tool_token_map(kernel: &KernelHandle, agent_id: &str) -> HashMap<String, Uuid> {
    kernel
        .list_tokens()
        .into_iter()
        .filter(|s| s.token.subject() == agent_id)
        .filter_map(|s| {
            s.token
                .resource()
                .path()
                .strip_prefix("tool://")
                .map(|name| (name.to_string(), s.token.id()))
        })
        .collect()
}

// ── TestServer ────────────────────────────────────────────────────────────────

/// Defines the upstream MCP server used by a test.
pub enum TestServer {
    /// Built-in Python3 mock — no npm/external deps required.
    BuiltinMock(MockServerConfig),
    /// Any real MCP server launched as a child process.
    External {
        command: String,
        args: Vec<String>,
        env: Vec<(String, String)>,
    },
}

impl TestServer {
    /// Convenience constructor: `npx @modelcontextprotocol/server-filesystem <path>`.
    pub fn filesystem(root_path: impl Into<String>) -> Self {
        TestServer::External {
            command: "npx".into(),
            args: vec![
                "--yes".into(),
                "@modelcontextprotocol/server-filesystem".into(),
                root_path.into(),
            ],
            env: vec![],
        }
    }

    fn into_proxy_config(self) -> StdioProxyConfig {
        match self {
            TestServer::BuiltinMock(cfg) => builtin_mock_proxy_config(cfg),
            TestServer::External { command, args, env } => {
                StdioProxyConfig { command, args, env }
            }
        }
    }
}

impl Default for TestServer {
    fn default() -> Self {
        TestServer::BuiltinMock(MockServerConfig::default())
    }
}

/// Configuration for the built-in mock MCP server.
#[derive(Clone, Default)]
pub struct MockServerConfig {
    /// Override the text returned for every `tools/call` response.
    /// Default: the mock returns the tool's natural echo/compute result.
    pub call_response_override: Option<String>,
}

/// Produce a `StdioProxyConfig` for the built-in Python3 mock server.
///
/// The mock server handles:
/// - `initialize`      → server info
/// - `tools/list`      → echo, add, get_info tools
/// - `tools/call`      → natural results (echo echoes, add adds) or override
/// - notifications     → silently ignored
/// - unknown requests  → `-32601` Method not found
fn builtin_mock_proxy_config(cfg: MockServerConfig) -> StdioProxyConfig {
    // Build the override expression for the Python script.
    let override_expr = match cfg.call_response_override {
        Some(ref s) => {
            // Escape backslashes and single-quotes for embedding in a Python string.
            let escaped = s.replace('\\', r"\\").replace('\'', r"\'");
            format!("'{}'", escaped)
        }
        None => "None".into(),
    };

    let script = format!(
        r#"import sys, json
OVERRIDE = {override}
TOOLS = [
    {{"name":"echo","description":"Echoes the message argument back.","inputSchema":{{"type":"object","properties":{{"message":{{"type":"string"}}}},"required":["message"]}}}},
    {{"name":"add","description":"Adds two numbers.","inputSchema":{{"type":"object","properties":{{"a":{{"type":"number"}},"b":{{"type":"number"}}}},"required":["a","b"]}}}},
    {{"name":"get_info","description":"Returns mock server info.","inputSchema":{{"type":"object","properties":{{}}}}}}
]
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        msg = json.loads(line)
    except Exception:
        continue
    method = msg.get("method","")
    id_ = msg.get("id")
    if method == "initialize":
        r = {{"jsonrpc":"2.0","id":id_,"result":{{"protocolVersion":"2024-11-05","capabilities":{{}},"serverInfo":{{"name":"mock-mcp","version":"0.1.0"}}}}}}
    elif method == "tools/list":
        r = {{"jsonrpc":"2.0","id":id_,"result":{{"tools":TOOLS}}}}
    elif method == "tools/call":
        params = msg.get("params",{{}})
        name = params.get("name","")
        args = params.get("arguments",{{}})
        if OVERRIDE is not None:
            text = OVERRIDE
        elif name == "echo":
            text = str(args.get("message",""))
        elif name == "add":
            text = str(args.get("a",0) + args.get("b",0))
        elif name == "get_info":
            text = "mock-mcp v0.1.0"
        else:
            text = "called " + name
        r = {{"jsonrpc":"2.0","id":id_,"result":{{"content":[{{"type":"text","text":text}}],"isError":False}}}}
    elif id_ is not None:
        r = {{"jsonrpc":"2.0","id":id_,"error":{{"code":-32601,"message":"Method not found"}}}}
    else:
        continue
    print(json.dumps(r), flush=True)
"#,
        override = override_expr,
    );

    StdioProxyConfig {
        command: "python3".into(),
        args: vec!["-c".into(), script],
        env: vec![],
    }
}

// ── TestGatewayBuilder ────────────────────────────────────────────────────────

/// Builder for [`TestGateway`].
///
/// Construct with [`TestGateway::builder()`] and call `.build().await` to
/// start the gateway.  The resulting [`TestGateway`] has already completed
/// the MCP handshake, so `agent.call_tool(...)` is ready to use immediately.
pub struct TestGatewayBuilder {
    upstream: TestServer,
    agent_id: String,
    server_name: String,
    policy_yaml: Option<String>,
    allowed_tools: Vec<String>,
    rate_limit: Option<RateLimitConfig>,
    timeout: Duration,
}

impl Default for TestGatewayBuilder {
    fn default() -> Self { Self::new() }
}

impl TestGatewayBuilder {
    pub fn new() -> Self {
        Self {
            upstream: TestServer::default(),
            agent_id: "test-agent".into(),
            server_name: "test-server".into(),
            policy_yaml: None,
            allowed_tools: vec![],
            rate_limit: None,
            timeout: DEFAULT_TEST_TIMEOUT,
        }
    }

    /// Set the upstream MCP server (default: [`TestServer::BuiltinMock`]).
    pub fn upstream(mut self, server: TestServer) -> Self {
        self.upstream = server;
        self
    }

    /// Set the agent identity string.
    ///
    /// Must match the `agent:` field in the policy YAML (if any).
    pub fn agent_id(mut self, id: impl Into<String>) -> Self {
        self.agent_id = id.into();
        self
    }

    /// Set the server name used in metric labels.
    pub fn server_name(mut self, name: impl Into<String>) -> Self {
        self.server_name = name.into();
        self
    }

    /// Load a YAML policy and automatically issue tokens for each rule.
    ///
    /// Resources must use the `tool://<name>` convention so the harness can
    /// map tool names to token IDs.
    pub fn policy_yaml(mut self, yaml: impl Into<String>) -> Self {
        self.policy_yaml = Some(yaml.into());
        self
    }

    /// Restrict which tools the agent may call via [`AllowlistMiddleware`].
    ///
    /// Empty list (default) means no allowlist — all tools pass through.
    pub fn allowed_tools(
        mut self,
        tools: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.allowed_tools = tools.into_iter().map(|t| t.into()).collect();
        self
    }

    /// Add a server-level token-bucket rate limit.
    pub fn rate_limit(mut self, max_calls: u64, window_seconds: u64) -> Self {
        self.rate_limit = Some(RateLimitConfig {
            max_calls,
            window_seconds,
            burst_size: None,
        });
        self
    }

    /// Set the per-operation timeout (default: 30 s).
    ///
    /// If setup or any agent operation exceeds this duration the test panics
    /// with a clear timeout message rather than hanging indefinitely.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Build and start the gateway, completing the MCP handshake.
    ///
    /// Panics if setup exceeds the configured timeout.
    pub async fn build(self) -> TestGateway {
        let t = self.timeout;
        timeout(t, self.build_inner())
            .await
            .unwrap_or_else(|_| panic!(
                "[TestGateway] setup timed out after {} s", t.as_secs()
            ))
    }

    async fn build_inner(self) -> TestGateway {
        // 1. Build the kernel (with or without pre-loaded policies).
        let kernel = Arc::new(if let Some(ref yaml) = self.policy_yaml {
            KernelHandle::from_policy_yaml(yaml)
                .expect("[TestGateway] policy YAML failed to compile")
        } else {
            KernelHandle::new()
        });

        // 2. Build the tool → token map from the kernel's issued tokens.
        let tool_tokens = build_tool_token_map(&kernel, &self.agent_id);

        // 3. Assemble the middleware chain:
        //    AllowlistMiddleware? → RateLimiterMiddleware? → PolicyEnforcementMiddleware?
        let mut middlewares: Vec<Arc<dyn InterceptionMiddleware>> = vec![];

        if !self.allowed_tools.is_empty() {
            let server_cfg = ServerConfig {
                command: None,
                url: None,
                transport: "stdio".into(),
                env: HashMap::new(),
                allowed_tools: self.allowed_tools.clone(),
                rate_limit: None,
                identity_strategy: IdentityStrategy::default(),
                tool_rate_limits: HashMap::new(),
                tools: HashMap::new(),
            };
            middlewares.push(Arc::new(AllowlistMiddleware::new(
                &self.server_name,
                &self.agent_id,
                server_cfg,
            )));
        }

        if let Some(ref rl) = self.rate_limit {
            let limiter = Arc::new(RateLimiter::new(
                &self.server_name,
                Some(rl.clone()),
                HashMap::new(),
            ));
            middlewares.push(Arc::new(RateLimiterMiddleware::new(
                &self.agent_id,
                limiter,
            )));
        }

        // Add enforcement whenever a policy YAML was provided — even if the
        // token map is empty (which means every tool call is denied because no
        // capability was issued for the requested agent/tool combination).
        if self.policy_yaml.is_some() {
            middlewares.push(Arc::new(PolicyEnforcementMiddleware::new(
                Arc::clone(&kernel),
                &self.agent_id,
                &self.server_name,
                tool_tokens,
            )));
        }

        let chain = Arc::new(MiddlewareChain::new(middlewares));

        // 4. Build the proxy.
        let proxy = StdioProxy::new(self.upstream.into_proxy_config())
            .with_middleware(chain);

        // 5. Create an in-process duplex channel connecting MockAgent ↔ StdioProxy.
        //
        //   mock_stream  — MockAgent reads/writes here
        //   proxy_stream — StdioProxy reads/writes here (split into halves)
        let (mock_stream, proxy_stream) = tokio::io::duplex(64 * 1024);
        let (proxy_read, proxy_write) = tokio::io::split(proxy_stream);

        // 6. Spawn the proxy in a background task.
        let proxy_task = tokio::spawn(async move {
            if let Err(e) = proxy.run(proxy_read, proxy_write).await {
                eprintln!("[TestGateway] proxy task error: {e}");
            }
        });

        // 7. Run the MCP handshake so the agent is ready to call tools.
        let mut agent = MockAgent::new(mock_stream, self.timeout);
        agent
            .handshake()
            .await
            .expect("[TestGateway] MCP handshake failed");

        TestGateway {
            kernel,
            agent: Some(agent),
            proxy_task: Some(proxy_task),
            timeout: self.timeout,
        }
    }
}

// ── TestGateway ───────────────────────────────────────────────────────────────

/// A fully-managed test gateway instance.
///
/// Owns:
/// - the `KernelHandle` (for direct audit/token inspection),
/// - the `MockAgent` (for sending tool calls),
/// - the background proxy task.
///
/// Call [`teardown`] at the end of every test to shut down cleanly.
/// Dropping the struct aborts the proxy task as a fallback.
///
/// [`teardown`]: TestGateway::teardown
pub struct TestGateway {
    /// The Aegis kernel — inspect `audit_entries()` and `token_count()` here.
    pub kernel: Arc<KernelHandle>,
    /// The mock MCP client — use `call_tool` or the assertion macros.
    ///
    /// Wrapped in `Option` so `teardown()` can drop it while `Drop` is still
    /// implemented on the struct.  Always `Some` until `teardown()` is called.
    pub agent: Option<MockAgent>,
    proxy_task: Option<JoinHandle<()>>,
    /// Default timeout for every agent operation.
    pub timeout: Duration,
}

impl TestGateway {
    /// Start building a new gateway with a fluent builder.
    pub fn builder() -> TestGatewayBuilder { TestGatewayBuilder::new() }

    /// Send a `tools/call` and return the raw result.
    ///
    /// Panics on network / serialization errors but not on Aegis denial;
    /// use [`assert_tool_call_denied!`] to assert denial.
    pub async fn call(&mut self, tool: &str, args: Value) -> McpResult {
        self.agent
            .as_mut()
            .expect("MockAgent already taken by teardown()")
            .call_tool(tool, args)
            .await
            .unwrap_or_else(|e| panic!("call_tool({tool}) I/O error: {e}"))
    }

    /// All kernel-level audit entries produced so far (oldest first).
    pub fn audit_entries(&self) -> Vec<AuditEntry> { self.kernel.audit_entries() }

    /// Number of kernel audit entries for `tool` with `decision`.
    pub fn audit_count(&self, tool: &str, decision: Decision) -> usize {
        self.kernel
            .audit_entries()
            .into_iter()
            .filter(|e| e.tool_name == tool && e.decision == decision)
            .count()
    }

    /// Cleanly shut down the gateway and the upstream MCP server.
    ///
    /// Drops the `MockAgent` (sending EOF to the proxy's agent-input reader),
    /// then waits up to 5 s for the proxy task to finish naturally.
    /// The upstream server exits when its stdin pipe closes — which happens
    /// as part of the proxy's own teardown sequence.
    pub async fn teardown(mut self) {
        // Taking and dropping MockAgent closes the write side of the duplex → EOF on proxy.
        drop(self.agent.take());

        if let Some(task) = self.proxy_task.take() {
            match tokio::time::timeout(Duration::from_secs(5), task).await {
                Ok(_) => {}
                Err(_) => eprintln!(
                    "[TestGateway] proxy task did not finish within 5 s — process may leak"
                ),
            }
        }
    }
}

impl Drop for TestGateway {
    /// Abort the proxy task if the test forgets to call `teardown()`.
    fn drop(&mut self) {
        if let Some(task) = self.proxy_task.take() {
            task.abort();
        }
    }
}

// ── Assertion macros ──────────────────────────────────────────────────────────

/// Assert that a `tools/call` is **allowed** and returns a success response.
///
/// Panics with a descriptive message if the gateway denies the call.
/// Returns the [`McpResult`] so callers can inspect `.text()` or `.unwrap()`.
///
/// # Usage
///
/// ```rust,ignore
/// // Basic allow check
/// assert_tool_call_allowed!(gw, "echo", json!({"message": "hello"}));
///
/// // With result inspection
/// let r = assert_tool_call_allowed!(gw, "add", json!({"a": 3, "b": 4}));
/// assert_eq!(r.text(), Some("7"));
/// ```
#[macro_export]
macro_rules! assert_tool_call_allowed {
    ($gw:expr, $tool:expr, $args:expr) => {{
        let _tool = $tool;
        let result = $gw
            .agent
            .as_mut()
            .expect("MockAgent already taken by teardown()")
            .call_tool(_tool, $args)
            .await
            .unwrap_or_else(|e| panic!("call_tool({}) I/O error: {}", _tool, e));
        assert!(
            result.is_ok(),
            "expected tool call '{}' to be ALLOWED, but was DENIED:\n  {:?}",
            _tool,
            result
        );
        result
    }};
}

/// Assert that a `tools/call` is **denied** and returns a JSON-RPC error.
///
/// Panics if the call unexpectedly succeeds.
/// Returns the [`McpResult`] for further inspection of the error code/reason.
///
/// An optional `code = <expr>` arm also asserts the specific error code.
///
/// # Usage
///
/// ```rust,ignore
/// // Basic deny check
/// assert_tool_call_denied!(gw, "write_file", json!({}));
///
/// // Assert specific Aegis error code
/// assert_tool_call_denied!(gw, "write_file", json!({}), code = AEGIS_DENIED);
/// assert_tool_call_denied!(gw, "banned_tool", json!({}), code = AEGIS_NOT_ALLOWED);
/// assert_tool_call_denied!(gw, "echo", json!({}), code = AEGIS_RATE_LIMITED);
/// ```
#[macro_export]
macro_rules! assert_tool_call_denied {
    ($gw:expr, $tool:expr, $args:expr) => {{
        let _tool = $tool;
        let result = $gw
            .agent
            .as_mut()
            .expect("MockAgent already taken by teardown()")
            .call_tool(_tool, $args)
            .await
            .unwrap_or_else(|e| panic!("call_tool({}) I/O error: {}", _tool, e));
        assert!(
            result.is_error(),
            "expected tool call '{}' to be DENIED, but was ALLOWED:\n  {:?}",
            _tool,
            result
        );
        result
    }};
    ($gw:expr, $tool:expr, $args:expr, code = $code:expr) => {{
        let result = $crate::assert_tool_call_denied!($gw, $tool, $args);
        assert_eq!(
            result.error_code(),
            Some($code as i64),
            "tool '{}' was denied with wrong error code — expected {}, got {:?}",
            $tool,
            $code,
            result.error_code()
        );
        result
    }};
}

/// Assert the kernel audit log contains an entry for `tool` with the specified
/// decision (`allow` or `deny`).
///
/// An optional `agent = <expr>` clause also checks the `agent_id` field.
///
/// # Usage
///
/// ```rust,ignore
/// assert_audit_contains!(gw, tool = "echo", decision = allow);
/// assert_audit_contains!(gw, tool = "write_file", decision = deny);
/// assert_audit_contains!(gw, tool = "echo", agent = "my-agent", decision = allow);
/// ```
#[macro_export]
macro_rules! assert_audit_contains {
    ($gw:expr, tool = $tool:expr, decision = allow) => {{
        let entries = $gw.kernel.audit_entries();
        assert!(
            entries.iter().any(|e| {
                e.tool_name == $tool
                    && matches!(e.decision, aegis_handle::Decision::Allow)
            }),
            "audit log has no ALLOW entry for tool '{}'\n  existing: {:?}",
            $tool,
            entries
                .iter()
                .map(|e| (&e.tool_name, &e.decision))
                .collect::<Vec<_>>()
        );
    }};
    ($gw:expr, tool = $tool:expr, decision = deny) => {{
        let entries = $gw.kernel.audit_entries();
        assert!(
            entries.iter().any(|e| {
                e.tool_name == $tool
                    && matches!(e.decision, aegis_handle::Decision::Deny)
            }),
            "audit log has no DENY entry for tool '{}'\n  existing: {:?}",
            $tool,
            entries
                .iter()
                .map(|e| (&e.tool_name, &e.decision))
                .collect::<Vec<_>>()
        );
    }};
    ($gw:expr, tool = $tool:expr, agent = $agent:expr, decision = allow) => {{
        let entries = $gw.kernel.audit_entries();
        assert!(
            entries.iter().any(|e| {
                e.tool_name == $tool
                    && e.agent_id == $agent
                    && matches!(e.decision, aegis_handle::Decision::Allow)
            }),
            "audit log has no ALLOW entry for tool='{}' agent='{}'",
            $tool,
            $agent
        );
    }};
    ($gw:expr, tool = $tool:expr, agent = $agent:expr, decision = deny) => {{
        let entries = $gw.kernel.audit_entries();
        assert!(
            entries.iter().any(|e| {
                e.tool_name == $tool
                    && e.agent_id == $agent
                    && matches!(e.decision, aegis_handle::Decision::Deny)
            }),
            "audit log has no DENY entry for tool='{}' agent='{}'",
            $tool,
            $agent
        );
    }};
}

/// Policy YAML for a single-tool "echo only" agent — convenient for tests
/// that just need one allowed tool with no constraints.
pub const ECHO_ONLY_POLICY: &str = r#"
policies:
  - name: echo-access
    agent: test-agent
    resource: "tool://echo"
    actions: [execute]
    ttl: 1h
    max_uses: 1000
"#;

/// Policy YAML granting access to both `echo` and `add` — for multi-tool tests.
pub const ECHO_AND_ADD_POLICY: &str = r#"
policies:
  - name: echo-access
    agent: test-agent
    resource: "tool://echo"
    actions: [execute]
    ttl: 1h

  - name: add-access
    agent: test-agent
    resource: "tool://add"
    actions: [execute]
    ttl: 1h
"#;
