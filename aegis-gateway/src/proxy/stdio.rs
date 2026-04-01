//! Stdio transparent proxy for MCP servers.
//!
//! The proxy sits between an MCP client (AI agent) and an MCP server:
//!
//! ```text
//! Agent → stdin → [Aegis Gateway] → stdin → MCP Server
//! Agent ← stdout ← [Aegis Gateway] ← stdout ← MCP Server
//! ```
//!
//! The gateway spawns the real MCP server as a child process and forwards
//! newline-delimited JSON messages in both directions. For now, all traffic
//! is forwarded transparently with byte-perfect fidelity (no
//! parse-reserialize that could alter field order or whitespace).

use std::process::Stdio;
use std::sync::Arc;

use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};

use super::middleware::{block_response, InterceptionMiddleware, InterceptionResult};

/// Errors from the stdio proxy.
#[derive(Debug, Error)]
pub enum StdioProxyError {
    #[error("failed to spawn MCP server: {0}")]
    Spawn(#[source] std::io::Error),

    #[error("I/O error in {direction}: {source}")]
    Io {
        direction: &'static str,
        source: std::io::Error,
    },

    #[error("server exited with non-zero status: {0}")]
    ServerExit(String),

    #[error("MCP parse error: {0}")]
    McpParse(#[from] aegis_mcp::McpError),

    #[error("MCP serialization error: {0}")]
    McpSerialize(String),
}

/// Result type for the stdio proxy.
pub type Result<T> = std::result::Result<T, StdioProxyError>;

/// Configuration for spawning an MCP server behind the proxy.
#[derive(Debug, Clone)]
pub struct StdioProxyConfig {
    /// The command to run (e.g. "npx", "python", or a path to a binary).
    pub command: String,
    /// Arguments to the command (e.g. \["@modelcontextprotocol/server-filesystem", "/tmp"\]).
    pub args: Vec<String>,
    /// Optional environment variables to set on the child process.
    pub env: Vec<(String, String)>,
}

/// A transparent stdio proxy between an MCP client and server.
///
/// On [`run`], the proxy:
/// 1. Spawns the MCP server as a child process with piped stdin/stdout.
/// 2. Runs two concurrent forwarding loops:
///    - **agent → server**: reads lines from `agent_input`, writes to server stdin
///    - **server → agent**: reads lines from server stdout, writes to `agent_output`
/// 3. Both loops run until EOF or error, then the child is awaited.
///
/// Forwarding is raw line-based (no parse/reserialize) to guarantee
/// byte-perfect fidelity.
pub struct StdioProxy {
    config: StdioProxyConfig,
    middleware: Option<Arc<dyn InterceptionMiddleware>>,
}

impl StdioProxy {
    pub fn new(config: StdioProxyConfig) -> Self {
        Self {
            config,
            middleware: None,
        }
    }

    /// Attach an interception middleware to the proxy.
    ///
    /// When set, messages are parsed, run through the middleware, and
    /// re-serialized. Without middleware, raw byte forwarding is used
    /// (byte-perfect fidelity).
    pub fn with_middleware(mut self, middleware: Arc<dyn InterceptionMiddleware>) -> Self {
        self.middleware = Some(middleware);
        self
    }

    /// Spawn the MCP server and run the bidirectional proxy.
    ///
    /// - `agent_input`: the agent's outgoing stream (what the agent sends)
    /// - `agent_output`: the agent's incoming stream (what the agent receives)
    ///
    /// Returns when both directions hit EOF or an I/O error occurs.
    pub async fn run<R, W>(&self, agent_input: R, agent_output: W) -> Result<()>
    where
        R: tokio::io::AsyncRead + Unpin,
        W: tokio::io::AsyncWrite + Unpin,
    {
        let child = self.spawn_server()?;
        self.run_with_child(agent_input, agent_output, child).await
    }

    /// Run the proxy using a pre-spawned child process. Useful for testing
    /// where you want to control the child directly.
    pub async fn run_with_child<R, W>(
        &self,
        agent_input: R,
        agent_output: W,
        mut child: Child,
    ) -> Result<()>
    where
        R: tokio::io::AsyncRead + Unpin,
        W: tokio::io::AsyncWrite + Unpin,
    {
        let server_stdin = child
            .stdin
            .take()
            .expect("child stdin was piped but is None");
        let server_stdout = child
            .stdout
            .take()
            .expect("child stdout was piped but is None");

        // Run both directions concurrently. No tokio::spawn needed — both
        // futures execute on the current task via join!, making progress
        // through the async runtime.
        match &self.middleware {
            None => {
                // Raw byte forwarding — byte-perfect fidelity
                let (a2s_result, s2a_result) = tokio::join!(
                    forward_lines(
                        BufReader::new(agent_input),
                        server_stdin,
                        "agent→server"
                    ),
                    forward_lines(
                        BufReader::new(server_stdout),
                        agent_output,
                        "server→agent"
                    ),
                );
                a2s_result?;
                s2a_result?;
            }
            Some(mw) => {
                // Middleware path — parse, intercept, re-serialize.
                // agent_output is shared: the server→agent loop writes
                // responses, and blocked requests in agent→server also
                // need to write error responses back to the agent.
                let shared_agent_output = Arc::new(tokio::sync::Mutex::new(agent_output));

                let (a2s_result, s2a_result) = tokio::join!(
                    forward_requests_with_middleware(
                        BufReader::new(agent_input),
                        server_stdin,
                        Arc::clone(&shared_agent_output),
                        Arc::clone(mw),
                    ),
                    forward_responses_with_middleware(
                        BufReader::new(server_stdout),
                        Arc::clone(&shared_agent_output),
                        Arc::clone(mw),
                    ),
                );
                a2s_result?;
                s2a_result?;
            }
        }

        // Wait for the child to exit
        let status = child.wait().await.map_err(|e| StdioProxyError::Io {
            direction: "child-wait",
            source: e,
        })?;
        if !status.success() {
            return Err(StdioProxyError::ServerExit(format!("{}", status)));
        }

        Ok(())
    }

    fn spawn_server(&self) -> Result<Child> {
        let mut cmd = Command::new(&self.config.command);
        cmd.args(&self.config.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true);

        for (k, v) in &self.config.env {
            cmd.env(k, v);
        }

        cmd.spawn().map_err(StdioProxyError::Spawn)
    }
}

/// Forward lines from `reader` to `writer` until EOF.
///
/// Each line is forwarded as-is (raw bytes including the newline) to
/// preserve byte-perfect fidelity. After each line, the writer is flushed
/// to minimize latency.
async fn forward_lines<R, W>(
    mut reader: BufReader<R>,
    mut writer: W,
    direction: &'static str,
) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut line_buf = Vec::with_capacity(4096);
    loop {
        line_buf.clear();
        let n = reader
            .read_until(b'\n', &mut line_buf)
            .await
            .map_err(|e| StdioProxyError::Io {
                direction,
                source: e,
            })?;
        if n == 0 {
            break; // EOF
        }
        writer
            .write_all(&line_buf)
            .await
            .map_err(|e| StdioProxyError::Io {
                direction,
                source: e,
            })?;
        writer
            .flush()
            .await
            .map_err(|e| StdioProxyError::Io {
                direction,
                source: e,
            })?;
    }
    // Shut down the write side so the peer sees EOF
    writer
        .shutdown()
        .await
        .map_err(|e| StdioProxyError::Io {
            direction,
            source: e,
        })?;
    Ok(())
}

/// Write an MCP message as a newline-delimited JSON line.
async fn write_message_line<W: tokio::io::AsyncWrite + Unpin>(
    writer: &mut W,
    message: &McpMessage,
) -> Result<()> {
    let mut bytes =
        message
            .to_json_bytes()
            .map_err(|e| StdioProxyError::McpSerialize(e.to_string()))?;
    bytes.push(b'\n');
    writer
        .write_all(&bytes)
        .await
        .map_err(|e| StdioProxyError::Io {
            direction: "write",
            source: e,
        })?;
    writer
        .flush()
        .await
        .map_err(|e| StdioProxyError::Io {
            direction: "write",
            source: e,
        })?;
    Ok(())
}

/// Forward agent→server messages through middleware.
///
/// Reads lines from agent, parses, runs through `on_request`, then:
/// - Forward/Modify: serialize and write to server_stdin
/// - Block: write error response back to agent_output (shared)
async fn forward_requests_with_middleware<R, W1, W2>(
    mut reader: BufReader<R>,
    mut server_writer: W1,
    agent_output: Arc<tokio::sync::Mutex<W2>>,
    middleware: Arc<dyn InterceptionMiddleware>,
) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W1: tokio::io::AsyncWrite + Unpin,
    W2: tokio::io::AsyncWrite + Unpin,
{
    let mut line_buf = Vec::with_capacity(4096);
    loop {
        line_buf.clear();
        let n = reader
            .read_until(b'\n', &mut line_buf)
            .await
            .map_err(|e| StdioProxyError::Io {
                direction: "agent→server",
                source: e,
            })?;
        if n == 0 {
            break;
        }

        let trimmed = line_buf.strip_suffix(b"\n").unwrap_or(&line_buf);
        if trimmed.is_empty() {
            continue;
        }

        let message = aegis_mcp::parse_message(trimmed)?;

        match middleware.on_request(message) {
            InterceptionResult::Forward(msg) | InterceptionResult::Modify(msg) => {
                write_message_line(&mut server_writer, &msg).await?;
            }
            InterceptionResult::Block(error) => {
                // Build an error response and send it back to the agent.
                // For notifications (no id), we silently drop.
                let original = aegis_mcp::parse_message(trimmed)?;
                if let Some(err_resp) = block_response(&original, error) {
                    let mut out = agent_output.lock().await;
                    write_message_line(&mut *out, &err_resp).await?;
                }
            }
        }
    }

    server_writer
        .shutdown()
        .await
        .map_err(|e| StdioProxyError::Io {
            direction: "agent→server",
            source: e,
        })?;
    Ok(())
}

/// Forward server→agent responses through middleware.
async fn forward_responses_with_middleware<R, W>(
    mut reader: BufReader<R>,
    agent_output: Arc<tokio::sync::Mutex<W>>,
    middleware: Arc<dyn InterceptionMiddleware>,
) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut line_buf = Vec::with_capacity(4096);
    loop {
        line_buf.clear();
        let n = reader
            .read_until(b'\n', &mut line_buf)
            .await
            .map_err(|e| StdioProxyError::Io {
                direction: "server→agent",
                source: e,
            })?;
        if n == 0 {
            break;
        }

        let trimmed = line_buf.strip_suffix(b"\n").unwrap_or(&line_buf);
        if trimmed.is_empty() {
            continue;
        }

        let message = aegis_mcp::parse_message(trimmed)?;

        match middleware.on_response(message) {
            InterceptionResult::Forward(msg) | InterceptionResult::Modify(msg) => {
                let mut out = agent_output.lock().await;
                write_message_line(&mut *out, &msg).await?;
            }
            InterceptionResult::Block(_) => {
                // Silently drop blocked server responses
            }
        }
    }

    let mut out = agent_output.lock().await;
    out.shutdown()
        .await
        .map_err(|e| StdioProxyError::Io {
            direction: "server→agent",
            source: e,
        })?;
    Ok(())
}

use aegis_mcp::McpMessage;

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Stdio;
    use tokio::process::Command;

    fn cat_config() -> StdioProxyConfig {
        StdioProxyConfig {
            command: "cat".into(),
            args: vec![],
            env: vec![],
        }
    }

    async fn spawn_child(cmd: &str, args: &[&str]) -> Child {
        Command::new(cmd)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .expect("failed to spawn child")
    }

    // -----------------------------------------------------------------------
    // Basic forwarding tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn single_message_roundtrip() {
        let input = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}\n";
        let mut output = Vec::new();

        let proxy = StdioProxy::new(cat_config());
        let child = spawn_child("cat", &[]).await;
        proxy
            .run_with_child(&input[..], &mut output, child)
            .await
            .unwrap();

        assert_eq!(output, input);
    }

    #[tokio::test]
    async fn multi_message_forwarding() {
        let msg1 = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"capabilities\":{}}}\n";
        let msg2 = "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n";
        let msg3 = "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\n";

        let input = format!("{}{}{}", msg1, msg2, msg3);
        let mut output = Vec::new();

        let proxy = StdioProxy::new(cat_config());
        let child = spawn_child("cat", &[]).await;
        proxy
            .run_with_child(input.as_bytes(), &mut output, child)
            .await
            .unwrap();

        let output_str = String::from_utf8(output).unwrap();
        assert_eq!(output_str, input);

        // Verify every line is parseable
        for line in output_str.lines() {
            aegis_mcp::parse_message(line.as_bytes()).unwrap();
        }
    }

    #[tokio::test]
    async fn byte_perfect_fidelity() {
        // Unusual but valid formatting — extra spaces, different field order
        let input = "{ \"method\" : \"tools/call\" , \"jsonrpc\" : \"2.0\" , \"id\" : 1 , \"params\" : { \"name\" : \"read_file\" } }\n";
        let mut output = Vec::new();

        let proxy = StdioProxy::new(cat_config());
        let child = spawn_child("cat", &[]).await;
        proxy
            .run_with_child(input.as_bytes(), &mut output, child)
            .await
            .unwrap();

        assert_eq!(
            String::from_utf8(output).unwrap(),
            input,
            "byte-perfect fidelity violated"
        );
    }

    #[tokio::test]
    async fn empty_input_eof() {
        let mut output = Vec::new();

        let proxy = StdioProxy::new(cat_config());
        let child = spawn_child("cat", &[]).await;
        proxy
            .run_with_child(&b""[..], &mut output, child)
            .await
            .unwrap();

        assert!(output.is_empty());
    }

    #[tokio::test]
    async fn large_batch_forwarding() {
        let mut input = String::new();
        for i in 0..200 {
            input.push_str(&format!(
                "{{\"jsonrpc\":\"2.0\",\"id\":{},\"method\":\"ping\"}}\n",
                i
            ));
        }
        let mut output = Vec::new();

        let proxy = StdioProxy::new(cat_config());
        let child = spawn_child("cat", &[]).await;
        proxy
            .run_with_child(input.as_bytes(), &mut output, child)
            .await
            .unwrap();

        assert_eq!(String::from_utf8(output).unwrap(), input);
    }

    // -----------------------------------------------------------------------
    // Mock MCP server tests
    // -----------------------------------------------------------------------

    /// Bash script that acts as a minimal MCP server.
    const MOCK_MCP_SERVER: &str = r#"
while IFS= read -r line; do
    case "$line" in
        *'"method":"initialize"'*|*'"method": "initialize"'*)
            id=$(echo "$line" | sed 's/.*"id":\([0-9]*\).*/\1/')
            echo "{\"jsonrpc\":\"2.0\",\"id\":${id},\"result\":{\"protocolVersion\":\"2024-11-05\",\"serverInfo\":{\"name\":\"mock-server\",\"version\":\"0.1.0\"},\"capabilities\":{\"tools\":{}}}}"
            ;;
        *'"method":"tools/list"'*|*'"method": "tools/list"'*)
            id=$(echo "$line" | sed 's/.*"id":\([0-9]*\).*/\1/')
            echo "{\"jsonrpc\":\"2.0\",\"id\":${id},\"result\":{\"tools\":[{\"name\":\"read_file\",\"description\":\"Read a file\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"path\":{\"type\":\"string\"}}}},{\"name\":\"write_file\",\"description\":\"Write a file\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"path\":{\"type\":\"string\"},\"content\":{\"type\":\"string\"}}}}]}}"
            ;;
        *'"method":"notifications/'*)
            ;;
        *'"method":"ping"'*)
            id=$(echo "$line" | sed 's/.*"id":\([0-9]*\).*/\1/')
            echo "{\"jsonrpc\":\"2.0\",\"id\":${id},\"result\":{}}"
            ;;
        *)
            echo "$line"
            ;;
    esac
done
"#;

    #[tokio::test]
    async fn mock_server_initialize_and_tools_list() {
        let input = concat!(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},\"clientInfo\":{\"name\":\"test\",\"version\":\"1.0\"}}}\n",
            "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\n",
        );

        let mut output = Vec::new();
        let proxy = StdioProxy::new(cat_config());
        let child = spawn_child("bash", &["-c", MOCK_MCP_SERVER]).await;
        proxy
            .run_with_child(input.as_bytes(), &mut output, child)
            .await
            .unwrap();

        let output_str = String::from_utf8(output).unwrap();
        let lines: Vec<&str> = output_str.lines().collect();

        // 2 responses (notification gets none)
        assert_eq!(lines.len(), 2, "expected 2 responses, got: {:?}", lines);

        // Validate initialize response
        let msg1 = aegis_mcp::parse_message(lines[0].as_bytes()).unwrap();
        match msg1 {
            aegis_mcp::McpMessage::Response(resp) => {
                assert_eq!(resp.id, aegis_mcp::RequestId::Number(1));
                let result = resp.result.unwrap();
                assert_eq!(result["protocolVersion"], "2024-11-05");
                assert_eq!(result["serverInfo"]["name"], "mock-server");
            }
            _ => panic!("expected Response for initialize"),
        }

        // Validate tools/list response
        let msg2 = aegis_mcp::parse_message(lines[1].as_bytes()).unwrap();
        match msg2 {
            aegis_mcp::McpMessage::Response(resp) => {
                assert_eq!(resp.id, aegis_mcp::RequestId::Number(2));
                let result = resp.result.unwrap();
                let tools = result["tools"].as_array().unwrap();
                assert_eq!(tools.len(), 2);
                assert_eq!(tools[0]["name"], "read_file");
                assert_eq!(tools[1]["name"], "write_file");
            }
            _ => panic!("expected Response for tools/list"),
        }
    }

    #[tokio::test]
    async fn mock_server_bidirectional_ping() {
        let input = concat!(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"ping\"}\n",
        );

        let mut output = Vec::new();
        let proxy = StdioProxy::new(cat_config());
        let child = spawn_child("bash", &["-c", MOCK_MCP_SERVER]).await;
        proxy
            .run_with_child(input.as_bytes(), &mut output, child)
            .await
            .unwrap();

        let output_str = String::from_utf8(output).unwrap();
        let lines: Vec<&str> = output_str.lines().collect();
        assert_eq!(lines.len(), 3);

        for (i, line) in lines.iter().enumerate() {
            let msg = aegis_mcp::parse_message(line.as_bytes()).unwrap();
            match msg {
                aegis_mcp::McpMessage::Response(resp) => {
                    assert_eq!(resp.id, aegis_mcp::RequestId::Number(i as i64 + 1));
                }
                _ => panic!("expected Response"),
            }
        }
    }

    #[tokio::test]
    async fn proxy_handles_server_stderr_separately() {
        // Server writes to stderr — must not appear in agent output
        let script = concat!(
            "echo 'stderr noise' >&2\n",
            "while IFS= read -r line; do echo \"$line\"; done\n",
        );
        let input = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n";
        let mut output = Vec::new();

        let proxy = StdioProxy::new(cat_config());
        let child = spawn_child("bash", &["-c", script]).await;
        proxy
            .run_with_child(&input[..], &mut output, child)
            .await
            .unwrap();

        let output_str = String::from_utf8(output).unwrap();
        assert!(!output_str.contains("stderr noise"));
        assert!(output_str.contains("ping"));
    }

    #[tokio::test]
    async fn proxy_server_exit_nonzero() {
        let script = "exit 1";
        let mut output = Vec::new();

        let proxy = StdioProxy::new(cat_config());
        let child = spawn_child("bash", &["-c", script]).await;
        let result = proxy
            .run_with_child(&b""[..], &mut output, child)
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, StdioProxyError::ServerExit(_)));
    }

    #[tokio::test]
    async fn proxy_server_exit_zero() {
        let script = "read -r line; echo \"$line\"; exit 0";
        let input = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n";
        let mut output = Vec::new();

        let proxy = StdioProxy::new(cat_config());
        let child = spawn_child("bash", &["-c", script]).await;
        proxy
            .run_with_child(&input[..], &mut output, child)
            .await
            .unwrap();

        assert!(!output.is_empty());
    }

    #[tokio::test]
    async fn proxy_run_spawns_child() {
        // Test the `run` method which internally spawns the child from config
        let input = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n";
        let mut output = Vec::new();

        let proxy = StdioProxy::new(cat_config());
        proxy.run(&input[..], &mut output).await.unwrap();

        assert_eq!(output, input);
    }

    #[tokio::test]
    async fn tools_call_forwarded_transparently() {
        // Complex nested arguments must pass through unmodified
        let input = "{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"tools/call\",\"params\":{\"name\":\"query\",\"arguments\":{\"sql\":\"SELECT * FROM users WHERE age > 18\",\"options\":{\"limit\":100,\"offset\":0}}}}\n";
        let mut output = Vec::new();

        let proxy = StdioProxy::new(cat_config());
        let child = spawn_child("cat", &[]).await;
        proxy
            .run_with_child(input.as_bytes(), &mut output, child)
            .await
            .unwrap();

        assert_eq!(
            String::from_utf8(output).unwrap(),
            input,
            "tools/call must be forwarded byte-for-byte"
        );
    }

    #[tokio::test]
    async fn full_mcp_session_through_proxy() {
        // Simulate a complete MCP session: init → tools/list → tools/call → done
        let input = concat!(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},\"clientInfo\":{\"name\":\"test-agent\",\"version\":\"1.0\"}}}\n",
            "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"ping\"}\n",
        );

        let mut output = Vec::new();
        let proxy = StdioProxy::new(cat_config());
        let child = spawn_child("bash", &["-c", MOCK_MCP_SERVER]).await;
        proxy
            .run_with_child(input.as_bytes(), &mut output, child)
            .await
            .unwrap();

        let output_str = String::from_utf8(output).unwrap();
        let lines: Vec<&str> = output_str.lines().collect();

        // 3 responses: initialize, tools/list, ping (notification has none)
        assert_eq!(lines.len(), 3, "got: {:?}", lines);

        // All must be valid parseable MCP responses
        for line in &lines {
            let msg = aegis_mcp::parse_message(line.as_bytes()).unwrap();
            assert!(
                matches!(msg, aegis_mcp::McpMessage::Response(_)),
                "expected all responses"
            );
        }

        // Verify the tools/list response contains tools
        let tools_resp = aegis_mcp::parse_message(lines[1].as_bytes()).unwrap();
        if let aegis_mcp::McpMessage::Response(resp) = tools_resp {
            let tools = resp.result.unwrap()["tools"].as_array().unwrap().clone();
            assert!(!tools.is_empty(), "tools/list should return tools");
            // Confirm the tool names
            let names: Vec<&str> = tools
                .iter()
                .map(|t| t["name"].as_str().unwrap())
                .collect();
            assert!(names.contains(&"read_file"));
            assert!(names.contains(&"write_file"));
        }
    }

    // -----------------------------------------------------------------------
    // Middleware tests
    // -----------------------------------------------------------------------

    use super::super::middleware::{
        InterceptionMiddleware, InterceptionResult, PassthroughMiddleware,
    };

    #[tokio::test]
    async fn passthrough_middleware_roundtrip() {
        let input = concat!(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}\n",
        );
        let mut output = Vec::new();

        let proxy = StdioProxy::new(cat_config())
            .with_middleware(Arc::new(PassthroughMiddleware));
        let child = spawn_child("cat", &[]).await;
        proxy
            .run_with_child(input.as_bytes(), &mut output, child)
            .await
            .unwrap();

        let output_str = String::from_utf8(output).unwrap();
        let lines: Vec<&str> = output_str.lines().collect();
        assert_eq!(lines.len(), 2);

        // Verify each line is valid JSON-RPC
        for line in &lines {
            aegis_mcp::parse_message(line.as_bytes()).unwrap();
        }
    }

    #[tokio::test]
    async fn passthrough_middleware_with_mock_server() {
        let input = concat!(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},\"clientInfo\":{\"name\":\"test\",\"version\":\"1.0\"}}}\n",
            "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\n",
        );

        let mut output = Vec::new();
        let proxy = StdioProxy::new(cat_config())
            .with_middleware(Arc::new(PassthroughMiddleware));
        let child = spawn_child("bash", &["-c", MOCK_MCP_SERVER]).await;
        proxy
            .run_with_child(input.as_bytes(), &mut output, child)
            .await
            .unwrap();

        let output_str = String::from_utf8(output).unwrap();
        let lines: Vec<&str> = output_str.lines().collect();
        assert_eq!(lines.len(), 2, "expected 2 responses, got: {:?}", lines);

        // Validate initialize response
        let msg = aegis_mcp::parse_message(lines[0].as_bytes()).unwrap();
        match msg {
            aegis_mcp::McpMessage::Response(resp) => {
                assert_eq!(resp.id, aegis_mcp::RequestId::Number(1));
                assert_eq!(resp.result.unwrap()["serverInfo"]["name"], "mock-server");
            }
            _ => panic!("expected Response"),
        }
    }

    /// A middleware that blocks all `tools/call` requests.
    struct BlockToolCallsMiddleware;

    impl InterceptionMiddleware for BlockToolCallsMiddleware {
        fn on_request(&self, message: McpMessage) -> InterceptionResult {
            if message.is_tool_call() {
                InterceptionResult::Block(aegis_mcp::JsonRpcError {
                    code: -32600,
                    message: "tool calls are blocked".into(),
                    data: None,
                })
            } else {
                InterceptionResult::Forward(message)
            }
        }

        fn on_response(&self, message: McpMessage) -> InterceptionResult {
            InterceptionResult::Forward(message)
        }
    }

    #[tokio::test]
    async fn blocking_middleware_returns_error() {
        let input = concat!(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"read_file\"}}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}\n",
        );

        let mut output = Vec::new();
        let proxy = StdioProxy::new(cat_config())
            .with_middleware(Arc::new(BlockToolCallsMiddleware));
        let child = spawn_child("cat", &[]).await;
        proxy
            .run_with_child(input.as_bytes(), &mut output, child)
            .await
            .unwrap();

        let output_str = String::from_utf8(output).unwrap();
        let lines: Vec<&str> = output_str.lines().collect();

        // Should get 2 lines: error for blocked tools/call + echo of ping
        assert_eq!(lines.len(), 2, "got: {:?}", lines);

        // First line: error response for the blocked tools/call
        let msg1 = aegis_mcp::parse_message(lines[0].as_bytes()).unwrap();
        match msg1 {
            aegis_mcp::McpMessage::Response(resp) => {
                assert_eq!(resp.id, aegis_mcp::RequestId::Number(1));
                let err = resp.error.unwrap();
                assert_eq!(err.code, -32600);
                assert_eq!(err.message, "tool calls are blocked");
            }
            _ => panic!("expected error Response for blocked call"),
        }

        // Second line: ping was forwarded through cat and came back
        let msg2 = aegis_mcp::parse_message(lines[1].as_bytes()).unwrap();
        assert!(matches!(msg2, aegis_mcp::McpMessage::Request(_)));
    }

    /// A middleware that uppercases the method name of requests.
    struct UppercaseMethodMiddleware;

    impl InterceptionMiddleware for UppercaseMethodMiddleware {
        fn on_request(&self, message: McpMessage) -> InterceptionResult {
            match message {
                McpMessage::Request(mut req) => {
                    req.method = req.method.to_uppercase();
                    InterceptionResult::Modify(McpMessage::Request(req))
                }
                other => InterceptionResult::Forward(other),
            }
        }

        fn on_response(&self, message: McpMessage) -> InterceptionResult {
            InterceptionResult::Forward(message)
        }
    }

    #[tokio::test]
    async fn modifying_middleware_alters_message() {
        let input = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n";
        let mut output = Vec::new();

        let proxy = StdioProxy::new(cat_config())
            .with_middleware(Arc::new(UppercaseMethodMiddleware));
        let child = spawn_child("cat", &[]).await;
        proxy
            .run_with_child(input.as_bytes(), &mut output, child)
            .await
            .unwrap();

        let output_str = String::from_utf8(output).unwrap();
        let msg = aegis_mcp::parse_message(output_str.trim().as_bytes()).unwrap();
        match msg {
            aegis_mcp::McpMessage::Request(req) => {
                assert_eq!(req.method, "PING");
            }
            _ => panic!("expected Request"),
        }
    }
}
