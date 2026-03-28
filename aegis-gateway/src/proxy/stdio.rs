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

use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};

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
}

impl StdioProxy {
    pub fn new(config: StdioProxyConfig) -> Self {
        Self { config }
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

        // Propagate first error
        a2s_result?;
        s2a_result?;

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
}
