//! aegis-mcp-proxy — drop Aegis enforcement in front of any MCP server.
//!
//! This binary sits between an MCP client (Claude Desktop, an agent script,
//! etc.) and any MCP server process, enforcing a YAML policy on every
//! `tools/call` request in real time.  Allowed calls are forwarded; denied
//! calls return a JSON-RPC error immediately — the real server never sees them.
//!
//! # Usage
//!
//! ```text
//! aegis-mcp-proxy [OPTIONS] -- <command> [args…]
//!
//! Options:
//!   --policy <file>   YAML policy file  (omit for passthrough — no enforcement)
//!   --agent  <id>     Agent identity string  (default: "claude")
//!   --server <name>   Server label used in log output  (default: "mcp-server")
//!
//! Examples:
//!   # Wrap the filesystem MCP server — allows read_file and list_directory only
//!   aegis-mcp-proxy --policy policy.yaml --agent claude \
//!     -- npx @modelcontextprotocol/server-filesystem /home/user/docs
//!
//!   # Wrap the built-in mock server (no npm needed)
//!   aegis-mcp-proxy --policy demo/policy.yaml --agent claude \
//!     -- python3 demo/mock_server.py
//!
//!   # Passthrough mode — no enforcement, raw proxy only
//!   aegis-mcp-proxy -- python3 demo/mock_server.py
//! ```
//!
//! # How it connects to Claude Desktop
//!
//! Add an entry in `~/Library/Application Support/Claude/claude_desktop_config.json`
//! (Mac) or `~/.config/Claude/claude_desktop_config.json` (Linux):
//!
//! ```json
//! {
//!   "mcpServers": {
//!     "aegis-mock": {
//!       "command": "/path/to/aegis-mcp-proxy",
//!       "args": [
//!         "--policy", "/path/to/demo/policy.yaml",
//!         "--agent",  "claude",
//!         "--",
//!         "python3", "/path/to/demo/mock_server.py"
//!       ]
//!     }
//!   }
//! }
//! ```
//!
//! Restart Claude Desktop.  Every tool call in your chat now goes through Aegis.
//! Enforcement decisions are printed to stderr — visible in Claude Desktop's
//! MCP server logs (Settings → Developer → MCP Logs).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use aegis_gateway::proxy::{
    InterceptionMiddleware, InterceptionResult, MiddlewareChain, StdioProxy,
};
use aegis_gateway::proxy::stdio::StdioProxyConfig;
use aegis_handle::{Action, Decision, KernelHandle, Resource, ToolCallRequest};
use aegis_mcp::{
    translate::{translate_to_intent, AgentContext, IntentKind},
    JsonRpcError, McpMessage,
};
use serde_json::json;
use uuid::Uuid;

// ── CLI ───────────────────────────────────────────────────────────────────────

struct Cli {
    policy_file: Option<PathBuf>,
    agent_id:    String,
    server_name: String,
    command:     String,
    cmd_args:    Vec<String>,
}

fn parse_cli() -> Cli {
    let all: Vec<String> = std::env::args().skip(1).collect();

    let sep = all.iter().position(|a| a == "--").unwrap_or_else(|| {
        eprintln!("aegis-mcp-proxy: missing '--' separator before MCP server command.");
        eprintln!();
        eprintln!("Usage: aegis-mcp-proxy [--policy FILE] [--agent ID] [--server NAME] -- COMMAND [ARGS...]");
        eprintln!();
        eprintln!("Examples:");
        eprintln!("  aegis-mcp-proxy --policy demo/policy.yaml --agent claude -- python3 demo/mock_server.py");
        eprintln!("  aegis-mcp-proxy -- npx @modelcontextprotocol/server-filesystem /tmp");
        std::process::exit(1);
    });

    let flags = &all[..sep];
    let cmd   = &all[sep + 1..];

    if cmd.is_empty() {
        eprintln!("aegis-mcp-proxy: no command after '--'.");
        std::process::exit(1);
    }

    let mut policy_file = None::<PathBuf>;
    let mut agent_id    = "claude".to_string();
    let mut server_name = "mcp-server".to_string();
    let mut i = 0;

    while i < flags.len() {
        match flags[i].as_str() {
            "--policy" if i + 1 < flags.len() => { policy_file = Some(PathBuf::from(&flags[i+1])); i += 2; }
            "--agent"  if i + 1 < flags.len() => { agent_id    = flags[i+1].clone(); i += 2; }
            "--server" if i + 1 < flags.len() => { server_name = flags[i+1].clone(); i += 2; }
            flag => { eprintln!("[aegis] warning: unknown flag '{flag}' (ignored)"); i += 1; }
        }
    }

    Cli {
        policy_file,
        agent_id,
        server_name,
        command:  cmd[0].clone(),
        cmd_args: cmd[1..].to_vec(),
    }
}

// ── Enforcement middleware ────────────────────────────────────────────────────

/// Intercepts every `tools/call`, looks up the matching capability token, and
/// calls `kernel.evaluate()`.  A call with no matching token is denied
/// immediately with error code -32001.
///
/// All other MCP messages (initialize, tools/list, notifications, …) are
/// forwarded unchanged.
struct AegisEnforcement {
    kernel:      Arc<KernelHandle>,
    agent_id:    String,
    server_name: String,
    /// tool_name → UUID of the capability token that covers it.
    token_map:   HashMap<String, Uuid>,
}

impl AegisEnforcement {
    /// Build the middleware from a loaded kernel.
    ///
    /// Scans all tokens whose subject matches `agent_id` and whose resource
    /// follows the `tool://<name>` convention, then builds the dispatch map.
    fn new(
        kernel:      Arc<KernelHandle>,
        agent_id:    impl Into<String>,
        server_name: impl Into<String>,
    ) -> Self {
        let agent_id    = agent_id.into();
        let server_name = server_name.into();

        let token_map: HashMap<String, Uuid> = kernel
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
            .collect();

        let allowed: Vec<&str> = token_map.keys().map(String::as_str).collect();
        eprintln!("[aegis] policy active — agent='{}' authorised tools: [{}]",
                  agent_id,
                  if allowed.is_empty() { "none".to_string() } else { allowed.join(", ") });

        Self { kernel, agent_id, server_name, token_map }
    }

    fn deny_response(&self, tool: &str, code: i64, reason: String) -> InterceptionResult {
        eprintln!("[aegis] DENY  tool={tool:<20} agent={} reason={reason}", self.agent_id);
        InterceptionResult::Block(JsonRpcError {
            code,
            message: reason.clone(),
            data: Some(json!({
                "aegis":    true,
                "decision": "deny",
                "reason":   reason,
                "tool":     tool,
                "agent":    self.agent_id,
                "server":   self.server_name,
            })),
        })
    }
}

impl InterceptionMiddleware for AegisEnforcement {
    fn on_request(&self, message: McpMessage) -> InterceptionResult {
        // Only intercept tools/call; let everything else through.
        let intent = match &message {
            McpMessage::Request(req) => {
                let ctx = AgentContext { agent_id: self.agent_id.clone(), token_id: String::new() };
                match translate_to_intent(req, &ctx) {
                    Some(IntentKind::ToolCall(tc)) => tc,
                    _ => return InterceptionResult::Forward(message),
                }
            }
            _ => return InterceptionResult::Forward(message),
        };

        let tool = &intent.tool_name;

        // Look up the capability token for this tool.
        let token_id = match self.token_map.get(tool) {
            Some(&id) => id,
            None => return self.deny_response(
                tool, -32001,
                format!("no capability token for tool '{tool}' — add it to policy.yaml and restart"),
            ),
        };

        // Build the resource URI and call the kernel.
        let resource = match Resource::new(&format!("tool://{tool}")) {
            Ok(r)  => r,
            Err(_) => return InterceptionResult::Forward(message), // shouldn't happen
        };

        let tcr = ToolCallRequest {
            agent_id:   self.agent_id.clone(),
            tool_name:  tool.clone(),
            action:     Action::Execute,
            resource,
            parameters: intent.parameters.clone(),
            token_id,
        };

        let result = self.kernel.evaluate(&tcr);

        match result.decision {
            Decision::Allow => {
                eprintln!(
                    "[aegis] ALLOW tool={tool:<20} agent={} latency={}µs  reason={}",
                    self.agent_id, result.audit.latency_us, result.audit.reason
                );
                InterceptionResult::Forward(message)
            }
            Decision::Deny => {
                self.deny_response(tool, -32001, result.audit.reason.clone())
            }
        }
    }

    fn on_response(&self, message: McpMessage) -> InterceptionResult {
        InterceptionResult::Forward(message)
    }
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let cli = parse_cli();

    // Load policy and build kernel (or run passthrough if no policy given).
    let enforcement: Option<Arc<dyn InterceptionMiddleware>> = match &cli.policy_file {
        None => {
            eprintln!("[aegis] no --policy flag — passthrough mode (no enforcement)");
            None
        }
        Some(path) => {
            let yaml = std::fs::read_to_string(path).unwrap_or_else(|e| {
                eprintln!("[aegis] cannot read '{}': {e}", path.display());
                std::process::exit(1);
            });
            let kernel = KernelHandle::from_policy_yaml(&yaml).unwrap_or_else(|e| {
                eprintln!("[aegis] policy error: {e}");
                std::process::exit(1);
            });
            let mw = AegisEnforcement::new(Arc::new(kernel), &cli.agent_id, &cli.server_name);
            Some(Arc::new(mw))
        }
    };

    // Assemble the proxy.
    let config = StdioProxyConfig {
        command: cli.command,
        args:    cli.cmd_args,
        env:     vec![],
    };

    let proxy = match enforcement {
        None     => StdioProxy::new(config),
        Some(mw) => StdioProxy::new(config)
            .with_middleware(Arc::new(MiddlewareChain::new(vec![mw]))),
    };

    eprintln!("[aegis] proxy starting (agent='{}' server='{}')", cli.agent_id, cli.server_name);

    if let Err(e) = proxy.run(tokio::io::stdin(), tokio::io::stdout()).await {
        eprintln!("[aegis] proxy error: {e}");
        std::process::exit(1);
    }
}
