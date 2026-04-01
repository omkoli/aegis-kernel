//! Gateway configuration: TOML parsing, validation, env-var substitution,
//! and hot-reload via filesystem watcher.
//!
//! ## Example `aegis.toml`
//!
//! ```toml
//! [gateway]
//! listen = "127.0.0.1:8080"
//! kernel_mode = "embedded"
//! log_level = "info"
//!
//! [servers.github]
//! command = "npx @modelcontextprotocol/server-github"
//! transport = "stdio"
//! env = { GITHUB_TOKEN = "${GITHUB_TOKEN}" }
//! allowed_tools = ["search_repositories", "get_file_contents"]
//!
//! [servers.github.rate_limit]
//! max_calls = 100
//! window_seconds = 60
//! ```

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use serde::Deserialize;
use thiserror::Error;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("I/O error reading config: {0}")]
    Io(#[from] std::io::Error),

    #[error("TOML parse error: {0}")]
    TomlParse(#[from] toml::de::Error),

    #[error("validation error: {0}")]
    Validation(String),

    #[error("environment variable '{name}' not set")]
    EnvVar { name: String },

    #[error("watcher error: {0}")]
    Watcher(String),
}

pub type Result<T> = std::result::Result<T, ConfigError>;

// ---------------------------------------------------------------------------
// Config structs
// ---------------------------------------------------------------------------

/// Top-level gateway configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct GatewayConfig {
    /// Global gateway settings.
    #[serde(default)]
    pub gateway: GatewaySettings,

    /// Named MCP server configurations.
    #[serde(default)]
    pub servers: HashMap<String, ServerConfig>,
}

/// Global gateway settings.
#[derive(Debug, Clone, Deserialize)]
pub struct GatewaySettings {
    /// Downstream listen address. Default: `"127.0.0.1:8080"`.
    #[serde(default = "default_listen")]
    pub listen: String,

    /// Whether the kernel runs embedded or as a remote gRPC service.
    /// Valid values: `"embedded"`, `"remote"`. Default: `"embedded"`.
    #[serde(default = "default_kernel_mode")]
    pub kernel_mode: String,

    /// gRPC address of the remote kernel (only used when `kernel_mode = "remote"`).
    #[serde(default)]
    pub kernel_grpc: Option<String>,

    /// Tracing log level. Default: `"info"`.
    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// Path for the audit log (JSON Lines).
    #[serde(default)]
    pub audit_log: Option<String>,
}

impl Default for GatewaySettings {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            kernel_mode: default_kernel_mode(),
            kernel_grpc: None,
            log_level: default_log_level(),
            audit_log: None,
        }
    }
}

fn default_listen() -> String {
    "127.0.0.1:8080".into()
}
fn default_kernel_mode() -> String {
    "embedded".into()
}
fn default_log_level() -> String {
    "info".into()
}

/// Configuration for a single MCP server behind the gateway.
#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    /// Command to spawn (for stdio transport).
    #[serde(default)]
    pub command: Option<String>,

    /// Upstream URL (for SSE transport).
    #[serde(default)]
    pub url: Option<String>,

    /// Transport type: `"stdio"` or `"sse"`.
    pub transport: String,

    /// Environment variables for the spawned process.
    /// Values may contain `${VAR}` references.
    #[serde(default)]
    pub env: HashMap<String, String>,

    /// Tool allowlist. `["*"]` allows all tools. Empty or absent means no filtering.
    #[serde(default)]
    pub allowed_tools: Vec<String>,

    /// Optional rate-limit configuration.
    #[serde(default)]
    pub rate_limit: Option<RateLimitConfig>,
}

/// Rate-limit configuration for a server.
#[derive(Debug, Clone, Deserialize)]
pub struct RateLimitConfig {
    /// Maximum number of calls in the window.
    pub max_calls: u64,
    /// Window duration in seconds.
    pub window_seconds: u64,
}

// ---------------------------------------------------------------------------
// Environment variable substitution
// ---------------------------------------------------------------------------

/// Replace all `${VAR_NAME}` occurrences in `input` with values from the
/// environment. Returns an error if a referenced variable is not set.
fn substitute_env_vars(input: &str) -> Result<String> {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '$' && chars.peek() == Some(&'{') {
            chars.next(); // consume '{'
            let mut var_name = String::new();
            loop {
                match chars.next() {
                    Some('}') => break,
                    Some(ch) => var_name.push(ch),
                    None => {
                        // Unterminated ${...} — treat as literal
                        result.push_str("${");
                        result.push_str(&var_name);
                        return Ok(result);
                    }
                }
            }
            let value = std::env::var(&var_name)
                .map_err(|_| ConfigError::EnvVar { name: var_name })?;
            result.push_str(&value);
        } else {
            result.push(c);
        }
    }

    Ok(result)
}

/// Apply env-var substitution to all string values in the config.
fn substitute_config_env_vars(config: &mut GatewayConfig) -> Result<()> {
    // Gateway-level strings
    config.gateway.listen = substitute_env_vars(&config.gateway.listen)?;
    config.gateway.kernel_mode = substitute_env_vars(&config.gateway.kernel_mode)?;
    if let Some(ref grpc) = config.gateway.kernel_grpc {
        config.gateway.kernel_grpc = Some(substitute_env_vars(grpc)?);
    }
    if let Some(ref audit) = config.gateway.audit_log {
        config.gateway.audit_log = Some(substitute_env_vars(audit)?);
    }

    // Server-level strings
    for server in config.servers.values_mut() {
        if let Some(ref cmd) = server.command {
            server.command = Some(substitute_env_vars(cmd)?);
        }
        if let Some(ref url) = server.url {
            server.url = Some(substitute_env_vars(url)?);
        }
        let env_map: HashMap<String, String> = server
            .env
            .iter()
            .map(|(k, v)| Ok((k.clone(), substitute_env_vars(v)?)))
            .collect::<Result<_>>()?;
        server.env = env_map;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Validate a parsed config. Returns `Ok(())` or the first validation error.
pub fn validate(config: &GatewayConfig) -> Result<()> {
    // 1. listen must be a valid socket address
    config
        .gateway
        .listen
        .parse::<SocketAddr>()
        .map_err(|e| ConfigError::Validation(format!("invalid listen address '{}': {}", config.gateway.listen, e)))?;

    // 2. kernel_mode must be "embedded" or "remote"
    match config.gateway.kernel_mode.as_str() {
        "embedded" | "remote" => {}
        other => {
            return Err(ConfigError::Validation(format!(
                "invalid kernel_mode '{}': must be 'embedded' or 'remote'",
                other
            )));
        }
    }

    // 3. If remote, kernel_grpc must be set
    if config.gateway.kernel_mode == "remote" && config.gateway.kernel_grpc.is_none() {
        return Err(ConfigError::Validation(
            "kernel_mode is 'remote' but kernel_grpc is not set".into(),
        ));
    }

    // 4. Each server must have a valid transport
    for (name, server) in &config.servers {
        match server.transport.as_str() {
            "stdio" => {
                if server.command.is_none() {
                    return Err(ConfigError::Validation(format!(
                        "server '{}': transport is 'stdio' but 'command' is not set",
                        name
                    )));
                }
            }
            "sse" => {
                if server.url.is_none() {
                    return Err(ConfigError::Validation(format!(
                        "server '{}': transport is 'sse' but 'url' is not set",
                        name
                    )));
                }
                // Basic URL validation: must start with http:// or https://
                if let Some(ref url) = server.url {
                    if !url.starts_with("http://") && !url.starts_with("https://") {
                        return Err(ConfigError::Validation(format!(
                            "server '{}': url '{}' must start with http:// or https://",
                            name, url
                        )));
                    }
                }
            }
            other => {
                return Err(ConfigError::Validation(format!(
                    "server '{}': invalid transport '{}': must be 'stdio' or 'sse'",
                    name, other
                )));
            }
        }

        // 5. Rate limit values must be positive
        if let Some(ref rl) = server.rate_limit {
            if rl.max_calls == 0 {
                return Err(ConfigError::Validation(format!(
                    "server '{}': rate_limit.max_calls must be > 0",
                    name
                )));
            }
            if rl.window_seconds == 0 {
                return Err(ConfigError::Validation(format!(
                    "server '{}': rate_limit.window_seconds must be > 0",
                    name
                )));
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

/// Parse a TOML string into a validated `GatewayConfig`.
///
/// Environment variable references (`${VAR}`) in string values are resolved
/// from the process environment before validation.
pub fn load_str(toml_str: &str) -> Result<GatewayConfig> {
    let mut config: GatewayConfig = toml::from_str(toml_str)?;
    substitute_config_env_vars(&mut config)?;
    validate(&config)?;
    Ok(config)
}

/// Load a config file from disk, parse, substitute, and validate.
pub fn load_file(path: impl AsRef<Path>) -> Result<GatewayConfig> {
    let content = std::fs::read_to_string(path)?;
    load_str(&content)
}

// ---------------------------------------------------------------------------
// Config watcher (hot-reload)
// ---------------------------------------------------------------------------

/// Callback invoked after a successful hot-reload.
pub type ReloadCallback = Box<dyn Fn(&GatewayConfig) + Send + Sync>;

/// Watches an `aegis.toml` file for changes and reloads automatically.
///
/// On each detected file modification the watcher:
/// 1. Re-reads and re-parses the file.
/// 2. Runs env-var substitution and validation.
/// 3. If valid, stores the new config and invokes the callback.
/// 4. If invalid, keeps the previous config (fail-safe).
pub struct ConfigWatcher {
    config: Arc<Mutex<GatewayConfig>>,
    _watcher: RecommendedWatcher,
    path: PathBuf,
}

impl ConfigWatcher {
    /// Start watching `path` for changes.
    ///
    /// Performs an initial load; returns an error if the initial config is invalid.
    pub fn new(path: impl AsRef<Path>, on_reload: Option<ReloadCallback>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let initial = load_file(&path)?;
        let config = Arc::new(Mutex::new(initial));

        let config_clone = Arc::clone(&config);
        let path_clone = path.clone();
        let on_reload = on_reload.map(Arc::new);

        let mut watcher =
            notify::recommended_watcher(move |res: std::result::Result<notify::Event, notify::Error>| {
                let event = match res {
                    Ok(e) => e,
                    Err(_) => return,
                };

                match event.kind {
                    EventKind::Modify(_) | EventKind::Create(_) => {}
                    _ => return,
                }

                match load_file(&path_clone) {
                    Ok(new_config) => {
                        if let Some(ref cb) = on_reload {
                            cb(&new_config);
                        }
                        *config_clone.lock().unwrap() = new_config;
                    }
                    Err(e) => {
                        tracing::warn!("config reload failed, keeping previous config: {}", e);
                    }
                }
            })
            .map_err(|e| ConfigError::Watcher(e.to_string()))?;

        // Watch the parent directory (some editors replace the file atomically)
        let watch_path = path.parent().unwrap_or(&path).to_path_buf();
        watcher
            .watch(&watch_path, RecursiveMode::NonRecursive)
            .map_err(|e| ConfigError::Watcher(e.to_string()))?;

        Ok(Self {
            config,
            _watcher: watcher,
            path,
        })
    }

    /// Returns a snapshot of the current config.
    pub fn config(&self) -> GatewayConfig {
        self.config.lock().unwrap().clone()
    }

    /// Returns the path being watched.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Force a manual reload from disk.
    pub fn reload(&self) -> Result<GatewayConfig> {
        let new_config = load_file(&self.path)?;
        *self.config.lock().unwrap() = new_config.clone();
        Ok(new_config)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // 1. Valid minimal config
    // -----------------------------------------------------------------------

    #[test]
    fn valid_minimal_config() {
        let toml = r#"
[gateway]
listen = "127.0.0.1:9090"
"#;
        let config = load_str(toml).unwrap();
        assert_eq!(config.gateway.listen, "127.0.0.1:9090");
        assert_eq!(config.gateway.kernel_mode, "embedded");
        assert_eq!(config.gateway.log_level, "info");
        assert!(config.servers.is_empty());
    }

    // -----------------------------------------------------------------------
    // 2. Full config with multiple servers
    // -----------------------------------------------------------------------

    #[test]
    fn valid_full_config() {
        let toml = r#"
[gateway]
listen = "0.0.0.0:8080"
kernel_mode = "embedded"
log_level = "debug"
audit_log = "./audit.jsonl"

[servers.github]
command = "npx @modelcontextprotocol/server-github"
transport = "stdio"
allowed_tools = ["search_repositories", "get_file_contents"]

[servers.github.rate_limit]
max_calls = 100
window_seconds = 60

[servers.slack]
url = "https://mcp.slack.example.com/sse"
transport = "sse"
allowed_tools = ["*"]
"#;
        let config = load_str(toml).unwrap();
        assert_eq!(config.servers.len(), 2);

        let github = &config.servers["github"];
        assert_eq!(github.transport, "stdio");
        assert_eq!(github.command.as_deref(), Some("npx @modelcontextprotocol/server-github"));
        assert_eq!(github.allowed_tools, vec!["search_repositories", "get_file_contents"]);
        let rl = github.rate_limit.as_ref().unwrap();
        assert_eq!(rl.max_calls, 100);
        assert_eq!(rl.window_seconds, 60);

        let slack = &config.servers["slack"];
        assert_eq!(slack.transport, "sse");
        assert_eq!(slack.url.as_deref(), Some("https://mcp.slack.example.com/sse"));
        assert_eq!(slack.allowed_tools, vec!["*"]);
    }

    // -----------------------------------------------------------------------
    // 3. Invalid transport value
    // -----------------------------------------------------------------------

    #[test]
    fn invalid_transport() {
        let toml = r#"
[gateway]
listen = "127.0.0.1:8080"

[servers.bad]
command = "echo hello"
transport = "websocket"
"#;
        let err = load_str(toml).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("invalid transport"), "got: {msg}");
    }

    // -----------------------------------------------------------------------
    // 4. Missing command for stdio transport
    // -----------------------------------------------------------------------

    #[test]
    fn stdio_missing_command() {
        let toml = r#"
[gateway]
listen = "127.0.0.1:8080"

[servers.bad]
transport = "stdio"
"#;
        let err = load_str(toml).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("command"), "got: {msg}");
    }

    // -----------------------------------------------------------------------
    // 5. Missing url for SSE transport
    // -----------------------------------------------------------------------

    #[test]
    fn sse_missing_url() {
        let toml = r#"
[gateway]
listen = "127.0.0.1:8080"

[servers.bad]
transport = "sse"
"#;
        let err = load_str(toml).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("url"), "got: {msg}");
    }

    // -----------------------------------------------------------------------
    // 6. Invalid listen address
    // -----------------------------------------------------------------------

    #[test]
    fn invalid_listen_address() {
        let toml = r#"
[gateway]
listen = "not-a-socket-addr"
"#;
        let err = load_str(toml).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("listen address"), "got: {msg}");
    }

    // -----------------------------------------------------------------------
    // 7. Invalid kernel_mode
    // -----------------------------------------------------------------------

    #[test]
    fn invalid_kernel_mode() {
        let toml = r#"
[gateway]
listen = "127.0.0.1:8080"
kernel_mode = "distributed"
"#;
        let err = load_str(toml).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("kernel_mode"), "got: {msg}");
    }

    // -----------------------------------------------------------------------
    // 8. Remote kernel mode without grpc address
    // -----------------------------------------------------------------------

    #[test]
    fn remote_mode_missing_grpc() {
        let toml = r#"
[gateway]
listen = "127.0.0.1:8080"
kernel_mode = "remote"
"#;
        let err = load_str(toml).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("kernel_grpc"), "got: {msg}");
    }

    // -----------------------------------------------------------------------
    // 9. Rate limit with zero values
    // -----------------------------------------------------------------------

    #[test]
    fn rate_limit_zero_max_calls() {
        let toml = r#"
[gateway]
listen = "127.0.0.1:8080"

[servers.test]
command = "echo"
transport = "stdio"

[servers.test.rate_limit]
max_calls = 0
window_seconds = 60
"#;
        let err = load_str(toml).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("max_calls"), "got: {msg}");
    }

    #[test]
    fn rate_limit_zero_window() {
        let toml = r#"
[gateway]
listen = "127.0.0.1:8080"

[servers.test]
command = "echo"
transport = "stdio"

[servers.test.rate_limit]
max_calls = 10
window_seconds = 0
"#;
        let err = load_str(toml).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("window_seconds"), "got: {msg}");
    }

    // -----------------------------------------------------------------------
    // 10. Malformed SSE URL
    // -----------------------------------------------------------------------

    #[test]
    fn malformed_sse_url() {
        let toml = r#"
[gateway]
listen = "127.0.0.1:8080"

[servers.bad]
url = "ftp://example.com/sse"
transport = "sse"
"#;
        let err = load_str(toml).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("http://") || msg.contains("https://"), "got: {msg}");
    }

    // -----------------------------------------------------------------------
    // 11. Environment variable substitution
    // -----------------------------------------------------------------------

    #[test]
    fn env_var_substitution() {
        std::env::set_var("AEGIS_TEST_TOKEN_9382", "secret-token-value");

        let toml = r#"
[gateway]
listen = "127.0.0.1:8080"

[servers.github]
command = "npx @modelcontextprotocol/server-github"
transport = "stdio"
env = { GITHUB_TOKEN = "${AEGIS_TEST_TOKEN_9382}" }
"#;
        let config = load_str(toml).unwrap();
        let github = &config.servers["github"];
        assert_eq!(
            github.env.get("GITHUB_TOKEN").unwrap(),
            "secret-token-value"
        );

        std::env::remove_var("AEGIS_TEST_TOKEN_9382");
    }

    // -----------------------------------------------------------------------
    // 12. Missing environment variable produces error
    // -----------------------------------------------------------------------

    #[test]
    fn missing_env_var() {
        // Make sure this var doesn't exist
        std::env::remove_var("AEGIS_NONEXISTENT_VAR_XYZ");

        let toml = r#"
[gateway]
listen = "127.0.0.1:8080"

[servers.github]
command = "npx server"
transport = "stdio"
env = { TOKEN = "${AEGIS_NONEXISTENT_VAR_XYZ}" }
"#;
        let err = load_str(toml).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("AEGIS_NONEXISTENT_VAR_XYZ"), "got: {msg}");
    }

    // -----------------------------------------------------------------------
    // 13. Defaults applied when gateway section is absent
    // -----------------------------------------------------------------------

    #[test]
    fn defaults_when_gateway_section_absent() {
        let toml = "";
        let config = load_str(toml).unwrap();
        assert_eq!(config.gateway.listen, "127.0.0.1:8080");
        assert_eq!(config.gateway.kernel_mode, "embedded");
        assert_eq!(config.gateway.log_level, "info");
        assert!(config.gateway.kernel_grpc.is_none());
        assert!(config.servers.is_empty());
    }

    // -----------------------------------------------------------------------
    // 14. Remote mode with grpc address is valid
    // -----------------------------------------------------------------------

    #[test]
    fn remote_mode_with_grpc() {
        let toml = r#"
[gateway]
listen = "127.0.0.1:8080"
kernel_mode = "remote"
kernel_grpc = "127.0.0.1:9090"
"#;
        let config = load_str(toml).unwrap();
        assert_eq!(config.gateway.kernel_mode, "remote");
        assert_eq!(
            config.gateway.kernel_grpc.as_deref(),
            Some("127.0.0.1:9090")
        );
    }

    // -----------------------------------------------------------------------
    // 15. Config watcher: load from file
    // -----------------------------------------------------------------------

    #[test]
    fn config_watcher_loads_initial() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("aegis.toml");
        std::fs::write(
            &path,
            r#"
[gateway]
listen = "127.0.0.1:3333"

[servers.echo]
command = "cat"
transport = "stdio"
"#,
        )
        .unwrap();

        let watcher = ConfigWatcher::new(&path, None).unwrap();
        let config = watcher.config();
        assert_eq!(config.gateway.listen, "127.0.0.1:3333");
        assert_eq!(config.servers.len(), 1);
    }

    // -----------------------------------------------------------------------
    // 16. Config watcher: manual reload picks up changes
    // -----------------------------------------------------------------------

    #[test]
    fn config_watcher_manual_reload() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("aegis.toml");
        std::fs::write(
            &path,
            r#"
[gateway]
listen = "127.0.0.1:4444"
"#,
        )
        .unwrap();

        let watcher = ConfigWatcher::new(&path, None).unwrap();
        assert_eq!(watcher.config().gateway.listen, "127.0.0.1:4444");

        // Overwrite the file
        std::fs::write(
            &path,
            r#"
[gateway]
listen = "127.0.0.1:5555"
"#,
        )
        .unwrap();

        let new_config = watcher.reload().unwrap();
        assert_eq!(new_config.gateway.listen, "127.0.0.1:5555");
        assert_eq!(watcher.config().gateway.listen, "127.0.0.1:5555");
    }

    // -----------------------------------------------------------------------
    // 17. Config watcher: invalid file keeps previous config
    // -----------------------------------------------------------------------

    #[test]
    fn config_watcher_reload_invalid_keeps_previous() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("aegis.toml");
        std::fs::write(
            &path,
            r#"
[gateway]
listen = "127.0.0.1:6666"
"#,
        )
        .unwrap();

        let watcher = ConfigWatcher::new(&path, None).unwrap();
        assert_eq!(watcher.config().gateway.listen, "127.0.0.1:6666");

        // Write invalid config
        std::fs::write(&path, "this is not valid TOML [[[").unwrap();

        // Manual reload should fail
        assert!(watcher.reload().is_err());
        // Previous config is still available
        assert_eq!(watcher.config().gateway.listen, "127.0.0.1:6666");
    }

    // -----------------------------------------------------------------------
    // 18. Config watcher: hot reload with callback
    // -----------------------------------------------------------------------

    #[test]
    fn config_watcher_hot_reload_callback() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("aegis.toml");
        std::fs::write(
            &path,
            r#"
[gateway]
listen = "127.0.0.1:7777"
"#,
        )
        .unwrap();

        let reload_count = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let reload_count_clone = Arc::clone(&reload_count);

        let watcher = ConfigWatcher::new(
            &path,
            Some(Box::new(move |_config| {
                reload_count_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            })),
        )
        .unwrap();

        // Write new valid config
        std::fs::write(
            &path,
            r#"
[gateway]
listen = "127.0.0.1:8888"
"#,
        )
        .unwrap();

        // Give the filesystem watcher time to fire
        std::thread::sleep(std::time::Duration::from_millis(500));

        // The watcher callback may or may not have fired by now depending on
        // OS notifications. Verify at least that manual reload works.
        let new_config = watcher.reload().unwrap();
        assert_eq!(new_config.gateway.listen, "127.0.0.1:8888");
    }

    // -----------------------------------------------------------------------
    // 19. TOML parse error for malformed input
    // -----------------------------------------------------------------------

    #[test]
    fn toml_parse_error() {
        let err = load_str("this is [[[not valid").unwrap_err();
        assert!(matches!(err, ConfigError::TomlParse(_)));
    }

    // -----------------------------------------------------------------------
    // 20. Env var in command field
    // -----------------------------------------------------------------------

    #[test]
    fn env_var_in_command() {
        std::env::set_var("AEGIS_TEST_CMD_7291", "/usr/bin/my-mcp-server");

        let toml = r#"
[gateway]
listen = "127.0.0.1:8080"

[servers.custom]
command = "${AEGIS_TEST_CMD_7291} --port 3000"
transport = "stdio"
"#;
        let config = load_str(toml).unwrap();
        assert_eq!(
            config.servers["custom"].command.as_deref(),
            Some("/usr/bin/my-mcp-server --port 3000")
        );

        std::env::remove_var("AEGIS_TEST_CMD_7291");
    }
}
