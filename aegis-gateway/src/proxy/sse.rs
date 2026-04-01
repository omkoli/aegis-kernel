//! SSE transport proxy for MCP servers.
//!
//! The proxy sits between MCP clients (AI agents) and a remote MCP server
//! that speaks the SSE transport:
//!
//! ```text
//! Agent ──POST /message──▶ [Aegis SSE Proxy] ──POST──▶ Remote MCP Server
//! Agent ◀──GET /sse (SSE)── [Aegis SSE Proxy] ◀──SSE──── Remote MCP Server
//! ```
//!
//! ## MCP SSE transport protocol
//!
//! 1. Client opens `GET /sse` → server responds with an SSE stream.
//! 2. First event is `event: endpoint\ndata: /message?sessionId=xxx`.
//! 3. Client sends JSON-RPC requests via `POST` to that endpoint.
//! 4. Server sends JSON-RPC responses/notifications back on the SSE stream.
//!
//! ## Proxy behaviour
//!
//! - **Downstream** (hyper HTTP server): accepts agent connections on a
//!   configurable port. Serves `GET /sse` (SSE stream) and `POST /message`
//!   (JSON-RPC relay).
//! - **Upstream** (reqwest HTTP client): maintains a persistent SSE connection
//!   to the real MCP server and forwards POST requests to it.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use futures_util::StreamExt;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::server::conn::http1;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::sync::{broadcast, Notify};
use tokio_stream::wrappers::BroadcastStream;
use tracing;

use super::middleware::{block_response, InterceptionMiddleware, InterceptionResult};

/// Errors from the SSE proxy.
#[derive(Debug, Error)]
pub enum SseProxyError {
    #[error("failed to bind listener: {0}")]
    Bind(#[source] std::io::Error),

    #[error("upstream connection failed: {0}")]
    UpstreamConnect(#[source] reqwest::Error),

    #[error("upstream SSE stream error: {0}")]
    UpstreamStream(#[source] reqwest::Error),

    #[error("upstream POST failed: {0}")]
    UpstreamPost(#[source] reqwest::Error),

    #[error("upstream returned non-success status: {0}")]
    UpstreamStatus(StatusCode),

    #[error("no endpoint event received from upstream")]
    NoEndpoint,

    #[error("hyper error: {0}")]
    Hyper(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("I/O error: {0}")]
    Io(#[source] std::io::Error),

    #[error("proxy shut down")]
    Shutdown,

    #[error("MCP parse error: {0}")]
    McpParse(#[from] aegis_mcp::McpError),

    #[error("MCP serialization error: {0}")]
    McpSerialize(String),
}

pub type Result<T> = std::result::Result<T, SseProxyError>;

/// Configuration for the SSE proxy.
#[derive(Debug, Clone)]
pub struct SseProxyConfig {
    /// The address to listen on for downstream agent connections.
    /// Defaults to `0.0.0.0:8080`.
    pub listen_addr: SocketAddr,

    /// The base URL of the upstream MCP server SSE endpoint.
    /// Example: `http://localhost:3001/sse`
    pub upstream_url: String,
}

impl Default for SseProxyConfig {
    fn default() -> Self {
        Self {
            listen_addr: ([0, 0, 0, 0], 8080).into(),
            upstream_url: String::new(),
        }
    }
}

/// Shared state between the proxy tasks and HTTP handlers.
struct ProxyState {
    /// The upstream base URL (without /sse path, e.g. `http://localhost:3001`).
    upstream_base: String,

    /// The upstream POST endpoint path received from the `endpoint` SSE event.
    /// e.g. `/message?sessionId=abc123`
    upstream_post_path: tokio::sync::RwLock<Option<String>>,

    /// Broadcast channel for SSE events flowing from upstream to downstream agents.
    /// Each agent's GET /sse handler subscribes to this channel.
    sse_tx: broadcast::Sender<Bytes>,

    /// HTTP client for upstream requests.
    client: reqwest::Client,

    /// Notifies waiting downstream handlers that the upstream endpoint is ready.
    endpoint_ready: Notify,

    /// Optional middleware for intercepting messages.
    middleware: Option<Arc<dyn InterceptionMiddleware>>,
}

/// An SSE transport proxy for MCP servers.
///
/// Listens for agent connections on a downstream HTTP port and maintains
/// a persistent SSE connection to the upstream MCP server. JSON-RPC POST
/// requests from agents are forwarded upstream, and SSE events from
/// upstream are broadcast to all connected agents.
pub struct SseProxy {
    config: SseProxyConfig,
    middleware: Option<Arc<dyn InterceptionMiddleware>>,
}

impl SseProxy {
    pub fn new(config: SseProxyConfig) -> Self {
        Self {
            config,
            middleware: None,
        }
    }

    /// Attach an interception middleware to the proxy.
    pub fn with_middleware(mut self, middleware: Arc<dyn InterceptionMiddleware>) -> Self {
        self.middleware = Some(middleware);
        self
    }

    /// Run the proxy until the provided shutdown signal fires.
    ///
    /// This spawns two concurrent tasks:
    /// - **Upstream listener**: connects to the remote MCP server's SSE endpoint
    ///   and broadcasts events to downstream agents.
    /// - **Downstream server**: accepts HTTP connections from agents, serving
    ///   `GET /sse` (SSE stream) and `POST /message` (JSON-RPC relay).
    pub async fn run(&self, shutdown: tokio::sync::watch::Receiver<()>) -> Result<()> {
        let (sse_tx, _) = broadcast::channel::<Bytes>(256);

        // Derive the upstream base URL by stripping the path from the configured URL.
        let upstream_base = self.upstream_base_url();

        let state = Arc::new(ProxyState {
            upstream_base,
            upstream_post_path: tokio::sync::RwLock::new(None),
            sse_tx,
            client: reqwest::Client::new(),
            endpoint_ready: Notify::new(),
            middleware: self.middleware.clone(),
        });

        let upstream_state = Arc::clone(&state);
        let upstream_url = self.config.upstream_url.clone();
        let mut upstream_shutdown = shutdown.clone();

        // Spawn upstream SSE listener
        let upstream_handle = tokio::spawn(async move {
            Self::upstream_listener(upstream_state, &upstream_url, &mut upstream_shutdown).await
        });

        // Run downstream HTTP server
        let downstream_result = self
            .downstream_server(Arc::clone(&state), shutdown)
            .await;

        // If downstream exits, abort upstream too
        upstream_handle.abort();
        let _ = upstream_handle.await;

        downstream_result
    }

    /// Run the proxy and return the actual listening address.
    ///
    /// Useful for tests where you bind to port 0 and need to know the
    /// assigned port.
    pub async fn run_with_addr(
        &self,
        shutdown: tokio::sync::watch::Receiver<()>,
    ) -> Result<(SocketAddr, tokio::task::JoinHandle<Result<()>>)> {
        let (sse_tx, _) = broadcast::channel::<Bytes>(256);
        let upstream_base = self.upstream_base_url();

        let state = Arc::new(ProxyState {
            upstream_base,
            upstream_post_path: tokio::sync::RwLock::new(None),
            sse_tx,
            client: reqwest::Client::new(),
            endpoint_ready: Notify::new(),
            middleware: self.middleware.clone(),
        });

        let listener = TcpListener::bind(self.config.listen_addr)
            .await
            .map_err(SseProxyError::Bind)?;
        let local_addr = listener.local_addr().map_err(SseProxyError::Io)?;

        let upstream_state = Arc::clone(&state);
        let upstream_url = self.config.upstream_url.clone();
        let mut upstream_shutdown = shutdown.clone();

        tokio::spawn(async move {
            Self::upstream_listener(upstream_state, &upstream_url, &mut upstream_shutdown).await
        });

        let server_state = Arc::clone(&state);
        let handle = tokio::spawn(async move {
            Self::accept_loop(listener, server_state, shutdown).await
        });

        Ok((local_addr, handle))
    }

    /// Derive the base URL (scheme + host + port) from the configured upstream URL.
    fn upstream_base_url(&self) -> String {
        // Parse out the scheme://host:port portion
        if let Some(idx) = self.config.upstream_url.find("://") {
            let after_scheme = &self.config.upstream_url[idx + 3..];
            if let Some(path_idx) = after_scheme.find('/') {
                return self.config.upstream_url[..idx + 3 + path_idx].to_string();
            }
        }
        self.config.upstream_url.clone()
    }

    // -----------------------------------------------------------------------
    // Upstream SSE listener
    // -----------------------------------------------------------------------

    async fn upstream_listener(
        state: Arc<ProxyState>,
        url: &str,
        shutdown: &mut tokio::sync::watch::Receiver<()>,
    ) -> Result<()> {
        tracing::info!("connecting to upstream SSE: {}", url);

        let response = state
            .client
            .get(url)
            .send()
            .await
            .map_err(SseProxyError::UpstreamConnect)?;

        if !response.status().is_success() {
            return Err(SseProxyError::UpstreamStatus(
                StatusCode::from_u16(response.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY),
            ));
        }

        let mut stream = response.bytes_stream();
        let mut buf = String::new();

        loop {
            tokio::select! {
                chunk = stream.next() => {
                    let chunk = match chunk {
                        Some(Ok(c)) => c,
                        Some(Err(e)) => return Err(SseProxyError::UpstreamStream(e)),
                        None => break, // stream ended
                    };

                    let text = String::from_utf8_lossy(&chunk);
                    buf.push_str(&text);

                    // Process complete SSE events (terminated by blank lines)
                    while let Some(event_end) = buf.find("\n\n") {
                        let event_block = buf[..event_end].to_string();
                        buf = buf[event_end + 2..].to_string();

                        Self::process_upstream_event(&state, &event_block).await;
                    }
                    // Also handle \r\n\r\n
                    while let Some(event_end) = buf.find("\r\n\r\n") {
                        let event_block = buf[..event_end].to_string();
                        buf = buf[event_end + 4..].to_string();

                        Self::process_upstream_event(&state, &event_block).await;
                    }
                }
                _ = shutdown.changed() => {
                    tracing::info!("upstream listener shutting down");
                    break;
                }
            }
        }

        Ok(())
    }

    /// Process a single SSE event block from the upstream server.
    async fn process_upstream_event(state: &ProxyState, event_block: &str) {
        let mut event_type = None;
        let mut data_lines = Vec::new();

        for line in event_block.lines() {
            let line = line.trim_end_matches('\r');
            if let Some(val) = line.strip_prefix("event:") {
                event_type = Some(val.trim().to_string());
            } else if let Some(val) = line.strip_prefix("data:") {
                data_lines.push(val.strip_prefix(' ').unwrap_or(val).to_string());
            }
        }

        let data = data_lines.join("\n");

        match event_type.as_deref() {
            Some("endpoint") => {
                // The upstream tells us where to POST messages.
                tracing::info!("upstream endpoint: {}", data);
                let mut path = state.upstream_post_path.write().await;
                *path = Some(data);
                state.endpoint_ready.notify_waiters();
            }
            _ => {
                // Run through middleware if present and data looks like JSON-RPC
                let final_data = if let Some(ref mw) = state.middleware {
                    if let Ok(message) = aegis_mcp::parse_message(data.as_bytes()) {
                        match mw.on_response(message) {
                            InterceptionResult::Forward(msg)
                            | InterceptionResult::Modify(msg) => {
                                match msg.to_json_bytes() {
                                    Ok(bytes) => {
                                        Some(String::from_utf8_lossy(&bytes).into_owned())
                                    }
                                    Err(_) => Some(data.clone()),
                                }
                            }
                            InterceptionResult::Block(_) => {
                                // Drop the event entirely
                                None
                            }
                        }
                    } else {
                        // Not valid JSON-RPC — forward as-is
                        Some(data.clone())
                    }
                } else {
                    Some(data.clone())
                };

                if let Some(final_data) = final_data {
                    // Reconstruct the SSE wire format.
                    let mut sse_bytes = String::new();
                    if let Some(ref et) = event_type {
                        sse_bytes.push_str(&format!("event: {}\n", et));
                    }
                    sse_bytes.push_str(&format!("data: {}\n", final_data));
                    sse_bytes.push('\n');

                    let _ = state.sse_tx.send(Bytes::from(sse_bytes));
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Downstream HTTP server
    // -----------------------------------------------------------------------

    async fn downstream_server(
        &self,
        state: Arc<ProxyState>,
        shutdown: tokio::sync::watch::Receiver<()>,
    ) -> Result<()> {
        let listener = TcpListener::bind(self.config.listen_addr)
            .await
            .map_err(SseProxyError::Bind)?;

        tracing::info!("SSE proxy listening on {}", self.config.listen_addr);

        Self::accept_loop(listener, state, shutdown).await
    }

    async fn accept_loop(
        listener: TcpListener,
        state: Arc<ProxyState>,
        mut shutdown: tokio::sync::watch::Receiver<()>,
    ) -> Result<()> {
        loop {
            tokio::select! {
                accept = listener.accept() => {
                    let (stream, _addr) = accept.map_err(SseProxyError::Io)?;
                    let io = TokioIo::new(stream);
                    let state = Arc::clone(&state);

                    tokio::spawn(async move {
                        let service = hyper::service::service_fn(move |req| {
                            let state = Arc::clone(&state);
                            async move { Self::handle_request(state, req).await }
                        });

                        if let Err(e) = http1::Builder::new()
                            .serve_connection(io, service)
                            .with_upgrades()
                            .await
                        {
                            tracing::error!("connection error: {}", e);
                        }
                    });
                }
                _ = shutdown.changed() => {
                    tracing::info!("downstream server shutting down");
                    break;
                }
            }
        }

        Ok(())
    }

    /// Route incoming requests to the appropriate handler.
    async fn handle_request(
        state: Arc<ProxyState>,
        req: Request<Incoming>,
    ) -> std::result::Result<Response<BoxBody>, Infallible> {
        let response = match (req.method(), req.uri().path()) {
            (&Method::GET, "/sse") => Self::handle_sse(state).await,
            (&Method::POST, "/message") => Self::handle_post(state, req).await,
            _ => Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(full_body(Bytes::from("Not Found")))
                .unwrap()),
        };

        Ok(response.unwrap_or_else(|e| {
            tracing::error!("handler error: {}", e);
            Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(full_body(Bytes::from(format!("Proxy error: {}", e))))
                .unwrap()
        }))
    }

    /// Handle `GET /sse` — subscribe the agent to the SSE event stream.
    ///
    /// First sends an `event: endpoint` with the local POST path, then
    /// streams events received from upstream.
    async fn handle_sse(state: Arc<ProxyState>) -> Result<Response<BoxBody>> {
        let rx = state.sse_tx.subscribe();

        // Build the initial endpoint event pointing agents to our /message path
        let endpoint_event = Bytes::from("event: endpoint\ndata: /message\n\n");

        // Create a stream: first the endpoint event, then broadcast events
        let initial = futures_util::stream::once(async move {
            Ok::<_, Infallible>(Frame::data(endpoint_event))
        });

        let events = BroadcastStream::new(rx).filter_map(|item| async move {
            match item {
                Ok(bytes) => Some(Ok::<_, Infallible>(Frame::data(bytes))),
                Err(_) => None, // lagged — skip
            }
        });

        let body_stream = initial.chain(events);
        let body = StreamBody::new(body_stream);

        let response = Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "text/event-stream")
            .header("Cache-Control", "no-cache")
            .header("Connection", "keep-alive")
            .header("Access-Control-Allow-Origin", "*")
            .body(BoxBody::new(body))
            .unwrap();

        Ok(response)
    }

    /// Handle `POST /message` — forward the agent's JSON-RPC request upstream.
    async fn handle_post(
        state: Arc<ProxyState>,
        req: Request<Incoming>,
    ) -> Result<Response<BoxBody>> {
        // Wait for the upstream endpoint to be available
        let post_url = {
            let path = state.upstream_post_path.read().await;
            match path.as_ref() {
                Some(p) => format!("{}{}", state.upstream_base, p),
                None => {
                    drop(path);
                    // Wait up to 10 seconds for the endpoint
                    tokio::select! {
                        _ = state.endpoint_ready.notified() => {}
                        _ = tokio::time::sleep(std::time::Duration::from_secs(10)) => {
                            return Err(SseProxyError::NoEndpoint);
                        }
                    }
                    let path = state.upstream_post_path.read().await;
                    match path.as_ref() {
                        Some(p) => format!("{}{}", state.upstream_base, p),
                        None => return Err(SseProxyError::NoEndpoint),
                    }
                }
            }
        };

        // Read the incoming body
        let body_bytes = req
            .collect()
            .await
            .map_err(|e| SseProxyError::Hyper(Box::new(e)))?
            .to_bytes();

        // Run through middleware if present
        let forward_bytes = if let Some(ref mw) = state.middleware {
            let message = aegis_mcp::parse_message(&body_bytes)
                .map_err(SseProxyError::McpParse)?;
            match mw.on_request(message) {
                InterceptionResult::Forward(msg) | InterceptionResult::Modify(msg) => {
                    let serialized = msg
                        .to_json_bytes()
                        .map_err(|e| SseProxyError::McpSerialize(e.to_string()))?;
                    serialized
                }
                InterceptionResult::Block(error) => {
                    // Re-parse to get the original message for building a response
                    let original = aegis_mcp::parse_message(&body_bytes)
                        .map_err(SseProxyError::McpParse)?;
                    if let Some(err_resp) = block_response(&original, error) {
                        let err_bytes = err_resp
                            .to_json_bytes()
                            .map_err(|e| SseProxyError::McpSerialize(e.to_string()))?;
                        let response = Response::builder()
                            .status(StatusCode::OK)
                            .header("Content-Type", "application/json")
                            .body(full_body(Bytes::from(err_bytes)))
                            .unwrap();
                        return Ok(response);
                    }
                    // Notification blocked — return 202 Accepted (nothing to respond with)
                    let response = Response::builder()
                        .status(StatusCode::ACCEPTED)
                        .body(full_body(Bytes::new()))
                        .unwrap();
                    return Ok(response);
                }
            }
        } else {
            body_bytes.to_vec()
        };

        tracing::debug!(
            "forwarding POST to upstream: {} ({} bytes)",
            post_url,
            forward_bytes.len()
        );

        // Forward to upstream
        let upstream_resp = state
            .client
            .post(&post_url)
            .header("Content-Type", "application/json")
            .body(forward_bytes)
            .send()
            .await
            .map_err(SseProxyError::UpstreamPost)?;

        let status =
            StatusCode::from_u16(upstream_resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
        let resp_body = upstream_resp
            .bytes()
            .await
            .map_err(SseProxyError::UpstreamPost)?;

        let response = Response::builder()
            .status(status)
            .header("Content-Type", "application/json")
            .body(full_body(resp_body))
            .unwrap();

        Ok(response)
    }
}

// ---------------------------------------------------------------------------
// Body helpers
// ---------------------------------------------------------------------------

type BoxBody = http_body_util::combinators::BoxBody<Bytes, Infallible>;

fn full_body(bytes: Bytes) -> BoxBody {
    BoxBody::new(Full::new(bytes).map_err(|never| match never {}))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::watch;

    #[test]
    fn default_config_listen_addr() {
        let config = SseProxyConfig::default();
        assert_eq!(config.listen_addr, SocketAddr::from(([0, 0, 0, 0], 8080)));
    }

    #[test]
    fn upstream_base_url_parsing() {
        let proxy = SseProxy::new(SseProxyConfig {
            listen_addr: ([127, 0, 0, 1], 0).into(),
            upstream_url: "http://localhost:3001/sse".to_string(),
        });
        assert_eq!(proxy.upstream_base_url(), "http://localhost:3001");

        let proxy2 = SseProxy::new(SseProxyConfig {
            listen_addr: ([127, 0, 0, 1], 0).into(),
            upstream_url: "https://example.com:8443/v1/sse".to_string(),
        });
        assert_eq!(proxy2.upstream_base_url(), "https://example.com:8443");

        let proxy3 = SseProxy::new(SseProxyConfig {
            listen_addr: ([127, 0, 0, 1], 0).into(),
            upstream_url: "http://localhost:3001".to_string(),
        });
        assert_eq!(proxy3.upstream_base_url(), "http://localhost:3001");
    }

    /// Test that the proxy starts, binds to a port, and shuts down cleanly.
    #[tokio::test]
    async fn proxy_starts_and_shuts_down() {
        let (shutdown_tx, shutdown_rx) = watch::channel(());
        let config = SseProxyConfig {
            listen_addr: ([127, 0, 0, 1], 0).into(),
            upstream_url: "http://127.0.0.1:1/sse".to_string(), // won't connect
        };
        let proxy = SseProxy::new(config);

        let (addr, handle) = proxy.run_with_addr(shutdown_rx).await.unwrap();
        assert_ne!(addr.port(), 0);

        // Shut it down
        let _ = shutdown_tx.send(());
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;
    }

    /// Test that GET /sse returns the correct content type and an endpoint event.
    #[tokio::test]
    async fn sse_endpoint_returns_event_stream() {
        let (shutdown_tx, shutdown_rx) = watch::channel(());
        let config = SseProxyConfig {
            listen_addr: ([127, 0, 0, 1], 0).into(),
            upstream_url: "http://127.0.0.1:1/sse".to_string(),
        };
        let proxy = SseProxy::new(config);

        let (addr, handle) = proxy.run_with_addr(shutdown_rx).await.unwrap();

        let client = reqwest::Client::builder()
            .no_proxy()
            .build()
            .unwrap();

        let resp = client
            .get(format!("http://127.0.0.1:{}/sse", addr.port()))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), 200);
        assert_eq!(
            resp.headers()
                .get("content-type")
                .unwrap()
                .to_str()
                .unwrap(),
            "text/event-stream"
        );

        // Read the first chunk — should contain the endpoint event
        let mut stream = resp.bytes_stream();
        let first_chunk = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            stream.next(),
        )
        .await
        .unwrap()
        .unwrap()
        .unwrap();

        let text = String::from_utf8_lossy(&first_chunk);
        assert!(
            text.contains("event: endpoint"),
            "expected endpoint event, got: {}",
            text
        );
        assert!(
            text.contains("data: /message"),
            "expected /message in endpoint data, got: {}",
            text
        );

        let _ = shutdown_tx.send(());
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;
    }

    /// Test that POST /message before upstream is ready returns an error.
    #[tokio::test]
    async fn post_without_upstream_returns_error() {
        let (shutdown_tx, shutdown_rx) = watch::channel(());
        let config = SseProxyConfig {
            listen_addr: ([127, 0, 0, 1], 0).into(),
            upstream_url: "http://127.0.0.1:1/sse".to_string(),
        };
        let proxy = SseProxy::new(config);

        let (addr, handle) = proxy.run_with_addr(shutdown_rx).await.unwrap();

        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .unwrap();

        let resp = client
            .post(format!("http://127.0.0.1:{}/message", addr.port()))
            .header("Content-Type", "application/json")
            .body(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#)
            .send()
            .await
            .unwrap();

        // Should get 502 because upstream endpoint was never received
        assert_eq!(resp.status(), 502);

        let _ = shutdown_tx.send(());
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;
    }

    /// Test that unknown routes return 404.
    #[tokio::test]
    async fn unknown_route_returns_404() {
        let (shutdown_tx, shutdown_rx) = watch::channel(());
        let config = SseProxyConfig {
            listen_addr: ([127, 0, 0, 1], 0).into(),
            upstream_url: "http://127.0.0.1:1/sse".to_string(),
        };
        let proxy = SseProxy::new(config);

        let (addr, handle) = proxy.run_with_addr(shutdown_rx).await.unwrap();

        let client = reqwest::Client::builder()
            .no_proxy()
            .build()
            .unwrap();

        let resp = client
            .get(format!("http://127.0.0.1:{}/unknown", addr.port()))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), 404);

        let _ = shutdown_tx.send(());
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;
    }

    /// Integration test: mock an upstream MCP SSE server and run a full round-trip.
    #[tokio::test]
    async fn full_roundtrip_with_mock_upstream() {
        // --- Start a mock upstream MCP server ---
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();

        let mock_handle = tokio::spawn(async move {
            // Accept one connection for SSE and potentially multiple for POSTs
            loop {
                let (stream, _) = upstream_listener.accept().await.unwrap();
                let io = TokioIo::new(stream);

                tokio::spawn(async move {
                    let service = hyper::service::service_fn(|req: Request<Incoming>| async move {
                        match (req.method().clone(), req.uri().path().to_string().as_str()) {
                            (Method::GET, "/sse") => {
                                // Send endpoint event, then echo any messages as SSE
                                let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(16);

                                // Send the endpoint event
                                let endpoint_event = Bytes::from(
                                    "event: endpoint\ndata: /message?sessionId=test-123\n\n",
                                );
                                tx.send(endpoint_event).await.unwrap();

                                // Keep sending keepalive to keep the connection open
                                tokio::spawn(async move {
                                    loop {
                                        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                                        if tx.send(Bytes::from(": keepalive\n\n")).await.is_err() {
                                            break;
                                        }
                                    }
                                });

                                let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
                                let body = StreamBody::new(
                                    stream.map(|b| Ok::<_, Infallible>(Frame::data(b))),
                                );

                                Ok::<_, Infallible>(
                                    Response::builder()
                                        .status(200)
                                        .header("Content-Type", "text/event-stream")
                                        .body(BoxBody::new(body))
                                        .unwrap(),
                                )
                            }
                            (Method::POST, path) if path.starts_with("/message") => {
                                let body = req.collect().await.unwrap().to_bytes();
                                let body_str = String::from_utf8_lossy(&body);

                                // Parse the request and respond
                                let response_json = if body_str.contains("\"method\":\"initialize\"")
                                    || body_str.contains("\"method\": \"initialize\"")
                                {
                                    // Return accepted status for initialize
                                    serde_json::json!({
                                        "jsonrpc": "2.0",
                                        "id": 1,
                                        "result": {
                                            "protocolVersion": "2024-11-05",
                                            "serverInfo": {
                                                "name": "mock-sse-server",
                                                "version": "0.1.0"
                                            },
                                            "capabilities": {"tools": {}}
                                        }
                                    })
                                } else {
                                    serde_json::json!({
                                        "jsonrpc": "2.0",
                                        "id": 1,
                                        "result": {}
                                    })
                                };

                                let resp_bytes =
                                    Bytes::from(serde_json::to_vec(&response_json).unwrap());

                                Ok::<_, Infallible>(
                                    Response::builder()
                                        .status(202)
                                        .header("Content-Type", "application/json")
                                        .body(full_body(resp_bytes))
                                        .unwrap(),
                                )
                            }
                            _ => Ok::<_, Infallible>(
                                Response::builder()
                                    .status(404)
                                    .body(full_body(Bytes::from("Not Found")))
                                    .unwrap(),
                            ),
                        }
                    });

                    let _ = http1::Builder::new()
                        .serve_connection(io, service)
                        .with_upgrades()
                        .await;
                });
            }
        });

        // --- Start the SSE proxy pointing at the mock upstream ---
        let (shutdown_tx, shutdown_rx) = watch::channel(());
        let config = SseProxyConfig {
            listen_addr: ([127, 0, 0, 1], 0).into(),
            upstream_url: format!("http://127.0.0.1:{}/sse", upstream_addr.port()),
        };
        let proxy = SseProxy::new(config);
        let (proxy_addr, proxy_handle) = proxy.run_with_addr(shutdown_rx).await.unwrap();

        // Give the proxy a moment to connect to upstream and receive the endpoint event
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        let client = reqwest::Client::builder()
            .no_proxy()
            .build()
            .unwrap();

        // --- Test GET /sse ---
        let sse_resp = client
            .get(format!("http://127.0.0.1:{}/sse", proxy_addr.port()))
            .send()
            .await
            .unwrap();

        assert_eq!(sse_resp.status(), 200);
        assert_eq!(
            sse_resp.headers().get("content-type").unwrap().to_str().unwrap(),
            "text/event-stream"
        );

        // --- Test POST /message ---
        let post_resp = client
            .post(format!("http://127.0.0.1:{}/message", proxy_addr.port()))
            .header("Content-Type", "application/json")
            .body(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}"#)
            .send()
            .await
            .unwrap();

        assert_eq!(post_resp.status(), 202);
        let resp_body: serde_json::Value = post_resp.json().await.unwrap();
        assert_eq!(resp_body["jsonrpc"], "2.0");
        assert_eq!(resp_body["result"]["serverInfo"]["name"], "mock-sse-server");

        // --- Cleanup ---
        let _ = shutdown_tx.send(());
        mock_handle.abort();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), proxy_handle).await;
    }
}
