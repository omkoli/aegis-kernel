use aegis_api::{routes::router, state::AppState};

#[tokio::main]
async fn main() {
    init_tracing();

    let state = AppState::new();
    let app = router(state);

    let addr = "0.0.0.0:3000";
    tracing::info!(addr, "Aegis API server starting");
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

/// Initialise the global tracing subscriber.
///
/// Output format is controlled by the `AEGIS_LOG_FORMAT` environment variable:
/// - `json`  → structured JSON lines (production / log aggregators)
/// - _(unset / anything else)_ → compact human-readable (development)
///
/// Filter is controlled by `RUST_LOG` (default: `aegis=info`).
fn init_tracing() {
    use tracing_subscriber::{fmt, EnvFilter};

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("aegis=info"));

    match std::env::var("AEGIS_LOG_FORMAT").as_deref() {
        Ok("json") => {
            fmt()
                .json()
                .with_env_filter(filter)
                .with_current_span(true)
                .with_span_list(true)
                .with_target(true)
                .with_file(false)
                .with_line_number(false)
                .init();
        }
        _ => {
            fmt()
                .with_env_filter(filter)
                .with_target(true)
                .with_thread_ids(false)
                .compact()
                .init();
        }
    }
}
