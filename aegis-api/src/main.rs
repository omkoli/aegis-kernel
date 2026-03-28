use aegis_api::{routes::router, state::AppState};

#[tokio::main]
async fn main() {
    let state = AppState::new();
    let app = router(state);

    let addr = "0.0.0.0:3000";
    println!("Aegis API server listening on http://{addr}");
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
