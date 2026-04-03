use std::time::Duration;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::Deserialize;
use uuid::Uuid;

use aegis_core::{
    DelegationRequest as CoreDelegationRequest, Resource, TokenRequest, TokenStore, ToolCallRequest,
};

use crate::convert::{
    audit_entry_to_response, parse_constraints, signed_token_to_response, string_to_action,
    AuditResponse, DelegateRequest, EnforceRequest, EnforceResponse, IssueRequest, RevokeResponse,
    TokenResponse,
};
use crate::state::AppState;

/// Builds the full axum Router with all management API routes.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/tokens", post(issue_token))
        .route("/tokens", get(list_tokens))
        .route("/tokens/{id}", get(get_token))
        .route("/tokens/{id}", delete(delete_token))
        .route("/tokens/{id}/revoke", post(revoke_token))
        .route("/enforce", post(enforce))
        .route("/delegate", post(delegate))
        .route("/audit", get(get_audit))
        .route("/audit/export", get(export_audit_jsonl))
        .route("/metrics", get(metrics_handler))
        .with_state(state)
}

/// POST /tokens — Issue a new capability token.
async fn issue_token(
    State(state): State<AppState>,
    Json(body): Json<IssueRequest>,
) -> Result<(StatusCode, Json<TokenResponse>), (StatusCode, Json<ErrorBody>)> {
    let resource = Resource::new(&body.resource).map_err(|e| bad_request(e.to_string()))?;
    let actions: Vec<_> = body.actions.iter().map(|a| string_to_action(a)).collect();
    let constraints = parse_constraints(&body.constraints).map_err(bad_request)?;

    let request = TokenRequest {
        subject: body.subject,
        resource,
        actions,
        constraints,
        ttl: body.ttl_secs.map(Duration::from_secs),
        delegatable: body.delegatable,
        max_uses: body.max_uses,
    };

    let signed = state
        .issuer
        .issue(request)
        .map_err(|e| bad_request(e.to_string()))?;
    metrics::gauge!("aegis_tokens_active").set(state.store.list().len() as f64);
    let response = signed_token_to_response(&signed);
    Ok((StatusCode::CREATED, Json(response)))
}

/// GET /tokens — List all tokens.
async fn list_tokens(State(state): State<AppState>) -> Json<Vec<TokenResponse>> {
    let tokens = state.store.list();
    Json(tokens.iter().map(signed_token_to_response).collect())
}

/// GET /tokens/:id — Get a token by ID.
async fn get_token(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<TokenResponse>, (StatusCode, Json<ErrorBody>)> {
    let signed = state
        .store
        .get(id)
        .map_err(|e: aegis_core::AegisError| not_found(e.to_string()))?;
    Ok(Json(signed_token_to_response(&signed)))
}

/// DELETE /tokens/:id — Delete a token by ID.
async fn delete_token(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<TokenResponse>, (StatusCode, Json<ErrorBody>)> {
    let signed = state
        .store
        .delete(id)
        .map_err(|e: aegis_core::AegisError| not_found(e.to_string()))?;
    metrics::gauge!("aegis_tokens_active").set(state.store.list().len() as f64);
    Ok(Json(signed_token_to_response(&signed)))
}

/// POST /tokens/:id/revoke — Revoke a token and all descendants.
async fn revoke_token(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<RevokeResponse>, (StatusCode, Json<ErrorBody>)> {
    let revoked_ids = state
        .delegation
        .revoke_cascade(id)
        .map_err(|e| bad_request(e.to_string()))?;
    metrics::gauge!("aegis_tokens_active").set(state.store.list().len() as f64);
    Ok(Json(RevokeResponse { revoked_ids }))
}

/// POST /enforce — Enforce a tool call request.
async fn enforce(
    State(state): State<AppState>,
    Json(body): Json<EnforceRequest>,
) -> Json<EnforceResponse> {
    let resource = Resource::new(&body.resource).unwrap_or_else(|_| {
        // For enforcement, pass through even invalid resources — the engine will deny
        Resource::new("invalid://").unwrap()
    });

    let call = ToolCallRequest {
        agent_id: body.agent_id,
        tool_name: body.tool_name,
        action: string_to_action(&body.action),
        resource,
        parameters: body.parameters,
        token_id: body.token_id,
    };

    let result = state.engine.enforce(&call);

    // Record audit
    state.audit_log.append(result.audit.clone());

    let audit = audit_entry_to_response(&result.audit);
    let decision = match result.decision {
        aegis_core::Decision::Allow => "allow",
        aegis_core::Decision::Deny => "deny",
    };

    Json(EnforceResponse {
        decision: decision.into(),
        audit,
    })
}

/// POST /delegate — Delegate a token.
async fn delegate(
    State(state): State<AppState>,
    Json(body): Json<DelegateRequest>,
) -> Result<(StatusCode, Json<TokenResponse>), (StatusCode, Json<ErrorBody>)> {
    let actions: Vec<_> = body.actions.iter().map(|a| string_to_action(a)).collect();
    let constraints = parse_constraints(&body.constraints).map_err(bad_request)?;

    let request = CoreDelegationRequest {
        parent_token_id: body.parent_token_id,
        new_subject: body.new_subject,
        actions,
        constraints,
        delegatable: body.delegatable,
        max_uses: body.max_uses,
        ttl_secs: body.ttl_secs,
    };

    let signed = state
        .delegation
        .delegate(request)
        .map_err(|e| bad_request(e.to_string()))?;
    let response = signed_token_to_response(&signed);
    Ok((StatusCode::CREATED, Json(response)))
}

/// Query params for GET /audit.
#[derive(Debug, Deserialize)]
pub struct HttpAuditQuery {
    pub token_id: Option<Uuid>,
    pub agent_id: Option<String>,
    pub tool_name: Option<String>,
    pub decision: Option<String>,
    pub resource_path: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

/// GET /audit — Query audit log.
async fn get_audit(
    State(state): State<AppState>,
    Query(query): Query<HttpAuditQuery>,
) -> Json<Vec<AuditResponse>> {
    let mut aq = aegis_audit::AuditQuery::new();
    if let Some(tid) = query.token_id {
        aq = aq.token(tid);
    }
    if let Some(ref aid) = query.agent_id {
        aq = aq.agent(aid);
    }
    if let Some(ref tool) = query.tool_name {
        aq = aq.tool(tool);
    }
    if let Some(ref d) = query.decision {
        match d.to_lowercase().as_str() {
            "allow" => aq = aq.decision(aegis_core::Decision::Allow),
            "deny" => aq = aq.decision(aegis_core::Decision::Deny),
            _ => {}
        }
    }
    if let Some(ref r) = query.resource_path {
        aq = aq.resource(r);
    }
    let limit = query.limit.unwrap_or(100);
    let offset = query.offset.unwrap_or(0);
    aq = aq.page(offset, limit);

    let page = state.audit_log.query(&aq);
    Json(page.entries.iter().map(audit_entry_to_response).collect())
}

/// GET /audit/export — Export full audit log as JSON Lines.
async fn export_audit_jsonl(
    State(state): State<AppState>,
) -> (
    StatusCode,
    [(axum::http::header::HeaderName, &'static str); 1],
    String,
) {
    let entries = state.audit_log.all();
    let mut buf = Vec::new();
    let _ = aegis_audit::JsonLinesExporter::export_entries(&entries, &mut buf);
    let body = String::from_utf8(buf).unwrap_or_default();
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/x-ndjson")],
        body,
    )
}

/// GET /metrics — Prometheus text-format metrics snapshot.
///
/// Compatible with any Prometheus scraper or `curl` for manual inspection.
/// Returns `Content-Type: text/plain; version=0.0.4` as required by the
/// Prometheus exposition format.
async fn metrics_handler(
    State(state): State<AppState>,
) -> (StatusCode, [(axum::http::header::HeaderName, &'static str); 1], String) {
    let body = state.prometheus.render();
    (
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
}

// ── Error helpers ──────────────────────────────────────────────────────

#[derive(Debug, serde::Serialize)]
pub struct ErrorBody {
    pub error: String,
}

fn bad_request(msg: String) -> (StatusCode, Json<ErrorBody>) {
    (StatusCode::BAD_REQUEST, Json(ErrorBody { error: msg }))
}

fn not_found(msg: String) -> (StatusCode, Json<ErrorBody>) {
    (StatusCode::NOT_FOUND, Json(ErrorBody { error: msg }))
}
