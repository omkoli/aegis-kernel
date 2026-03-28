use reqwest::StatusCode;
use serde_json::{json, Value};
use tokio::net::TcpListener;

use aegis_api::routes::router;
use aegis_api::state::AppState;

// ── Test helpers ───────────────────────────────────────────────────────

async fn spawn_server() -> String {
    let state = AppState::new();
    let app = router(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

fn client() -> reqwest::Client {
    reqwest::Client::new()
}

async fn issue_token(base: &str, body: &Value) -> Value {
    let resp = client()
        .post(format!("{base}/tokens"))
        .json(body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    resp.json().await.unwrap()
}

fn base_issue_body() -> Value {
    json!({
        "subject": "test-agent",
        "resource": "file:///data/test",
        "actions": ["read", "write"],
        "ttl_secs": 3600,
        "delegatable": true,
        "max_uses": 100
    })
}

// ── 1. POST /tokens → CREATED ──────────────────────────────────────────

#[tokio::test]
async fn issue_token_returns_created() {
    let base = spawn_server().await;
    let token = issue_token(&base, &base_issue_body()).await;

    assert!(token["id"].is_string());
    assert_eq!(token["subject"], "test-agent");
    assert_eq!(token["resource"], "file:///data/test");
    assert_eq!(token["actions"], json!(["read", "write"]));
    assert_eq!(token["delegatable"], true);
    assert_eq!(token["max_uses"], 100);
    assert_eq!(token["revoked"], false);
    assert!(token["signature"].is_string());
    assert!(token["issued_at"].is_string());
    assert!(token["expires_at"].is_string());
}

// ── 2. GET /tokens/:id → 200 ───────────────────────────────────────────

#[tokio::test]
async fn get_token_by_id() {
    let base = spawn_server().await;
    let token = issue_token(&base, &base_issue_body()).await;
    let id = token["id"].as_str().unwrap();

    let resp = client()
        .get(format!("{base}/tokens/{id}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let fetched: Value = resp.json().await.unwrap();
    assert_eq!(fetched["id"], token["id"]);
    assert_eq!(fetched["subject"], "test-agent");
}

// ── 3. GET /tokens/:id → 404 for nonexistent ───────────────────────────

#[tokio::test]
async fn get_nonexistent_token_returns_404() {
    let base = spawn_server().await;
    let fake_id = uuid::Uuid::new_v4();

    let resp = client()
        .get(format!("{base}/tokens/{fake_id}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let body: Value = resp.json().await.unwrap();
    assert!(body["error"].as_str().unwrap().contains("not found"));
}

// ── 4. DELETE /tokens/:id → 200 ────────────────────────────────────────

#[tokio::test]
async fn delete_token_returns_deleted_token() {
    let base = spawn_server().await;
    let token = issue_token(&base, &base_issue_body()).await;
    let id = token["id"].as_str().unwrap();

    let resp = client()
        .delete(format!("{base}/tokens/{id}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let deleted: Value = resp.json().await.unwrap();
    assert_eq!(deleted["id"], token["id"]);

    // Confirm it's gone
    let resp = client()
        .get(format!("{base}/tokens/{id}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ── 5. DELETE /tokens/:id → 404 for nonexistent ────────────────────────

#[tokio::test]
async fn delete_nonexistent_token_returns_404() {
    let base = spawn_server().await;
    let fake_id = uuid::Uuid::new_v4();

    let resp = client()
        .delete(format!("{base}/tokens/{fake_id}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ── 6. GET /tokens → list all ──────────────────────────────────────────

#[tokio::test]
async fn list_tokens_returns_all() {
    let base = spawn_server().await;

    // Start with empty list
    let resp = client().get(format!("{base}/tokens")).send().await.unwrap();
    let list: Vec<Value> = resp.json().await.unwrap();
    assert!(list.is_empty());

    // Issue two tokens
    issue_token(&base, &base_issue_body()).await;
    issue_token(
        &base,
        &json!({
            "subject": "agent-2",
            "resource": "file:///other",
            "actions": ["read"],
            "ttl_secs": 600
        }),
    )
    .await;

    let resp = client().get(format!("{base}/tokens")).send().await.unwrap();
    let list: Vec<Value> = resp.json().await.unwrap();
    assert_eq!(list.len(), 2);
}

// ── 7. POST /tokens validation errors → 400 ────────────────────────────

#[tokio::test]
async fn issue_token_validation_errors() {
    let base = spawn_server().await;

    // Empty subject
    let resp = client()
        .post(format!("{base}/tokens"))
        .json(&json!({
            "subject": "",
            "resource": "file:///data",
            "actions": ["read"]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // Empty actions
    let resp = client()
        .post(format!("{base}/tokens"))
        .json(&json!({
            "subject": "agent",
            "resource": "file:///data",
            "actions": []
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // Empty resource
    let resp = client()
        .post(format!("{base}/tokens"))
        .json(&json!({
            "subject": "agent",
            "resource": "",
            "actions": ["read"]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ── 8. POST /enforce → allow with audit ─────────────────────────────────

#[tokio::test]
async fn enforce_allow_with_audit() {
    let base = spawn_server().await;
    let token = issue_token(&base, &base_issue_body()).await;
    let token_id = token["id"].as_str().unwrap();

    let resp = client()
        .post(format!("{base}/enforce"))
        .json(&json!({
            "agent_id": "test-agent",
            "tool_name": "read_file",
            "action": "read",
            "resource": "file:///data/test",
            "parameters": {},
            "token_id": token_id
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["decision"], "allow");
    assert!(body["audit"]["request_id"].is_string());
    assert_eq!(body["audit"]["agent_id"], "test-agent");
    assert_eq!(body["audit"]["tool_name"], "read_file");
    assert_eq!(body["audit"]["action"], "read");
    assert_eq!(body["audit"]["decision"], "allow");
    assert!(body["audit"]["latency_us"].as_u64().unwrap() > 0);
}

// ── 9. POST /enforce → deny (wrong action) ─────────────────────────────

#[tokio::test]
async fn enforce_deny_wrong_action() {
    let base = spawn_server().await;
    let token = issue_token(&base, &base_issue_body()).await;
    let token_id = token["id"].as_str().unwrap();

    let resp = client()
        .post(format!("{base}/enforce"))
        .json(&json!({
            "agent_id": "test-agent",
            "tool_name": "delete_file",
            "action": "delete",
            "resource": "file:///data/test",
            "parameters": {},
            "token_id": token_id
        }))
        .send()
        .await
        .unwrap();

    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["decision"], "deny");
    assert!(body["audit"]["reason"]
        .as_str()
        .unwrap()
        .contains("not permitted"));
}

// ── 10. POST /enforce → deny (nonexistent token) ───────────────────────

#[tokio::test]
async fn enforce_deny_nonexistent_token() {
    let base = spawn_server().await;
    let fake_id = uuid::Uuid::new_v4();

    let resp = client()
        .post(format!("{base}/enforce"))
        .json(&json!({
            "agent_id": "agent",
            "tool_name": "tool",
            "action": "read",
            "resource": "file:///data",
            "parameters": {},
            "token_id": fake_id.to_string()
        }))
        .send()
        .await
        .unwrap();

    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["decision"], "deny");
    assert!(body["audit"]["reason"]
        .as_str()
        .unwrap()
        .contains("not found"));
}

// ── 11. GET /audit → returns enforcement records ────────────────────────

#[tokio::test]
async fn audit_log_records_enforcements() {
    let base = spawn_server().await;
    let token = issue_token(&base, &base_issue_body()).await;
    let token_id = token["id"].as_str().unwrap();

    // Enforce twice
    for _ in 0..2 {
        client()
            .post(format!("{base}/enforce"))
            .json(&json!({
                "agent_id": "test-agent",
                "tool_name": "read_file",
                "action": "read",
                "resource": "file:///data/test",
                "parameters": {},
                "token_id": token_id
            }))
            .send()
            .await
            .unwrap();
    }

    let resp = client().get(format!("{base}/audit")).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let entries: Vec<Value> = resp.json().await.unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0]["agent_id"], "test-agent");
}

// ── 12. GET /audit?token_id=... → filtered ──────────────────────────────

#[tokio::test]
async fn audit_log_filtered_by_token_id() {
    let base = spawn_server().await;

    let token1 = issue_token(&base, &base_issue_body()).await;
    let token2 = issue_token(
        &base,
        &json!({
            "subject": "agent-2",
            "resource": "file:///other",
            "actions": ["read"],
            "ttl_secs": 600
        }),
    )
    .await;

    // Enforce with both tokens
    for tid in [
        token1["id"].as_str().unwrap(),
        token2["id"].as_str().unwrap(),
    ] {
        client()
            .post(format!("{base}/enforce"))
            .json(&json!({
                "agent_id": if tid == token1["id"].as_str().unwrap() { "test-agent" } else { "agent-2" },
                "tool_name": "tool",
                "action": "read",
                "resource": if tid == token1["id"].as_str().unwrap() { "file:///data/test" } else { "file:///other" },
                "parameters": {},
                "token_id": tid
            }))
            .send()
            .await
            .unwrap();
    }

    // Filter by token1's ID
    let resp = client()
        .get(format!(
            "{base}/audit?token_id={}",
            token1["id"].as_str().unwrap()
        ))
        .send()
        .await
        .unwrap();
    let entries: Vec<Value> = resp.json().await.unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["token_id"], token1["id"]);
}

// ── 13. GET /audit?limit=N → limited ────────────────────────────────────

#[tokio::test]
async fn audit_log_with_limit() {
    let base = spawn_server().await;
    let token = issue_token(&base, &base_issue_body()).await;
    let token_id = token["id"].as_str().unwrap();

    for _ in 0..5 {
        client()
            .post(format!("{base}/enforce"))
            .json(&json!({
                "agent_id": "test-agent",
                "tool_name": "tool",
                "action": "read",
                "resource": "file:///data/test",
                "parameters": {},
                "token_id": token_id
            }))
            .send()
            .await
            .unwrap();
    }

    let resp = client()
        .get(format!("{base}/audit?limit=2"))
        .send()
        .await
        .unwrap();
    let entries: Vec<Value> = resp.json().await.unwrap();
    assert_eq!(entries.len(), 2);
}

// ── 14. POST /delegate → CREATED ────────────────────────────────────────

#[tokio::test]
async fn delegate_token() {
    let base = spawn_server().await;
    let parent = issue_token(&base, &base_issue_body()).await;
    let parent_id = parent["id"].as_str().unwrap();

    let resp = client()
        .post(format!("{base}/delegate"))
        .json(&json!({
            "parent_token_id": parent_id,
            "new_subject": "child-agent",
            "actions": ["read"],
            "delegatable": false,
            "ttl_secs": 600
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let child: Value = resp.json().await.unwrap();
    assert_eq!(child["subject"], "child-agent");
    assert_eq!(child["actions"], json!(["read"]));
    assert_eq!(child["delegatable"], false);
    assert_eq!(child["parent_id"], parent_id);
}

// ── 15. POST /tokens/:id/revoke → cascading revocation ─────────────────

#[tokio::test]
async fn revoke_cascades_to_children() {
    let base = spawn_server().await;
    let parent = issue_token(&base, &base_issue_body()).await;
    let parent_id = parent["id"].as_str().unwrap();

    // Delegate a child
    let child_resp = client()
        .post(format!("{base}/delegate"))
        .json(&json!({
            "parent_token_id": parent_id,
            "new_subject": "child-agent",
            "actions": ["read"],
            "delegatable": false,
            "ttl_secs": 600
        }))
        .send()
        .await
        .unwrap();
    let child: Value = child_resp.json().await.unwrap();
    let child_id = child["id"].as_str().unwrap();

    // Revoke parent
    let resp = client()
        .post(format!("{base}/tokens/{parent_id}/revoke"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let revoke_body: Value = resp.json().await.unwrap();
    let revoked_ids: Vec<String> = revoke_body["revoked_ids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert!(revoked_ids.contains(&parent_id.to_string()));
    assert!(revoked_ids.contains(&child_id.to_string()));

    // Both tokens should be revoked
    let parent_check: Value = client()
        .get(format!("{base}/tokens/{parent_id}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(parent_check["revoked"], true);

    let child_check: Value = client()
        .get(format!("{base}/tokens/{child_id}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(child_check["revoked"], true);
}

// ── 16. Full CRUD lifecycle ─────────────────────────────────────────────

#[tokio::test]
async fn full_crud_lifecycle() {
    let base = spawn_server().await;

    // 1. Issue
    let token = issue_token(&base, &base_issue_body()).await;
    let id = token["id"].as_str().unwrap();

    // 2. Get
    let resp = client()
        .get(format!("{base}/tokens/{id}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 3. Enforce (allow)
    let resp = client()
        .post(format!("{base}/enforce"))
        .json(&json!({
            "agent_id": "test-agent",
            "tool_name": "read_file",
            "action": "read",
            "resource": "file:///data/test",
            "parameters": {},
            "token_id": id
        }))
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["decision"], "allow");

    // 4. Delegate
    let child_resp = client()
        .post(format!("{base}/delegate"))
        .json(&json!({
            "parent_token_id": id,
            "new_subject": "delegated-agent",
            "actions": ["read"],
            "delegatable": false,
            "ttl_secs": 600
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(child_resp.status(), StatusCode::CREATED);
    let child: Value = child_resp.json().await.unwrap();
    let child_id = child["id"].as_str().unwrap();

    // 5. Enforce delegated token
    let resp = client()
        .post(format!("{base}/enforce"))
        .json(&json!({
            "agent_id": "delegated-agent",
            "tool_name": "read_data",
            "action": "read",
            "resource": "file:///data/test",
            "parameters": {},
            "token_id": child_id
        }))
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["decision"], "allow");

    // 6. Revoke parent (cascades)
    let resp = client()
        .post(format!("{base}/tokens/{id}/revoke"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 7. Enforce revoked child → deny
    let resp = client()
        .post(format!("{base}/enforce"))
        .json(&json!({
            "agent_id": "delegated-agent",
            "tool_name": "read_data",
            "action": "read",
            "resource": "file:///data/test",
            "parameters": {},
            "token_id": child_id
        }))
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["decision"], "deny");

    // 8. Audit log has all enforcement records
    let resp = client().get(format!("{base}/audit")).send().await.unwrap();
    let entries: Vec<Value> = resp.json().await.unwrap();
    assert_eq!(entries.len(), 3); // allow + allow (delegated) + deny (revoked)

    // 9. Delete the parent token
    let resp = client()
        .delete(format!("{base}/tokens/{id}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 10. Confirm deleted
    let resp = client()
        .get(format!("{base}/tokens/{id}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ── 17. Constraints through the API ─────────────────────────────────────

#[tokio::test]
async fn issue_and_enforce_with_constraints() {
    let base = spawn_server().await;

    let token = issue_token(
        &base,
        &json!({
            "subject": "constrained-agent",
            "resource": "api://payments",
            "actions": ["execute"],
            "constraints": {
                "amount": {"type": "range", "min": 0.0, "max": 1000.0},
                "currency": {"type": "exact", "value": "USD"}
            },
            "ttl_secs": 3600,
            "delegatable": false
        }),
    )
    .await;
    let token_id = token["id"].as_str().unwrap();

    // Valid parameters → allow
    let resp = client()
        .post(format!("{base}/enforce"))
        .json(&json!({
            "agent_id": "constrained-agent",
            "tool_name": "charge",
            "action": "execute",
            "resource": "api://payments",
            "parameters": {"amount": "500", "currency": "USD"},
            "token_id": token_id
        }))
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["decision"], "allow");

    // Invalid constraint → deny
    let resp = client()
        .post(format!("{base}/enforce"))
        .json(&json!({
            "agent_id": "constrained-agent",
            "tool_name": "charge",
            "action": "execute",
            "resource": "api://payments",
            "parameters": {"amount": "500", "currency": "EUR"},
            "token_id": token_id
        }))
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["decision"], "deny");
    assert!(body["audit"]["reason"]
        .as_str()
        .unwrap()
        .contains("constraint violation"));
}

// ── 18. GET /audit?agent_id=... → filtered by agent ─────────────────────

#[tokio::test]
async fn audit_log_filtered_by_agent_id() {
    let base = spawn_server().await;

    let token1 = issue_token(&base, &base_issue_body()).await;
    let token2 = issue_token(
        &base,
        &json!({
            "subject": "other-agent",
            "resource": "file:///other",
            "actions": ["read"],
            "ttl_secs": 600
        }),
    )
    .await;

    // Enforce with both
    client()
        .post(format!("{base}/enforce"))
        .json(&json!({
            "agent_id": "test-agent",
            "tool_name": "tool",
            "action": "read",
            "resource": "file:///data/test",
            "parameters": {},
            "token_id": token1["id"].as_str().unwrap()
        }))
        .send()
        .await
        .unwrap();

    client()
        .post(format!("{base}/enforce"))
        .json(&json!({
            "agent_id": "other-agent",
            "tool_name": "tool",
            "action": "read",
            "resource": "file:///other",
            "parameters": {},
            "token_id": token2["id"].as_str().unwrap()
        }))
        .send()
        .await
        .unwrap();

    let resp = client()
        .get(format!("{base}/audit?agent_id=other-agent"))
        .send()
        .await
        .unwrap();
    let entries: Vec<Value> = resp.json().await.unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["agent_id"], "other-agent");
}
