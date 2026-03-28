//! Conversion helpers between aegis-core types and JSON API types.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use aegis_core::{Action, AuditEntry, Constraints, Decision, ParamConstraint, SignedToken};

// ── JSON API types ─────────────────────────────────────────────────────

/// JSON representation of a signed token (for API responses).
#[derive(Debug, Serialize, Deserialize)]
pub struct TokenResponse {
    pub id: Uuid,
    pub subject: String,
    pub resource: String,
    pub actions: Vec<String>,
    pub constraints: std::collections::HashMap<String, serde_json::Value>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub delegatable: bool,
    pub max_uses: Option<u64>,
    pub revoked: bool,
    pub parent_id: Option<Uuid>,
    pub signature: String,
}

/// JSON representation of an audit entry.
#[derive(Debug, Serialize, Deserialize)]
pub struct AuditResponse {
    pub request_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub agent_id: String,
    pub tool_name: String,
    pub action: String,
    pub resource_path: String,
    pub token_id: Uuid,
    pub decision: String,
    pub reason: String,
    pub token_chain: Vec<Uuid>,
    pub latency_us: u64,
}

/// JSON body for POST /tokens.
#[derive(Debug, Deserialize)]
pub struct IssueRequest {
    pub subject: String,
    pub resource: String,
    pub actions: Vec<String>,
    #[serde(default)]
    pub constraints: std::collections::HashMap<String, serde_json::Value>,
    pub ttl_secs: Option<u64>,
    #[serde(default)]
    pub delegatable: bool,
    pub max_uses: Option<u64>,
}

/// JSON body for POST /enforce.
#[derive(Debug, Deserialize)]
pub struct EnforceRequest {
    pub agent_id: String,
    pub tool_name: String,
    pub action: String,
    pub resource: String,
    #[serde(default)]
    pub parameters: std::collections::HashMap<String, String>,
    pub token_id: Uuid,
}

/// JSON body for POST /delegate.
#[derive(Debug, Deserialize)]
pub struct DelegateRequest {
    pub parent_token_id: Uuid,
    pub new_subject: String,
    pub actions: Vec<String>,
    #[serde(default)]
    pub constraints: std::collections::HashMap<String, serde_json::Value>,
    #[serde(default)]
    pub delegatable: bool,
    pub max_uses: Option<u64>,
    pub ttl_secs: Option<u64>,
}

/// JSON response for enforcement.
#[derive(Debug, Serialize)]
pub struct EnforceResponse {
    pub decision: String,
    pub audit: AuditResponse,
}

/// JSON response for revocation.
#[derive(Debug, Serialize)]
pub struct RevokeResponse {
    pub revoked_ids: Vec<Uuid>,
}

// ── Conversions ────────────────────────────────────────────────────────

pub fn action_to_string(action: &Action) -> String {
    match action {
        Action::Read => "read".into(),
        Action::Write => "write".into(),
        Action::Execute => "execute".into(),
        Action::Delete => "delete".into(),
        Action::Custom(s) => s.clone(),
    }
}

pub fn string_to_action(s: &str) -> Action {
    match s.to_lowercase().as_str() {
        "read" => Action::Read,
        "write" => Action::Write,
        "execute" => Action::Execute,
        "delete" => Action::Delete,
        other => Action::Custom(other.into()),
    }
}

pub fn constraint_to_json(c: &ParamConstraint) -> serde_json::Value {
    match c {
        ParamConstraint::Exact(v) => serde_json::json!({"type": "exact", "value": v}),
        ParamConstraint::OneOf(v) => serde_json::json!({"type": "one_of", "values": v}),
        ParamConstraint::Regex(v) => serde_json::json!({"type": "regex", "pattern": v}),
        ParamConstraint::Range { min, max } => {
            serde_json::json!({"type": "range", "min": min, "max": max})
        }
    }
}

pub fn json_to_constraint(v: &serde_json::Value) -> Result<ParamConstraint, String> {
    let typ = v
        .get("type")
        .and_then(|t| t.as_str())
        .ok_or("missing 'type' field")?;
    match typ {
        "exact" => {
            let val = v
                .get("value")
                .and_then(|v| v.as_str())
                .ok_or("missing 'value' for exact constraint")?;
            Ok(ParamConstraint::Exact(val.into()))
        }
        "one_of" => {
            let vals = v
                .get("values")
                .and_then(|v| v.as_array())
                .ok_or("missing 'values' for one_of constraint")?
                .iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect();
            Ok(ParamConstraint::OneOf(vals))
        }
        "regex" => {
            let pat = v
                .get("pattern")
                .and_then(|v| v.as_str())
                .ok_or("missing 'pattern' for regex constraint")?;
            Ok(ParamConstraint::Regex(pat.into()))
        }
        "range" => {
            let min = v
                .get("min")
                .and_then(|v| v.as_f64())
                .ok_or("missing 'min' for range constraint")?;
            let max = v
                .get("max")
                .and_then(|v| v.as_f64())
                .ok_or("missing 'max' for range constraint")?;
            Ok(ParamConstraint::Range { min, max })
        }
        other => Err(format!("unknown constraint type: {other}")),
    }
}

pub fn parse_constraints(
    map: &std::collections::HashMap<String, serde_json::Value>,
) -> Result<Constraints, String> {
    let mut constraints = Constraints::new();
    for (key, value) in map {
        let pc = json_to_constraint(value)?;
        constraints = constraints
            .add(key.clone(), pc)
            .map_err(|e| e.to_string())?;
    }
    Ok(constraints)
}

pub fn signed_token_to_response(signed: &SignedToken) -> TokenResponse {
    let token = &signed.token;
    let mut constraints = std::collections::HashMap::new();
    for (key, pc) in token.constraints().iter() {
        constraints.insert(key.clone(), constraint_to_json(pc));
    }

    TokenResponse {
        id: token.id(),
        subject: token.subject().to_string(),
        resource: token.resource().path().to_string(),
        actions: token.actions().iter().map(action_to_string).collect(),
        constraints,
        issued_at: token.issued_at(),
        expires_at: token.expires_at(),
        delegatable: token.is_delegatable(),
        max_uses: token.max_uses(),
        revoked: token.is_revoked(),
        parent_id: token.parent_id(),
        signature: signed
            .signature
            .to_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
    }
}

pub fn audit_entry_to_response(entry: &AuditEntry) -> AuditResponse {
    AuditResponse {
        request_id: entry.request_id,
        timestamp: entry.timestamp,
        agent_id: entry.agent_id.clone(),
        tool_name: entry.tool_name.clone(),
        action: action_to_string(&entry.action),
        resource_path: entry.resource_path.clone(),
        token_id: entry.token_id,
        decision: match entry.decision {
            Decision::Allow => "allow".into(),
            Decision::Deny => "deny".into(),
        },
        reason: entry.reason.clone(),
        token_chain: entry.token_chain.clone(),
        latency_us: entry.latency_us,
    }
}
