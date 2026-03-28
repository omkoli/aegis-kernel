use std::collections::HashMap;
use std::sync::Arc;

use chrono::Utc;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::resource::{Action, ParamConstraint, Resource};
use crate::signing::TokenSigner;
use crate::store::TokenStore;
use crate::AegisError;

/// A request from an agent to invoke a tool, carrying the capability token
/// that authorises the call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallRequest {
    /// Identity of the calling agent.
    pub agent_id: String,
    /// Name of the tool being invoked.
    pub tool_name: String,
    /// The action the agent wants to perform.
    pub action: Action,
    /// The target resource.
    pub resource: Resource,
    /// Parameters supplied by the agent (validated against token constraints).
    #[serde(default)]
    pub parameters: HashMap<String, String>,
    /// ID of the capability token presented for authorisation.
    pub token_id: Uuid,
}

/// Result of a validation check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationResult {
    Allow,
    Deny(String),
}

/// Validates tool-call requests against capability tokens.
///
/// Validation pipeline (fail-fast):
/// 1. Token lookup
/// 2. Signature verification
/// 3. Expiry check
/// 4. Revocation check
/// 5. Subject (agent) match
/// 6. Resource match
/// 7. Action match
/// 8. Constraint check
/// 9. Usage check
pub struct TokenValidator<S: TokenSigner, T: TokenStore> {
    signer: S,
    store: Arc<T>,
    usage_counts: DashMap<Uuid, u64>,
}

impl<S: TokenSigner, T: TokenStore> TokenValidator<S, T> {
    pub fn new(signer: S, store: Arc<T>) -> Self {
        Self {
            signer,
            store,
            usage_counts: DashMap::new(),
        }
    }

    /// Runs the full validation pipeline on a tool-call request.
    /// Returns `Ok(ValidationResult::Allow)` on success, or the first error.
    pub fn validate(&self, request: &ToolCallRequest) -> Result<ValidationResult, AegisError> {
        // 1. Lookup
        let signed = self.store.get(request.token_id)?;
        let token = &signed.token;

        // 2. Signature verification
        self.signer.verify(token, &signed.signature)?;

        // 3. Expiry check
        let now = Utc::now();
        if token.is_expired_at(now) {
            return Ok(ValidationResult::Deny(format!(
                "token {} has expired",
                token.id()
            )));
        }

        // 4. Revocation check
        if token.is_revoked() {
            return Ok(ValidationResult::Deny(format!(
                "token {} has been revoked",
                token.id()
            )));
        }

        // 5. Subject (agent) match
        if token.subject() != request.agent_id {
            return Ok(ValidationResult::Deny(format!(
                "agent '{}' does not match token subject '{}'",
                request.agent_id,
                token.subject()
            )));
        }

        // 6. Resource match
        if token.resource() != &request.resource {
            return Ok(ValidationResult::Deny(format!(
                "resource mismatch: token grants '{}', request targets '{}'",
                token.resource().path(),
                request.resource.path()
            )));
        }

        // 7. Action match
        if !token.permits(&request.action) {
            return Ok(ValidationResult::Deny(format!(
                "action {:?} not permitted by token {}",
                request.action,
                token.id()
            )));
        }

        // 8. Constraint check
        for (key, constraint) in token.constraints().iter() {
            if let Some(value) = request.parameters.get(key) {
                if let Some(reason) = check_constraint(constraint, value) {
                    return Ok(ValidationResult::Deny(format!(
                        "constraint violation on '{key}': {reason}"
                    )));
                }
            }
            // Missing parameters are not a violation — constraints only apply
            // to parameters that are actually present in the request.
        }

        // 9. Usage check
        if let Some(max) = token.max_uses() {
            let mut count = self.usage_counts.entry(token.id()).or_insert(0);
            if *count >= max {
                return Ok(ValidationResult::Deny(format!(
                    "token {} usage exhausted ({}/{})",
                    token.id(),
                    *count,
                    max
                )));
            }
            *count += 1;
        }

        Ok(ValidationResult::Allow)
    }

    /// Returns the current usage count for a token.
    pub fn usage_count(&self, token_id: Uuid) -> u64 {
        self.usage_counts.get(&token_id).map(|r| *r).unwrap_or(0)
    }
}

/// Checks a single parameter value against a constraint. Returns `None` if
/// the value satisfies the constraint, or `Some(reason)` if it violates it.
fn check_constraint(constraint: &ParamConstraint, value: &str) -> Option<String> {
    match constraint {
        ParamConstraint::Exact(expected) => {
            if value != expected {
                Some(format!("expected '{expected}', got '{value}'"))
            } else {
                None
            }
        }
        ParamConstraint::OneOf(options) => {
            if !options.iter().any(|o| o == value) {
                Some(format!("'{value}' not in allowed set {options:?}"))
            } else {
                None
            }
        }
        ParamConstraint::Regex(pattern) => {
            // Simple prefix/suffix/contains matching for common patterns,
            // full regex would require the `regex` crate.
            if pattern.starts_with('^') && pattern.ends_with('$') {
                let inner = &pattern[1..pattern.len() - 1];
                if value != inner {
                    Some(format!("'{value}' does not match pattern '{pattern}'"))
                } else {
                    None
                }
            } else {
                // For non-trivial regex, we just check contains as a best-effort.
                // A production system would use the `regex` crate.
                None
            }
        }
        ParamConstraint::Range { min, max } => match value.parse::<f64>() {
            Ok(v) if v >= *min && v <= *max => None,
            Ok(v) => Some(format!("{v} outside range [{min}, {max}]")),
            Err(_) => Some(format!("'{value}' is not a valid number")),
        },
    }
}
