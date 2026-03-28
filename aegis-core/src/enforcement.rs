use std::sync::Arc;
use std::time::Instant;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::signing::TokenSigner;
use crate::store::TokenStore;
use crate::validation::{ToolCallRequest, ValidationResult};
use crate::AegisError;

/// The outcome of an enforcement decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Decision {
    Allow,
    Deny,
}

/// A complete audit record for a single enforcement decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Unique ID for this audit record.
    pub request_id: Uuid,
    /// When the decision was made.
    pub timestamp: DateTime<Utc>,
    /// Identity of the calling agent.
    pub agent_id: String,
    /// Name of the tool being invoked.
    pub tool_name: String,
    /// The action that was requested.
    pub action: crate::resource::Action,
    /// The resource targeted.
    pub resource_path: String,
    /// The token ID presented (if any — may be a nonexistent token).
    pub token_id: Uuid,
    /// The enforcement decision.
    pub decision: Decision,
    /// Human-readable reason for the decision.
    pub reason: String,
    /// Delegation chain from presented token up to root (empty for root tokens).
    pub token_chain: Vec<Uuid>,
    /// Wall-clock latency of the enforcement check in microseconds.
    pub latency_us: u64,
}

/// The result returned by `EnforcementEngine::enforce`.
#[derive(Debug, Clone)]
pub struct EnforcementResult {
    pub decision: Decision,
    pub audit: AuditEntry,
}

/// Orchestrates token validation and produces audited enforcement decisions.
///
/// Wraps `TokenValidator` to add audit-trail generation and delegation-chain
/// resolution for every enforcement decision.
pub struct EnforcementEngine<S: TokenSigner, T: TokenStore> {
    validator: crate::validation::TokenValidator<S, T>,
    store: Arc<T>,
}

impl<S: TokenSigner, T: TokenStore> EnforcementEngine<S, T> {
    pub fn new(signer: S, store: Arc<T>) -> Self {
        let validator = crate::validation::TokenValidator::new(signer, Arc::clone(&store));
        Self { validator, store }
    }

    /// Enforces a tool-call request: validates the token and returns an
    /// `EnforcementResult` containing the decision and a full audit entry.
    pub fn enforce(&self, request: &ToolCallRequest) -> EnforcementResult {
        let start = Instant::now();
        let request_id = Uuid::new_v4();

        let (decision, reason) = match self.validator.validate(request) {
            Ok(ValidationResult::Allow) => (Decision::Allow, "all checks passed".to_string()),
            Ok(ValidationResult::Deny(reason)) => (Decision::Deny, reason),
            Err(AegisError::SignatureInvalid(msg)) => {
                (Decision::Deny, format!("signature invalid: {msg}"))
            }
            Err(AegisError::TokenNotFound { id }) => {
                (Decision::Deny, format!("token {id} not found"))
            }
            Err(e) => (Decision::Deny, format!("validation error: {e}")),
        };

        let token_chain = self.resolve_chain(request.token_id);
        let latency_us = start.elapsed().as_micros() as u64;

        let audit = AuditEntry {
            request_id,
            timestamp: Utc::now(),
            agent_id: request.agent_id.clone(),
            tool_name: request.tool_name.clone(),
            action: request.action.clone(),
            resource_path: request.resource.path().to_string(),
            token_id: request.token_id,
            decision: decision.clone(),
            reason,
            token_chain,
            latency_us,
        };

        EnforcementResult { decision, audit }
    }

    /// Returns a reference to the inner validator (for usage count queries, etc.).
    pub fn validator(&self) -> &crate::validation::TokenValidator<S, T> {
        &self.validator
    }

    /// Resolves the delegation chain from the given token up to the root.
    /// Returns an empty vec if the token is not found or is a root token.
    fn resolve_chain(&self, token_id: Uuid) -> Vec<Uuid> {
        let mut chain = Vec::new();
        let mut current_id = token_id;
        while let Ok(entry) = self.store.get(current_id) {
            match entry.token.parent_id() {
                Some(parent_id) => {
                    chain.push(parent_id);
                    current_id = parent_id;
                }
                None => break,
            }
        }
        chain
    }
}
