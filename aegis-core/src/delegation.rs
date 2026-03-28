use std::collections::VecDeque;
use std::sync::Arc;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::resource::{Action, Constraints};
use crate::signing::TokenSigner;
use crate::store::{SignedToken, TokenStore};
use crate::token::CapabilityToken;
use crate::AegisError;

/// A request to derive a new token from an existing parent token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationRequest {
    /// ID of the parent token to derive from.
    pub parent_token_id: Uuid,
    /// The new subject (delegatee).
    pub new_subject: String,
    /// Actions the derived token should grant (must be subset of parent).
    pub actions: Vec<Action>,
    /// Additional constraints (merged with / must not weaken parent).
    #[serde(default)]
    pub constraints: Constraints,
    /// Whether the derived token can itself be delegated.
    #[serde(default)]
    pub delegatable: bool,
    /// Max uses for the derived token (must be <= parent if parent has one).
    #[serde(default)]
    pub max_uses: Option<u64>,
    /// TTL in seconds for the derived token (clamped to parent's remaining).
    #[serde(default)]
    pub ttl_secs: Option<u64>,
}

/// Handles delegation (derivation) and cascading revocation.
pub struct DelegationService<S: TokenSigner, T: TokenStore> {
    signer: S,
    store: Arc<T>,
}

impl<S: TokenSigner, T: TokenStore> DelegationService<S, T> {
    pub fn new(signer: S, store: Arc<T>) -> Self {
        Self { signer, store }
    }

    /// Derives a new token from a parent, enforcing scope narrowing.
    ///
    /// Rules:
    /// - Parent must be delegatable.
    /// - Parent must not be revoked or expired.
    /// - Derived resource must equal parent resource.
    /// - Derived actions must be a subset of parent actions.
    /// - Derived max_uses must be <= parent max_uses (if parent has one).
    /// - Derived TTL is clamped to parent's remaining TTL.
    /// - Derived token cannot be delegatable if parent is not.
    /// - Derived constraints are additive (parent's constraints carry forward).
    pub fn delegate(&self, request: DelegationRequest) -> Result<SignedToken, AegisError> {
        // Look up and validate parent
        let parent_signed = self.store.get(request.parent_token_id)?;
        let parent = &parent_signed.token;

        if !parent.is_delegatable() {
            return Err(AegisError::NotDelegatable { id: parent.id() });
        }
        if parent.is_revoked() {
            return Err(AegisError::ParentRevoked { id: parent.id() });
        }
        let now = Utc::now();
        if parent.is_expired_at(now) {
            return Err(AegisError::ParentExpired { id: parent.id() });
        }

        // Resource must match
        // (Derived token gets same resource — no escalation to different resources.)

        // Actions must be subset of parent
        for action in &request.actions {
            if !parent.permits(action) {
                return Err(AegisError::ScopeEscalation {
                    reason: format!(
                        "action {:?} not permitted by parent token {}",
                        action,
                        parent.id()
                    ),
                });
            }
        }

        // Delegatable: child can only be delegatable if parent is
        if request.delegatable && !parent.is_delegatable() {
            return Err(AegisError::ScopeEscalation {
                reason: "cannot make derived token delegatable when parent is not".into(),
            });
        }

        // Max uses: must be <= parent's max_uses if parent has one
        let max_uses = match (parent.max_uses(), request.max_uses) {
            (Some(parent_max), Some(child_max)) => {
                if child_max > parent_max {
                    return Err(AegisError::ScopeEscalation {
                        reason: format!(
                            "derived max_uses ({child_max}) exceeds parent max_uses ({parent_max})"
                        ),
                    });
                }
                Some(child_max)
            }
            (Some(parent_max), None) => Some(parent_max),
            (None, child_max) => child_max,
        };

        // TTL: clamp to parent's remaining TTL
        let parent_remaining = parent.expires_at().map(|exp| {
            let remaining = exp - now;
            remaining.to_std().unwrap_or_default()
        });

        let requested_ttl = request
            .ttl_secs
            .map(std::time::Duration::from_secs)
            .or(parent_remaining);

        let expires_at = match (requested_ttl, parent_remaining) {
            (Some(req), Some(parent_rem)) => {
                let clamped = req.min(parent_rem);
                Some(now + clamped)
            }
            (Some(req), None) => Some(now + req),
            (None, Some(parent_rem)) => Some(now + parent_rem),
            (None, None) => None,
        };

        // Merge constraints: parent constraints carry forward, child adds more
        let mut merged_constraints = parent.constraints().clone();
        for (key, constraint) in request.constraints.iter() {
            merged_constraints = merged_constraints.add(key.clone(), constraint.clone())?;
        }

        // Build derived token
        let token = CapabilityToken::new_with_parent(
            request.new_subject,
            parent.resource().clone(),
            request.actions,
            merged_constraints,
            expires_at,
            request.delegatable,
            max_uses,
            Some(parent.id()),
        )?;

        let signature = self.signer.sign(&token)?;
        let signed = SignedToken { token, signature };
        self.store.insert(signed.clone())?;

        Ok(signed)
    }

    /// Revokes a token and all its descendants via BFS traversal.
    ///
    /// Returns the list of all token IDs that were revoked.
    pub fn revoke_cascade(&self, token_id: Uuid) -> Result<Vec<Uuid>, AegisError> {
        let mut revoked_ids = Vec::new();
        let mut queue = VecDeque::new();
        queue.push_back(token_id);

        while let Some(id) = queue.pop_front() {
            // Get the token, revoke it, re-sign, re-store
            let mut entry = match self.store.get(id) {
                Ok(e) => e,
                Err(AegisError::TokenNotFound { .. }) => continue,
                Err(e) => return Err(e),
            };

            if !entry.token.is_revoked() {
                entry.token.revoke()?;
                let new_sig = self.signer.sign(&entry.token)?;
                entry.signature = new_sig;
                // Delete and re-insert to update
                let _ = self.store.delete(id);
                self.store.insert(entry)?;
                revoked_ids.push(id);
            }

            // Find all children of this token
            for child in self.store.list() {
                if child.token.parent_id() == Some(id) && !child.token.is_revoked() {
                    queue.push_back(child.token.id());
                }
            }
        }

        Ok(revoked_ids)
    }

    /// Returns a reference to the underlying store.
    pub fn store(&self) -> &T {
        &self.store
    }

    /// Returns a reference to the signer.
    pub fn signer(&self) -> &S {
        &self.signer
    }

    /// Returns all direct children of a given token.
    pub fn children_of(&self, token_id: Uuid) -> Vec<SignedToken> {
        self.store
            .list()
            .into_iter()
            .filter(|s| s.token.parent_id() == Some(token_id))
            .collect()
    }

    /// Returns the full chain of ancestors from the given token up to the root.
    pub fn ancestor_chain(&self, token_id: Uuid) -> Result<Vec<Uuid>, AegisError> {
        let mut chain = Vec::new();
        let mut current_id = token_id;
        loop {
            let entry = self.store.get(current_id)?;
            match entry.token.parent_id() {
                Some(parent_id) => {
                    chain.push(parent_id);
                    current_id = parent_id;
                }
                None => break,
            }
        }
        Ok(chain)
    }
}
