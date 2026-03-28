use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::resource::{Action, Constraints, Resource};
use crate::AegisError;

/// A capability token granting a set of actions on a resource, optionally
/// constrained and time-bounded.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CapabilityToken {
    id: Uuid,
    resource: Resource,
    actions: Vec<Action>,
    constraints: Constraints,
    issued_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
    revoked: bool,
}

impl CapabilityToken {
    /// Creates a new capability token.
    ///
    /// # Errors
    /// - `AegisError::NoActions` if `actions` is empty.
    /// - `AegisError::TokenAlreadyExpired` if `expires_at` is in the past.
    pub fn new(
        resource: Resource,
        actions: Vec<Action>,
        constraints: Constraints,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<Self, AegisError> {
        if actions.is_empty() {
            return Err(AegisError::NoActions);
        }
        let now = Utc::now();
        if let Some(exp) = expires_at {
            if exp <= now {
                return Err(AegisError::TokenAlreadyExpired {
                    expires_at: exp,
                    now,
                });
            }
        }
        Ok(Self {
            id: Uuid::new_v4(),
            resource,
            actions,
            constraints,
            issued_at: now,
            expires_at,
            revoked: false,
        })
    }

    pub fn id(&self) -> Uuid {
        self.id
    }

    pub fn resource(&self) -> &Resource {
        &self.resource
    }

    pub fn actions(&self) -> &[Action] {
        &self.actions
    }

    pub fn constraints(&self) -> &Constraints {
        &self.constraints
    }

    pub fn issued_at(&self) -> DateTime<Utc> {
        self.issued_at
    }

    pub fn expires_at(&self) -> Option<DateTime<Utc>> {
        self.expires_at
    }

    pub fn is_revoked(&self) -> bool {
        self.revoked
    }

    /// Checks whether this token has expired at the given time.
    pub fn is_expired_at(&self, when: DateTime<Utc>) -> bool {
        self.expires_at.is_some_and(|exp| when >= exp)
    }

    /// Revokes this token.
    ///
    /// # Errors
    /// Returns `AegisError::TokenAlreadyRevoked` if the token was already revoked.
    pub fn revoke(&mut self) -> Result<(), AegisError> {
        if self.revoked {
            return Err(AegisError::TokenAlreadyRevoked { id: self.id });
        }
        self.revoked = true;
        Ok(())
    }

    /// Checks whether this token grants the given action.
    pub fn permits(&self, action: &Action) -> bool {
        self.actions.contains(action)
    }
}
