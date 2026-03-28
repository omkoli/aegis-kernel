use chrono::{DateTime, Utc};
use uuid::Uuid;

/// All error variants for the Aegis core crate.
#[derive(Debug, thiserror::Error)]
pub enum AegisError {
    #[error("resource path must not be empty")]
    EmptyResourcePath,

    #[error("action name must not be empty")]
    EmptyActionName,

    #[error("constraint key must not be empty")]
    EmptyConstraintKey,

    #[error("invalid range: min ({min}) > max ({max})")]
    InvalidRange { min: f64, max: f64 },

    #[error("capability token must have at least one action")]
    NoActions,

    #[error("token already expired at {expires_at} (now: {now})")]
    TokenAlreadyExpired {
        expires_at: DateTime<Utc>,
        now: DateTime<Utc>,
    },

    #[error("token {id} is already revoked")]
    TokenAlreadyRevoked { id: Uuid },

    #[error("token {id} has expired")]
    TokenExpired { id: Uuid },

    #[error("token {id} has been revoked")]
    TokenRevoked { id: Uuid },

    #[error("action {action:?} not permitted by token {token_id}")]
    ActionNotPermitted { token_id: Uuid, action: String },

    #[error("resource mismatch: expected {expected}, got {actual}")]
    ResourceMismatch { expected: String, actual: String },

    #[error("constraint violation on parameter '{param}': {reason}")]
    ConstraintViolation { param: String, reason: String },

    #[error("duplicate action in token: {action:?}")]
    DuplicateAction { action: String },

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("deserialization error: {0}")]
    Deserialization(String),

    #[error("signature verification failed: {0}")]
    SignatureInvalid(String),
}
