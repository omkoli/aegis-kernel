use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;

use crate::request::TokenRequest;
use crate::signing::TokenSigner;
use crate::store::{SignedToken, TokenStore};
use crate::token::CapabilityToken;
use crate::AegisError;

/// Configuration for the token issuer.
#[derive(Debug, Clone)]
pub struct IssuerConfig {
    /// Default TTL applied when a request has no explicit TTL.
    pub default_ttl: Duration,
    /// Maximum allowed TTL. Requests exceeding this are clamped.
    pub max_ttl: Duration,
}

impl Default for IssuerConfig {
    fn default() -> Self {
        Self {
            default_ttl: Duration::from_secs(3600),   // 1 hour
            max_ttl: Duration::from_secs(86400 * 30), // 30 days
        }
    }
}

/// Issues, signs, and stores capability tokens.
pub struct TokenIssuer<S: TokenSigner, T: TokenStore> {
    signer: S,
    store: Arc<T>,
    config: IssuerConfig,
}

impl<S: TokenSigner, T: TokenStore> TokenIssuer<S, T> {
    pub fn new(signer: S, store: Arc<T>, config: IssuerConfig) -> Self {
        Self {
            signer,
            store,
            config,
        }
    }

    /// Issues a new token from a request.
    ///
    /// 1. Validates the request (non-empty actions, valid subject).
    /// 2. Applies default TTL if none given; clamps to max TTL.
    /// 3. Creates a `CapabilityToken`, signs it, and stores it.
    pub fn issue(&self, request: TokenRequest) -> Result<SignedToken, AegisError> {
        // Validate
        if request.subject.is_empty() {
            return Err(AegisError::EmptySubject);
        }
        if request.actions.is_empty() {
            return Err(AegisError::NoActions);
        }
        if let Some(0) = request.max_uses {
            return Err(AegisError::InvalidMaxUses);
        }

        // Compute expiry with TTL clamping
        let ttl = request.ttl.unwrap_or(self.config.default_ttl);
        let clamped_ttl = ttl.min(self.config.max_ttl);
        let expires_at = Utc::now() + clamped_ttl;

        // Build token
        let token = CapabilityToken::new(
            request.subject,
            request.resource,
            request.actions,
            request.constraints,
            Some(expires_at),
            request.delegatable,
            request.max_uses,
        )?;

        // Sign
        let signature = self.signer.sign(&token)?;

        let signed = SignedToken { token, signature };
        self.store.insert(signed.clone())?;

        Ok(signed)
    }

    /// Retrieves a token by ID from the store.
    pub fn get(&self, id: uuid::Uuid) -> Result<SignedToken, AegisError> {
        self.store.get(id)
    }

    /// Lists all tokens in the store.
    pub fn list(&self) -> Vec<SignedToken> {
        self.store.list()
    }

    /// Deletes a token by ID from the store.
    pub fn delete(&self, id: uuid::Uuid) -> Result<SignedToken, AegisError> {
        self.store.delete(id)
    }

    /// Returns a reference to the underlying store.
    pub fn store(&self) -> &T {
        &self.store
    }

    /// Returns a reference to the signer.
    pub fn signer(&self) -> &S {
        &self.signer
    }
}
