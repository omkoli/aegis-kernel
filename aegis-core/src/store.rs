use dashmap::DashMap;
use uuid::Uuid;

use crate::signing::TokenSignature;
use crate::token::CapabilityToken;
use crate::AegisError;

/// A token paired with its cryptographic signature.
#[derive(Debug, Clone)]
pub struct SignedToken {
    pub token: CapabilityToken,
    pub signature: TokenSignature,
}

/// Trait for token storage backends.
pub trait TokenStore: Send + Sync {
    fn insert(&self, entry: SignedToken) -> Result<(), AegisError>;
    fn get(&self, id: Uuid) -> Result<SignedToken, AegisError>;
    fn list(&self) -> Vec<SignedToken>;
    fn delete(&self, id: Uuid) -> Result<SignedToken, AegisError>;
    fn contains(&self, id: Uuid) -> bool;
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool;
}

/// Concurrent in-memory token store backed by `DashMap`.
#[derive(Debug, Default)]
pub struct InMemoryTokenStore {
    tokens: DashMap<Uuid, SignedToken>,
}

impl InMemoryTokenStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl TokenStore for InMemoryTokenStore {
    fn insert(&self, entry: SignedToken) -> Result<(), AegisError> {
        self.tokens.insert(entry.token.id(), entry);
        Ok(())
    }

    fn get(&self, id: Uuid) -> Result<SignedToken, AegisError> {
        self.tokens
            .get(&id)
            .map(|r| r.value().clone())
            .ok_or(AegisError::TokenNotFound { id })
    }

    fn list(&self) -> Vec<SignedToken> {
        self.tokens.iter().map(|r| r.value().clone()).collect()
    }

    fn delete(&self, id: Uuid) -> Result<SignedToken, AegisError> {
        self.tokens
            .remove(&id)
            .map(|(_, v)| v)
            .ok_or(AegisError::TokenNotFound { id })
    }

    fn contains(&self, id: Uuid) -> bool {
        self.tokens.contains_key(&id)
    }

    fn len(&self) -> usize {
        self.tokens.len()
    }

    fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }
}
