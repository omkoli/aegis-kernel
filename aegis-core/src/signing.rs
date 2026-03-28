use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::canonical::canonical_json;
use crate::AegisError;

/// A 64-byte Ed25519 signature wrapper with serde support.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenSignature(Signature);

impl TokenSignature {
    pub fn to_bytes(&self) -> [u8; 64] {
        self.0.to_bytes()
    }

    pub fn from_bytes(bytes: &[u8; 64]) -> Self {
        Self(Signature::from_bytes(bytes))
    }

    pub fn inner(&self) -> &Signature {
        &self.0
    }
}

impl Serialize for TokenSignature {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let hex_str: String = self
            .0
            .to_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        serializer.serialize_str(&hex_str)
    }
}

impl<'de> Deserialize<'de> for TokenSignature {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let hex_str = String::deserialize(deserializer)?;
        if hex_str.len() != 128 {
            return Err(serde::de::Error::custom(format!(
                "expected 128 hex chars, got {}",
                hex_str.len()
            )));
        }
        let mut bytes = [0u8; 64];
        for (i, chunk) in hex_str.as_bytes().chunks(2).enumerate() {
            let s = std::str::from_utf8(chunk).map_err(serde::de::Error::custom)?;
            bytes[i] = u8::from_str_radix(s, 16).map_err(serde::de::Error::custom)?;
        }
        Ok(Self(Signature::from_bytes(&bytes)))
    }
}

/// Trait for signing and verifying capability tokens.
pub trait TokenSigner {
    /// Sign the canonical representation of a serializable value.
    fn sign<T: Serialize>(&self, value: &T) -> Result<TokenSignature, AegisError>;

    /// Verify a signature against the canonical representation of a value.
    fn verify<T: Serialize>(&self, value: &T, signature: &TokenSignature)
        -> Result<(), AegisError>;
}

/// Ed25519-based token signer using `ed25519-dalek`.
pub struct Ed25519TokenSigner {
    signing_key: SigningKey,
}

impl Ed25519TokenSigner {
    /// Creates a new signer from an Ed25519 signing key.
    pub fn new(signing_key: SigningKey) -> Self {
        Self { signing_key }
    }

    /// Generates a new signer with a random key.
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        Self {
            signing_key: SigningKey::generate(&mut rng),
        }
    }

    /// Returns the verifying (public) key for this signer.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Returns the raw 32-byte signing key material.
    pub fn signing_key_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Reconstructs a signer from raw 32-byte signing key material.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(bytes),
        }
    }
}

impl TokenSigner for Ed25519TokenSigner {
    fn sign<T: Serialize>(&self, value: &T) -> Result<TokenSignature, AegisError> {
        let bytes = canonical_json(value)?;
        let signature = self.signing_key.sign(&bytes);
        Ok(TokenSignature(signature))
    }

    fn verify<T: Serialize>(
        &self,
        value: &T,
        signature: &TokenSignature,
    ) -> Result<(), AegisError> {
        let bytes = canonical_json(value)?;
        self.signing_key
            .verifying_key()
            .verify(&bytes, signature.inner())
            .map_err(|e| AegisError::SignatureInvalid(e.to_string()))
    }
}

/// Verifier-only counterpart — holds only the public key.
pub struct Ed25519TokenVerifier {
    verifying_key: VerifyingKey,
}

impl Ed25519TokenVerifier {
    pub fn new(verifying_key: VerifyingKey) -> Self {
        Self { verifying_key }
    }
}

impl Ed25519TokenVerifier {
    pub fn verify<T: Serialize>(
        &self,
        value: &T,
        signature: &TokenSignature,
    ) -> Result<(), AegisError> {
        let bytes = canonical_json(value)?;
        self.verifying_key
            .verify(&bytes, signature.inner())
            .map_err(|e| AegisError::SignatureInvalid(e.to_string()))
    }
}
