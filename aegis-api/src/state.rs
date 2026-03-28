use std::sync::{Arc, RwLock};

use aegis_core::{
    AuditEntry, DelegationService, Ed25519TokenSigner, EnforcementEngine, InMemoryTokenStore,
    IssuerConfig, TokenIssuer,
};

/// Shared application state for the management API.
#[derive(Clone)]
pub struct AppState {
    pub issuer: Arc<TokenIssuer<Ed25519TokenSigner, InMemoryTokenStore>>,
    pub delegation: Arc<DelegationService<Ed25519TokenSigner, InMemoryTokenStore>>,
    pub engine: Arc<EnforcementEngine<Ed25519TokenSigner, InMemoryTokenStore>>,
    pub store: Arc<InMemoryTokenStore>,
    pub audit_log: Arc<RwLock<Vec<AuditEntry>>>,
}

impl AppState {
    /// Creates a new `AppState` with fresh keys and an empty store.
    pub fn new() -> Self {
        Self::with_config(IssuerConfig::default())
    }

    /// Creates a new `AppState` with the given issuer config.
    pub fn with_config(config: IssuerConfig) -> Self {
        let signer = Ed25519TokenSigner::generate();
        let store = Arc::new(InMemoryTokenStore::new());
        let key_bytes = signer.signing_key_bytes();

        let issuer = Arc::new(TokenIssuer::new(
            Ed25519TokenSigner::from_bytes(&key_bytes),
            Arc::clone(&store),
            config,
        ));
        let delegation = Arc::new(DelegationService::new(
            Ed25519TokenSigner::from_bytes(&key_bytes),
            Arc::clone(&store),
        ));
        let engine = Arc::new(EnforcementEngine::new(
            Ed25519TokenSigner::from_bytes(&key_bytes),
            Arc::clone(&store),
        ));

        Self {
            issuer,
            delegation,
            engine,
            store,
            audit_log: Arc::new(RwLock::new(Vec::new())),
        }
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}
