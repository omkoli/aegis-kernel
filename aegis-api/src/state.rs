use std::sync::{Arc, OnceLock};

use aegis_audit::{AuditLog, InMemoryAuditStore};
use aegis_core::{
    DelegationService, Ed25519TokenSigner, EnforcementEngine, InMemoryTokenStore, IssuerConfig,
    TokenIssuer,
};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};

/// Global Prometheus handle — installed exactly once per process.
static PROMETHEUS: OnceLock<PrometheusHandle> = OnceLock::new();

fn init_prometheus() -> PrometheusHandle {
    PROMETHEUS
        .get_or_init(|| {
            PrometheusBuilder::new()
                .install_recorder()
                .expect("failed to install Prometheus recorder")
        })
        .clone()
}

/// Shared application state for the management API.
#[derive(Clone)]
pub struct AppState {
    pub issuer: Arc<TokenIssuer<Ed25519TokenSigner, InMemoryTokenStore>>,
    pub delegation: Arc<DelegationService<Ed25519TokenSigner, InMemoryTokenStore>>,
    pub engine: Arc<EnforcementEngine<Ed25519TokenSigner, InMemoryTokenStore>>,
    pub store: Arc<InMemoryTokenStore>,
    pub audit_log: AuditLog,
    /// Handle for rendering the Prometheus `/metrics` snapshot.
    pub prometheus: PrometheusHandle,
}

impl AppState {
    /// Creates a new `AppState` with fresh keys and an empty store.
    ///
    /// Installs the global Prometheus metrics recorder on first call.
    pub fn new() -> Self {
        Self::with_config(IssuerConfig::default())
    }

    /// Creates a new `AppState` with the given issuer config.
    ///
    /// Installs the global Prometheus metrics recorder (no-op if already installed).
    pub fn with_config(config: IssuerConfig) -> Self {
        let prometheus = init_prometheus();

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

        let audit_store = Arc::new(InMemoryAuditStore::new());
        let audit_log = AuditLog::new(audit_store);

        Self {
            issuer,
            delegation,
            engine,
            store,
            audit_log,
            prometheus,
        }
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}
