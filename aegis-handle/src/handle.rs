//! The `KernelHandle` — single entry point for MCP Gateway embedding.

use std::path::Path;
use std::sync::Arc;

use uuid::Uuid;

use aegis_audit::{AuditLog, AuditQuery, InMemoryAuditStore, Page};
use aegis_core::{
    AuditEntry, DelegationRequest, DelegationService, Ed25519TokenSigner, EnforcementEngine,
    EnforcementResult, InMemoryTokenStore, SignedToken, TokenIssuer, TokenRequest, TokenStore,
    ToolCallRequest,
};
use aegis_policy::PolicyCompiler;

use crate::config::{KernelBuilder, KernelConfig};
use crate::error::KernelError;

/// The single entry point for MCP Gateway embedding.
///
/// Wraps the enforcement engine, token issuer, delegation service,
/// policy compiler, and audit log behind a unified, thread-safe API.
///
/// All methods are `&self` — `KernelHandle` is `Send + Sync` and
/// can be shared across threads via `Arc<KernelHandle>`.
pub struct KernelHandle {
    engine: Arc<EnforcementEngine<Ed25519TokenSigner, InMemoryTokenStore>>,
    issuer: Arc<TokenIssuer<Ed25519TokenSigner, InMemoryTokenStore>>,
    delegation: Arc<DelegationService<Ed25519TokenSigner, InMemoryTokenStore>>,
    store: Arc<InMemoryTokenStore>,
    compiler: PolicyCompiler,
    audit_log: AuditLog,
    key_bytes: [u8; 32],
}

impl KernelHandle {
    /// Creates a new `KernelHandle` with default configuration and no policies.
    pub fn new() -> Self {
        Self::from_config(KernelConfig::default()).expect("default config should not fail")
    }

    /// Creates a `KernelHandle` from a policy YAML file or directory.
    pub fn from_policy_file(path: impl AsRef<Path>) -> Result<Self, KernelError> {
        KernelBuilder::new().policy_file(path.as_ref()).build()
    }

    /// Creates a `KernelHandle` from an inline YAML policy string.
    pub fn from_policy_yaml(yaml: &str) -> Result<Self, KernelError> {
        KernelBuilder::new().policy_yaml(yaml).build()
    }

    /// Returns a fluent builder for constructing a `KernelHandle`.
    pub fn builder() -> KernelBuilder {
        KernelBuilder::new()
    }

    /// Constructs from a full `KernelConfig`.
    pub(crate) fn from_config(config: KernelConfig) -> Result<Self, KernelError> {
        let signer = Ed25519TokenSigner::generate();
        let key_bytes = signer.signing_key_bytes();
        let store = Arc::new(InMemoryTokenStore::new());

        let issuer = Arc::new(TokenIssuer::new(
            Ed25519TokenSigner::from_bytes(&key_bytes),
            Arc::clone(&store),
            config.issuer_config,
        ));
        let delegation = Arc::new(DelegationService::new(
            Ed25519TokenSigner::from_bytes(&key_bytes),
            Arc::clone(&store),
        ));
        let engine = Arc::new(EnforcementEngine::new(
            Ed25519TokenSigner::from_bytes(&key_bytes),
            Arc::clone(&store),
        ));
        let audit_store = Arc::new(InMemoryAuditStore::with_capacity(config.audit_capacity));
        let audit_log = AuditLog::new(audit_store);
        let compiler = PolicyCompiler::new();

        let handle = Self {
            engine,
            issuer,
            delegation,
            store,
            compiler,
            audit_log,
            key_bytes,
        };

        // Load initial policies
        if let Some(ref yaml) = config.policy_yaml {
            let requests = handle.compiler.compile_str(yaml)?;
            for req in requests {
                handle.issuer.issue(req)?;
            }
        } else if let Some(ref path) = config.policy_path {
            let requests = handle.compiler.compile_file(path)?;
            for req in requests {
                handle.issuer.issue(req)?;
            }
        }

        Ok(handle)
    }

    // ── Core API ────────────────────────────────────���──────────────────

    /// Evaluates a tool-call request against the security policy.
    ///
    /// This is the primary method the MCP Gateway calls for every tool invocation.
    /// Returns an `EnforcementResult` containing the `Decision` (Allow/Deny)
    /// and a full `AuditEntry`.
    pub fn evaluate(&self, req: &ToolCallRequest) -> EnforcementResult {
        let result = self.engine.enforce(req);
        self.audit_log.append(result.audit.clone());
        result
    }

    /// Issues a new capability token from a `TokenRequest`.
    ///
    /// The MCP Gateway calls this when an agent session starts or when
    /// policies grant a new capability.
    pub fn issue_token(&self, req: TokenRequest) -> Result<SignedToken, KernelError> {
        Ok(self.issuer.issue(req)?)
    }

    /// Retrieves a token by ID.
    pub fn get_token(&self, id: Uuid) -> Result<SignedToken, KernelError> {
        Ok(self.issuer.get(id)?)
    }

    /// Lists all active tokens.
    pub fn list_tokens(&self) -> Vec<SignedToken> {
        self.issuer.list()
    }

    /// Deletes a token by ID.
    pub fn delete_token(&self, id: Uuid) -> Result<SignedToken, KernelError> {
        Ok(self.issuer.delete(id)?)
    }

    /// Revokes a token and all its descendants (cascading revocation).
    ///
    /// Returns the list of all revoked token IDs.
    pub fn revoke_token(&self, id: Uuid) -> Result<Vec<Uuid>, KernelError> {
        Ok(self.delegation.revoke_cascade(id)?)
    }

    /// Delegates a token to a new subject with narrowed scope.
    pub fn delegate_token(&self, req: DelegationRequest) -> Result<SignedToken, KernelError> {
        Ok(self.delegation.delegate(req)?)
    }

    // ── Policy Management ──────────────────────────────────────────────

    /// Reloads policies from a YAML string.
    ///
    /// Compiles the YAML and issues tokens for each policy rule.
    /// Previously issued tokens remain valid; this adds new ones.
    pub fn load_policies_yaml(&self, yaml: &str) -> Result<Vec<SignedToken>, KernelError> {
        let requests = self.compiler.compile_str(yaml)?;
        let mut tokens = Vec::with_capacity(requests.len());
        for req in requests {
            tokens.push(self.issuer.issue(req)?);
        }
        Ok(tokens)
    }

    /// Reloads policies from a file or directory.
    pub fn load_policies_file(&self, path: &Path) -> Result<Vec<SignedToken>, KernelError> {
        let requests = self.compiler.compile_file(path)?;
        let mut tokens = Vec::with_capacity(requests.len());
        for req in requests {
            tokens.push(self.issuer.issue(req)?);
        }
        Ok(tokens)
    }

    /// Compiles a policy YAML string into `TokenRequest`s without issuing.
    ///
    /// Useful for dry-run / validation.
    pub fn compile_policies(&self, yaml: &str) -> Result<Vec<TokenRequest>, KernelError> {
        Ok(self.compiler.compile_str(yaml)?)
    }

    // ── Audit ──────────────────────────────────────────────────────────

    /// Queries the audit log with filters and pagination.
    pub fn query_audit(&self, query: &AuditQuery) -> Page {
        self.audit_log.query(query)
    }

    /// Returns all audit entries (oldest first).
    pub fn audit_entries(&self) -> Vec<AuditEntry> {
        self.audit_log.all()
    }

    /// Returns the number of audit entries.
    pub fn audit_len(&self) -> usize {
        self.audit_log.len()
    }

    /// Clears all audit entries.
    pub fn clear_audit(&self) {
        self.audit_log.clear();
    }

    /// Exports audit log as JSON Lines to a writer.
    pub fn export_audit<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<usize> {
        aegis_audit::JsonLinesExporter::export_all(self.audit_log.store(), writer)
    }

    // ── Accessors ────────────────────────────────────────��─────────────

    /// Returns the number of active tokens in the store.
    pub fn token_count(&self) -> usize {
        self.store.len()
    }

    /// Returns the raw signing key bytes (for advanced use cases).
    pub fn signing_key_bytes(&self) -> [u8; 32] {
        self.key_bytes
    }
}

impl Default for KernelHandle {
    fn default() -> Self {
        Self::new()
    }
}

// KernelHandle is Send + Sync because all inner types are
// (Arc types, parking_lot locks, DashMap).
// This static assertion ensures it.
fn _assert_send_sync<T: Send + Sync>() {}
const _: fn() = || _assert_send_sync::<KernelHandle>();
