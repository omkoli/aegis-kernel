//! Builder and configuration for `KernelHandle`.

use std::path::PathBuf;

use aegis_audit::store::DEFAULT_CAPACITY;
use aegis_core::IssuerConfig;

use crate::error::KernelError;
use crate::handle::KernelHandle;

/// Configuration for building a `KernelHandle`.
#[derive(Debug, Clone)]
pub struct KernelConfig {
    /// Path to a YAML policy file or directory.
    pub policy_path: Option<PathBuf>,
    /// Inline YAML policy string (alternative to file).
    pub policy_yaml: Option<String>,
    /// Audit ring buffer capacity.
    pub audit_capacity: usize,
    /// Token issuer configuration.
    pub issuer_config: IssuerConfig,
}

impl Default for KernelConfig {
    fn default() -> Self {
        Self {
            policy_path: None,
            policy_yaml: None,
            audit_capacity: DEFAULT_CAPACITY,
            issuer_config: IssuerConfig::default(),
        }
    }
}

/// Fluent builder for `KernelHandle`.
#[derive(Debug, Default)]
pub struct KernelBuilder {
    config: KernelConfig,
}

impl KernelBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the policy file or directory path.
    pub fn policy_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.config.policy_path = Some(path.into());
        self
    }

    /// Set an inline YAML policy string.
    pub fn policy_yaml(mut self, yaml: impl Into<String>) -> Self {
        self.config.policy_yaml = Some(yaml.into());
        self
    }

    /// Set the audit ring buffer capacity.
    pub fn audit_capacity(mut self, capacity: usize) -> Self {
        self.config.audit_capacity = capacity;
        self
    }

    /// Set the token issuer configuration.
    pub fn issuer_config(mut self, config: IssuerConfig) -> Self {
        self.config.issuer_config = config;
        self
    }

    /// Build the `KernelHandle`.
    pub fn build(self) -> Result<KernelHandle, KernelError> {
        KernelHandle::from_config(self.config)
    }
}
