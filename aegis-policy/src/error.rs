/// Errors from the policy engine.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("failed to read policy file: {0}")]
    Io(#[from] std::io::Error),

    #[error("failed to parse YAML: {0}")]
    Yaml(#[from] serde_yaml::Error),

    #[error("policy '{name}': {reason}")]
    Validation { name: String, reason: String },

    #[error("duplicate policy name: '{0}'")]
    DuplicateName(String),

    #[error("core error: {0}")]
    Core(#[from] aegis_core::AegisError),

    #[error("watcher error: {0}")]
    Watcher(String),
}
