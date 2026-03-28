/// Errors from the kernel handle.
#[derive(Debug, thiserror::Error)]
pub enum KernelError {
    #[error("core error: {0}")]
    Core(#[from] aegis_core::AegisError),

    #[error("policy error: {0}")]
    Policy(#[from] aegis_policy::PolicyError),

    #[error("no policies loaded")]
    NoPolicies,

    #[error("policy not found: {0}")]
    PolicyNotFound(String),

    #[error("configuration error: {0}")]
    Config(String),
}
