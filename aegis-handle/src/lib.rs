//! # KernelHandle — MCP Gateway Embedding Interface
//!
//! `KernelHandle` is the single entry point that the MCP Gateway (S3–S4)
//! imports to evaluate tool calls against Aegis security policies.
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use aegis_handle::{KernelHandle, KernelConfig};
//!
//! // Build from a policy file
//! let handle = KernelHandle::from_policy_file("policies.yaml")
//!     .expect("failed to load policies");
//!
//! // Or build with full configuration
//! let handle = KernelHandle::builder()
//!     .policy_file("policies.yaml")
//!     .audit_capacity(500_000)
//!     .build()
//!     .expect("failed to build kernel");
//! ```
//!
//! ## Evaluating Tool Calls
//!
//! ```rust,ignore
//! let req = ToolCallRequest {
//!     agent_id: "finance-agent".into(),
//!     tool_name: "query_db".into(),
//!     action: Action::Read,
//!     resource: Resource::new("db://finance/transactions").unwrap(),
//!     parameters: [("amount".into(), "500".into())].into(),
//!     token_id: token_id, // obtained from issue_token()
//! };
//!
//! let result = handle.evaluate(&req);
//! // result.decision is Decision::Allow or Decision::Deny
//! // result.audit contains the full AuditEntry
//! ```
//!
//! ## MCP Gateway Integration
//!
//! The MCP Gateway should:
//!
//! 1. **Initialize** a `KernelHandle` at startup from a policy YAML file.
//! 2. **Issue tokens** for each agent session using policies compiled from YAML.
//! 3. **Evaluate** every tool call through `handle.evaluate()` before execution.
//! 4. **Query audit** logs for observability and compliance.
//! 5. **Reload policies** on configuration changes without restart.

mod config;
mod error;
mod handle;

pub use config::{KernelBuilder, KernelConfig};
pub use error::KernelError;
pub use handle::KernelHandle;

// Re-export key types that consumers need
pub use aegis_audit::{AuditQuery, Page, SortOrder};
pub use aegis_core::{
    Action, AegisError, AuditEntry, CapabilityToken, Constraints, Decision, EnforcementResult,
    IssuerConfig, ParamConstraint, Resource, SignedToken, TokenRequest, ToolCallRequest,
};
