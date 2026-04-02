pub mod audit;
pub mod config;
pub mod identity;
pub mod metrics;
pub mod proxy;
pub mod ratelimit;

pub use audit::{
    genesis_hash, hash_record, new_trace_id, redact_parameters, spawn_audit_writer, verify_chain,
    AuditDecision, AuditError, AuditRecord, AuditWriterConfig, AuditWriterHandle, UpstreamStatus,
    GENESIS_INPUT,
};
pub use config::IdentityStrategy;
pub use identity::{
    AgentIdentifier, ConnectionContext, HeaderAgentIdentifier, ProcessAgentIdentifier,
    TokenAgentIdentifier, Transport, AEGIS_TOKEN_HEADER,
};
pub use proxy::{AllowlistMiddleware, AEGIS_ERROR_NOT_ALLOWED};
pub use proxy::{MiddlewareChain, InterceptionMiddleware, InterceptionResult};
pub use proxy::{RateLimiter, RateLimiterMiddleware, AEGIS_ERROR_RATE_LIMITED};
pub use ratelimit::{AgentId, RateLimitExceeded, ServerName, SlidingWindowCounter, WindowState};
