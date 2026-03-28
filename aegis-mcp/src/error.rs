use thiserror::Error;

/// Errors that can occur when parsing MCP messages.
#[derive(Debug, Error)]
pub enum McpError {
    #[error("invalid JSON: {0}")]
    InvalidJson(#[source] serde_json::Error),

    #[error("message is not a JSON object")]
    NotAnObject,

    #[error("unrecognized message structure")]
    UnrecognizedMessage,
}

pub type Result<T> = std::result::Result<T, McpError>;
