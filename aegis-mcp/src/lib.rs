pub mod error;
pub mod framing;
pub mod message;
pub mod translate;

pub use error::{McpError, Result};
pub use framing::{
    read_all_sse, read_all_stdio, SseFrameReader, SseFrameWriter, StdioFrameReader,
    StdioFrameWriter,
};
pub use message::{
    extract_resource_read, extract_tool_call, parse_message, JsonRpcError, McpMessage,
    McpNotification, McpRequest, McpResponse, RequestId, ResourceReadRequest, ToolCallRequest,
};
pub use translate::{
    denial_to_response, translate_to_intent, AgentContext, DenyReason, EnforcementDecision,
    IntentKind, ResourceReadIntent, ToolCallIntent, AEGIS_ERROR_BASE, AEGIS_ERROR_CONSTRAINT_VIOLATION,
    AEGIS_ERROR_DENIED, AEGIS_ERROR_RATE_LIMITED, AEGIS_ERROR_SCOPE_EXCEEDED,
    AEGIS_ERROR_TOKEN_EXPIRED, AEGIS_ERROR_TOKEN_REVOKED, AEGIS_ERROR_UNAUTHORIZED,
    AEGIS_ERROR_UNKNOWN_METHOD,
};
