//! Interception middleware for MCP proxy message pipelines.
//!
//! Every message flowing through the proxy (stdio or SSE) can be inspected,
//! modified, or blocked by an [`InterceptionMiddleware`] implementation.
//!
//! The default [`PassthroughMiddleware`] forwards everything unchanged,
//! useful for testing the pipeline without any policy logic.

use aegis_mcp::{JsonRpcError, McpMessage, McpResponse, RequestId};

/// The result of running a message through an interception middleware.
#[derive(Debug)]
pub enum InterceptionResult {
    /// Forward the (possibly original) message to the next stage.
    Forward(McpMessage),
    /// Block the message and return a JSON-RPC error to the caller.
    Block(JsonRpcError),
    /// Replace the message with a modified version before forwarding.
    Modify(McpMessage),
}

/// Trait for middleware that can inspect, modify, or block MCP messages.
///
/// Implementors receive every message flowing through the proxy in both
/// directions and return an [`InterceptionResult`] to control what happens.
///
/// Methods take `&self` so middleware can be shared behind `Arc`.
pub trait InterceptionMiddleware: Send + Sync {
    /// Called for messages flowing from the agent toward the MCP server
    /// (requests and notifications sent by the agent).
    fn on_request(&self, message: McpMessage) -> InterceptionResult;

    /// Called for messages flowing from the MCP server back toward the agent
    /// (responses and notifications from the server).
    fn on_response(&self, message: McpMessage) -> InterceptionResult;
}

/// A middleware that forwards every message unchanged.
///
/// Useful as a default or for testing the middleware pipeline.
pub struct PassthroughMiddleware;

impl InterceptionMiddleware for PassthroughMiddleware {
    fn on_request(&self, message: McpMessage) -> InterceptionResult {
        InterceptionResult::Forward(message)
    }

    fn on_response(&self, message: McpMessage) -> InterceptionResult {
        InterceptionResult::Forward(message)
    }
}

/// Extract the request ID from an MCP message, if it has one.
pub fn extract_id(message: &McpMessage) -> Option<RequestId> {
    match message {
        McpMessage::Request(r) => Some(r.id.clone()),
        McpMessage::Response(r) => Some(r.id.clone()),
        McpMessage::Notification(_) => None,
    }
}

/// Build a JSON-RPC error response for a blocked request.
///
/// Returns `None` for notifications (which have no id and expect no response).
pub fn block_response(message: &McpMessage, error: JsonRpcError) -> Option<McpMessage> {
    let id = extract_id(message)?;
    // Only requests should get error responses; if we somehow block a
    // response or notification, there's no one to send the error to.
    if !matches!(message, McpMessage::Request(_)) {
        return None;
    }
    Some(McpMessage::Response(McpResponse {
        jsonrpc: "2.0".to_string(),
        id,
        result: None,
        error: Some(error),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_mcp::{McpNotification, McpRequest, RequestId};

    #[test]
    fn passthrough_forwards_request() {
        let mw = PassthroughMiddleware;
        let msg = McpMessage::Request(McpRequest {
            jsonrpc: "2.0".into(),
            id: RequestId::Number(1),
            method: "tools/list".into(),
            params: None,
        });
        let result = mw.on_request(msg);
        assert!(matches!(result, InterceptionResult::Forward(_)));
    }

    #[test]
    fn passthrough_forwards_response() {
        let mw = PassthroughMiddleware;
        let msg = McpMessage::Response(McpResponse {
            jsonrpc: "2.0".into(),
            id: RequestId::Number(1),
            result: Some(serde_json::json!({})),
            error: None,
        });
        let result = mw.on_response(msg);
        assert!(matches!(result, InterceptionResult::Forward(_)));
    }

    #[test]
    fn passthrough_forwards_notification() {
        let mw = PassthroughMiddleware;
        let msg = McpMessage::Notification(McpNotification {
            jsonrpc: "2.0".into(),
            method: "notifications/initialized".into(),
            params: None,
        });
        let result = mw.on_request(msg);
        assert!(matches!(result, InterceptionResult::Forward(_)));
    }

    #[test]
    fn extract_id_from_request() {
        let msg = McpMessage::Request(McpRequest {
            jsonrpc: "2.0".into(),
            id: RequestId::Number(42),
            method: "test".into(),
            params: None,
        });
        assert_eq!(extract_id(&msg), Some(RequestId::Number(42)));
    }

    #[test]
    fn extract_id_from_notification_is_none() {
        let msg = McpMessage::Notification(McpNotification {
            jsonrpc: "2.0".into(),
            method: "test".into(),
            params: None,
        });
        assert_eq!(extract_id(&msg), None);
    }

    #[test]
    fn block_response_for_request() {
        let msg = McpMessage::Request(McpRequest {
            jsonrpc: "2.0".into(),
            id: RequestId::Number(5),
            method: "tools/call".into(),
            params: None,
        });
        let err = JsonRpcError {
            code: -32600,
            message: "blocked".into(),
            data: None,
        };
        let resp = block_response(&msg, err).unwrap();
        match resp {
            McpMessage::Response(r) => {
                assert_eq!(r.id, RequestId::Number(5));
                assert!(r.error.is_some());
                assert_eq!(r.error.unwrap().code, -32600);
            }
            _ => panic!("expected Response"),
        }
    }

    #[test]
    fn block_response_for_notification_is_none() {
        let msg = McpMessage::Notification(McpNotification {
            jsonrpc: "2.0".into(),
            method: "notifications/progress".into(),
            params: None,
        });
        let err = JsonRpcError {
            code: -32600,
            message: "blocked".into(),
            data: None,
        };
        assert!(block_response(&msg, err).is_none());
    }
}
