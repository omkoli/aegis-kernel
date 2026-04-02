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

/// A chain of [`InterceptionMiddleware`] implementations applied in order.
///
/// Each middleware in the chain sees the message in turn. The first middleware
/// that returns [`InterceptionResult::Block`] short-circuits the chain; no
/// subsequent middlewares are invoked.  If a middleware returns
/// [`InterceptionResult::Modify`] the modified message is passed to the next
/// middleware rather than the original.
///
/// An empty chain forwards every message unchanged.
pub struct MiddlewareChain {
    middlewares: Vec<std::sync::Arc<dyn InterceptionMiddleware>>,
}

impl MiddlewareChain {
    /// Create a new chain from an ordered list of middlewares.
    pub fn new(middlewares: Vec<std::sync::Arc<dyn InterceptionMiddleware>>) -> Self {
        Self { middlewares }
    }

    fn run<F>(&self, message: McpMessage, apply: F) -> InterceptionResult
    where
        F: Fn(&dyn InterceptionMiddleware, McpMessage) -> InterceptionResult,
    {
        let mut current = message;
        for mw in &self.middlewares {
            match apply(mw.as_ref(), current) {
                InterceptionResult::Forward(m) => current = m,
                InterceptionResult::Modify(m) => current = m,
                block @ InterceptionResult::Block(_) => return block,
            }
        }
        InterceptionResult::Forward(current)
    }
}

impl InterceptionMiddleware for MiddlewareChain {
    fn on_request(&self, message: McpMessage) -> InterceptionResult {
        self.run(message, |mw, msg| mw.on_request(msg))
    }

    fn on_response(&self, message: McpMessage) -> InterceptionResult {
        self.run(message, |mw, msg| mw.on_response(msg))
    }
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
    use std::sync::Arc;

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

    // -----------------------------------------------------------------------
    // MiddlewareChain tests
    // -----------------------------------------------------------------------

    /// A middleware that blocks every request with the given error code.
    struct BlockingMiddleware(i64);
    impl InterceptionMiddleware for BlockingMiddleware {
        fn on_request(&self, _message: McpMessage) -> InterceptionResult {
            InterceptionResult::Block(JsonRpcError {
                code: self.0,
                message: "blocked".into(),
                data: None,
            })
        }
        fn on_response(&self, message: McpMessage) -> InterceptionResult {
            InterceptionResult::Forward(message)
        }
    }

    /// A middleware that modifies every request by changing its method.
    struct ModifyingMiddleware(&'static str);
    impl InterceptionMiddleware for ModifyingMiddleware {
        fn on_request(&self, message: McpMessage) -> InterceptionResult {
            if let McpMessage::Request(mut req) = message {
                req.method = self.0.to_string();
                InterceptionResult::Modify(McpMessage::Request(req))
            } else {
                InterceptionResult::Forward(message)
            }
        }
        fn on_response(&self, message: McpMessage) -> InterceptionResult {
            InterceptionResult::Forward(message)
        }
    }

    fn make_request(method: &str) -> McpMessage {
        McpMessage::Request(McpRequest {
            jsonrpc: "2.0".into(),
            id: RequestId::Number(1),
            method: method.to_string(),
            params: None,
        })
    }

    #[test]
    fn empty_chain_forwards() {
        let chain = MiddlewareChain::new(vec![]);
        let msg = make_request("tools/list");
        assert!(matches!(chain.on_request(msg), InterceptionResult::Forward(_)));
    }

    #[test]
    fn single_passthrough_in_chain() {
        let chain = MiddlewareChain::new(vec![Arc::new(PassthroughMiddleware)]);
        let msg = make_request("tools/list");
        assert!(matches!(chain.on_request(msg), InterceptionResult::Forward(_)));
    }

    #[test]
    fn blocking_middleware_short_circuits() {
        let chain = MiddlewareChain::new(vec![
            Arc::new(BlockingMiddleware(-32008)),
            Arc::new(PassthroughMiddleware),
        ]);
        let result = chain.on_request(make_request("tools/call"));
        match result {
            InterceptionResult::Block(err) => assert_eq!(err.code, -32008),
            other => panic!("expected Block, got {:?}", other),
        }
    }

    #[test]
    fn first_block_prevents_second_middleware() {
        // Second middleware would block with a different code; first blocks first.
        let chain = MiddlewareChain::new(vec![
            Arc::new(BlockingMiddleware(-1)),
            Arc::new(BlockingMiddleware(-2)),
        ]);
        let result = chain.on_request(make_request("tools/call"));
        match result {
            InterceptionResult::Block(err) => assert_eq!(err.code, -1),
            other => panic!("expected Block(-1), got {:?}", other),
        }
    }

    #[test]
    fn modify_result_passed_to_next_middleware() {
        // First middleware renames method to "modified"; second would block any
        // method called "original" but passes "modified" — so no block expected.
        struct BlockIfOriginal;
        impl InterceptionMiddleware for BlockIfOriginal {
            fn on_request(&self, message: McpMessage) -> InterceptionResult {
                if let McpMessage::Request(ref req) = message {
                    if req.method == "original" {
                        return InterceptionResult::Block(JsonRpcError {
                            code: -99,
                            message: "blocked original".into(),
                            data: None,
                        });
                    }
                }
                InterceptionResult::Forward(message)
            }
            fn on_response(&self, message: McpMessage) -> InterceptionResult {
                InterceptionResult::Forward(message)
            }
        }

        let chain = MiddlewareChain::new(vec![
            Arc::new(ModifyingMiddleware("modified")),
            Arc::new(BlockIfOriginal),
        ]);
        let result = chain.on_request(make_request("original"));
        // First mw renamed it to "modified", so BlockIfOriginal passes it through
        assert!(matches!(result, InterceptionResult::Forward(_)));
    }

    #[test]
    fn chain_on_response_passes_through() {
        let chain = MiddlewareChain::new(vec![
            Arc::new(PassthroughMiddleware),
            Arc::new(PassthroughMiddleware),
        ]);
        let resp = McpMessage::Response(McpResponse {
            jsonrpc: "2.0".into(),
            id: RequestId::Number(1),
            result: Some(serde_json::json!({})),
            error: None,
        });
        assert!(matches!(chain.on_response(resp), InterceptionResult::Forward(_)));
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
