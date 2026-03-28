use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{McpError, Result};

/// A JSON-RPC 2.0 request/response identifier.
/// Per the spec, this can be a string, a number, or null (for error
/// responses where the original request id could not be determined).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RequestId {
    Number(i64),
    String(String),
    Null,
}

/// A JSON-RPC 2.0 error object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

/// A JSON-RPC 2.0 request message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpRequest {
    pub jsonrpc: String,
    pub id: RequestId,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

/// A JSON-RPC 2.0 response message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpResponse {
    pub jsonrpc: String,
    pub id: RequestId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

/// A JSON-RPC 2.0 notification message (a request without an id).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpNotification {
    pub jsonrpc: String,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

/// Top-level MCP message envelope.
#[derive(Debug, Clone)]
pub enum McpMessage {
    Request(McpRequest),
    Response(McpResponse),
    Notification(McpNotification),
}

/// Extracted details from a `tools/call` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallRequest {
    pub name: String,
    #[serde(default)]
    pub arguments: Option<Value>,
}

/// Extracted details from a `resources/read` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceReadRequest {
    pub uri: String,
}

impl McpMessage {
    /// Returns `true` if this message is a `tools/call` request.
    pub fn is_tool_call(&self) -> bool {
        matches!(self, McpMessage::Request(r) if r.method == "tools/call")
    }

    /// Returns `true` if this message is a `resources/read` request.
    pub fn is_resource_read(&self) -> bool {
        matches!(self, McpMessage::Request(r) if r.method == "resources/read")
    }

    /// Returns `true` if this message is an `initialize` request.
    pub fn is_initialization(&self) -> bool {
        matches!(self, McpMessage::Request(r) if r.method == "initialize")
    }

    /// Returns `true` if this message is a notification.
    pub fn is_notification(&self) -> bool {
        matches!(self, McpMessage::Notification(_))
    }
}

/// Extract a `ToolCallRequest` from a `tools/call` request.
///
/// Returns `Some` only when the request method is `"tools/call"` and the
/// params contain a valid `name` field.
pub fn extract_tool_call(request: &McpRequest) -> Option<ToolCallRequest> {
    if request.method != "tools/call" {
        return None;
    }
    let params = request.params.as_ref()?;
    let name = params.get("name")?.as_str()?;
    Some(ToolCallRequest {
        name: name.to_owned(),
        arguments: params.get("arguments").cloned(),
    })
}

/// Extract a `ResourceReadRequest` from a `resources/read` request.
///
/// Returns `Some` only when the request method is `"resources/read"` and
/// the params contain a valid `uri` field.
pub fn extract_resource_read(request: &McpRequest) -> Option<ResourceReadRequest> {
    if request.method != "resources/read" {
        return None;
    }
    let params = request.params.as_ref()?;
    let uri = params.get("uri")?.as_str()?;
    Some(ResourceReadRequest {
        uri: uri.to_owned(),
    })
}

/// Parse raw bytes into a typed MCP message.
///
/// Distinguishes between Request, Response, and Notification by inspecting
/// the presence of `id`, `method`, `result`, and `error` fields in the
/// JSON-RPC 2.0 envelope.
pub fn parse_message(bytes: &[u8]) -> Result<McpMessage> {
    let raw: Value = serde_json::from_slice(bytes).map_err(McpError::InvalidJson)?;

    let obj = raw.as_object().ok_or(McpError::NotAnObject)?;

    let has_id = obj.contains_key("id");
    let has_method = obj.contains_key("method");
    let has_result = obj.contains_key("result");
    let has_error = obj.contains_key("error");

    if has_id && has_method {
        // Request: has both id and method
        let request: McpRequest =
            serde_json::from_value(raw).map_err(McpError::InvalidJson)?;
        Ok(McpMessage::Request(request))
    } else if has_id && (has_result || has_error) {
        // Response: has id and either result or error
        let response: McpResponse =
            serde_json::from_value(raw).map_err(McpError::InvalidJson)?;
        Ok(McpMessage::Response(response))
    } else if has_method && !has_id {
        // Notification: has method but no id
        let notification: McpNotification =
            serde_json::from_value(raw).map_err(McpError::InvalidJson)?;
        Ok(McpMessage::Notification(notification))
    } else {
        Err(McpError::UnrecognizedMessage)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_request_with_number_id() {
        let json = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"capabilities":{}}}"#;
        let msg = parse_message(json.as_bytes()).unwrap();
        match msg {
            McpMessage::Request(req) => {
                assert_eq!(req.jsonrpc, "2.0");
                assert_eq!(req.id, RequestId::Number(1));
                assert_eq!(req.method, "initialize");
                assert!(req.params.is_some());
            }
            _ => panic!("expected Request"),
        }
    }

    #[test]
    fn parse_request_with_string_id() {
        let json = r#"{"jsonrpc":"2.0","id":"abc-123","method":"tools/list"}"#;
        let msg = parse_message(json.as_bytes()).unwrap();
        match msg {
            McpMessage::Request(req) => {
                assert_eq!(req.id, RequestId::String("abc-123".into()));
                assert_eq!(req.method, "tools/list");
                assert!(req.params.is_none());
            }
            _ => panic!("expected Request"),
        }
    }

    #[test]
    fn parse_success_response() {
        let json = r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05"}}"#;
        let msg = parse_message(json.as_bytes()).unwrap();
        match msg {
            McpMessage::Response(resp) => {
                assert_eq!(resp.id, RequestId::Number(1));
                assert!(resp.result.is_some());
                assert!(resp.error.is_none());
            }
            _ => panic!("expected Response"),
        }
    }

    #[test]
    fn parse_error_response() {
        let json = r#"{"jsonrpc":"2.0","id":2,"error":{"code":-32601,"message":"Method not found"}}"#;
        let msg = parse_message(json.as_bytes()).unwrap();
        match msg {
            McpMessage::Response(resp) => {
                assert_eq!(resp.id, RequestId::Number(2));
                assert!(resp.result.is_none());
                let err = resp.error.as_ref().unwrap();
                assert_eq!(err.code, -32601);
                assert_eq!(err.message, "Method not found");
            }
            _ => panic!("expected Response"),
        }
    }

    #[test]
    fn parse_notification() {
        let json = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
        let msg = parse_message(json.as_bytes()).unwrap();
        match msg {
            McpMessage::Notification(notif) => {
                assert_eq!(notif.method, "notifications/initialized");
                assert!(notif.params.is_none());
            }
            _ => panic!("expected Notification"),
        }
    }

    #[test]
    fn parse_notification_with_params() {
        let json =
            r#"{"jsonrpc":"2.0","method":"notifications/progress","params":{"token":"x","value":50}}"#;
        let msg = parse_message(json.as_bytes()).unwrap();
        match msg {
            McpMessage::Notification(notif) => {
                assert_eq!(notif.method, "notifications/progress");
                assert!(notif.params.is_some());
            }
            _ => panic!("expected Notification"),
        }
    }

    #[test]
    fn parse_invalid_json() {
        let result = parse_message(b"not json");
        assert!(result.is_err());
    }

    #[test]
    fn parse_non_object() {
        let result = parse_message(b"[1, 2, 3]");
        assert!(result.is_err());
    }

    #[test]
    fn parse_unrecognized_message() {
        let json = r#"{"jsonrpc":"2.0","id":1}"#;
        let result = parse_message(json.as_bytes());
        assert!(result.is_err());
    }

    // --- extract_tool_call tests ---

    #[test]
    fn extract_tool_call_valid() {
        let req = McpRequest {
            jsonrpc: "2.0".into(),
            id: RequestId::Number(1),
            method: "tools/call".into(),
            params: Some(serde_json::json!({"name": "read_file", "arguments": {"path": "/tmp/x"}})),
        };
        let tc = extract_tool_call(&req).unwrap();
        assert_eq!(tc.name, "read_file");
        assert!(tc.arguments.is_some());
    }

    #[test]
    fn extract_tool_call_wrong_method() {
        let req = McpRequest {
            jsonrpc: "2.0".into(),
            id: RequestId::Number(1),
            method: "tools/list".into(),
            params: Some(serde_json::json!({"name": "read_file"})),
        };
        assert!(extract_tool_call(&req).is_none());
    }

    #[test]
    fn extract_tool_call_no_params() {
        let req = McpRequest {
            jsonrpc: "2.0".into(),
            id: RequestId::Number(1),
            method: "tools/call".into(),
            params: None,
        };
        assert!(extract_tool_call(&req).is_none());
    }

    // --- extract_resource_read tests ---

    #[test]
    fn extract_resource_read_valid() {
        let req = McpRequest {
            jsonrpc: "2.0".into(),
            id: RequestId::Number(1),
            method: "resources/read".into(),
            params: Some(serde_json::json!({"uri": "file:///etc/hosts"})),
        };
        let rr = extract_resource_read(&req).unwrap();
        assert_eq!(rr.uri, "file:///etc/hosts");
    }

    #[test]
    fn extract_resource_read_wrong_method() {
        let req = McpRequest {
            jsonrpc: "2.0".into(),
            id: RequestId::Number(1),
            method: "resources/list".into(),
            params: Some(serde_json::json!({"uri": "file:///etc/hosts"})),
        };
        assert!(extract_resource_read(&req).is_none());
    }

    // --- classifier tests ---

    #[test]
    fn classifier_is_tool_call() {
        let json = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x"}}"#;
        let msg = parse_message(json.as_bytes()).unwrap();
        assert!(msg.is_tool_call());
        assert!(!msg.is_resource_read());
        assert!(!msg.is_initialization());
        assert!(!msg.is_notification());
    }

    #[test]
    fn classifier_is_resource_read() {
        let json = r#"{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"x"}}"#;
        let msg = parse_message(json.as_bytes()).unwrap();
        assert!(msg.is_resource_read());
        assert!(!msg.is_tool_call());
    }

    #[test]
    fn classifier_is_initialization() {
        let json = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
        let msg = parse_message(json.as_bytes()).unwrap();
        assert!(msg.is_initialization());
        assert!(!msg.is_tool_call());
    }

    #[test]
    fn classifier_is_notification() {
        let json = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
        let msg = parse_message(json.as_bytes()).unwrap();
        assert!(msg.is_notification());
        assert!(!msg.is_tool_call());
    }

    #[test]
    fn classifier_response_all_false() {
        let json = r#"{"jsonrpc":"2.0","id":1,"result":{}}"#;
        let msg = parse_message(json.as_bytes()).unwrap();
        assert!(!msg.is_tool_call());
        assert!(!msg.is_resource_read());
        assert!(!msg.is_initialization());
        assert!(!msg.is_notification());
    }
}
