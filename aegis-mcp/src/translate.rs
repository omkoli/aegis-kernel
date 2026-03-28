//! Translation between MCP protocol messages and kernel-level intents.
//!
//! This module bridges the MCP JSON-RPC world and the Aegis enforcement
//! engine by converting parsed MCP requests into structured intents and
//! converting enforcement decisions back into MCP responses.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

use crate::message::{
    extract_resource_read, extract_tool_call, JsonRpcError, McpRequest, McpResponse, RequestId,
};

// ---------------------------------------------------------------------------
// Aegis-specific JSON-RPC error codes
// ---------------------------------------------------------------------------

/// JSON-RPC server error range base for Aegis (-32000 to -32099).
pub const AEGIS_ERROR_BASE: i64 = -32000;

/// The tool call was denied by policy enforcement.
pub const AEGIS_ERROR_DENIED: i64 = -32001;

/// The agent's capability token has expired.
pub const AEGIS_ERROR_TOKEN_EXPIRED: i64 = -32002;

/// The agent's capability token has been revoked.
pub const AEGIS_ERROR_TOKEN_REVOKED: i64 = -32003;

/// The agent is not authorized (no valid token presented).
pub const AEGIS_ERROR_UNAUTHORIZED: i64 = -32004;

/// The requested action exceeds the token's scope.
pub const AEGIS_ERROR_SCOPE_EXCEEDED: i64 = -32005;

/// A parameter constraint on the capability token was violated.
pub const AEGIS_ERROR_CONSTRAINT_VIOLATION: i64 = -32006;

/// The method in the request is not recognized for translation.
pub const AEGIS_ERROR_UNKNOWN_METHOD: i64 = -32007;

// ---------------------------------------------------------------------------
// AgentContext
// ---------------------------------------------------------------------------

/// Contextual information about the agent making an MCP request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentContext {
    /// Unique identifier for the agent.
    pub agent_id: String,
    /// Capability token ID the agent is presenting for authorization.
    pub token_id: String,
}

// ---------------------------------------------------------------------------
// ToolCallIntent / ResourceReadIntent
// ---------------------------------------------------------------------------

/// A kernel-level intent translated from an MCP `tools/call` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallIntent {
    /// The agent making the call.
    pub agent_id: String,
    /// Capability token presented.
    pub token_id: String,
    /// Name of the tool being invoked.
    pub tool_name: String,
    /// Flat key-value parameters extracted from the tool call arguments.
    /// Nested values are JSON-serialized strings.
    pub parameters: HashMap<String, String>,
    /// The original request ID so we can correlate the response.
    pub request_id: RequestId,
    /// The raw arguments value (preserved for forwarding).
    pub raw_arguments: Option<Value>,
}

/// A kernel-level intent translated from an MCP `resources/read` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceReadIntent {
    /// The agent making the call.
    pub agent_id: String,
    /// Capability token presented.
    pub token_id: String,
    /// The resource URI being read.
    pub uri: String,
    /// The original request ID so we can correlate the response.
    pub request_id: RequestId,
}

/// Union of all translatable intent kinds.
#[derive(Debug, Clone)]
pub enum IntentKind {
    ToolCall(ToolCallIntent),
    ResourceRead(ResourceReadIntent),
}

// ---------------------------------------------------------------------------
// EnforcementDecision
// ---------------------------------------------------------------------------

/// The outcome of an enforcement check, used to build an MCP response.
#[derive(Debug, Clone)]
pub enum EnforcementDecision {
    /// The request is allowed — the gateway should forward it.
    Allow,
    /// The request is denied.
    Deny(DenyReason),
}

/// Details about why a request was denied.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DenyReason {
    /// Aegis error code (one of the `AEGIS_ERROR_*` constants).
    pub code: i64,
    /// Human-readable explanation.
    pub reason: String,
}

impl DenyReason {
    pub fn policy(reason: impl Into<String>) -> Self {
        Self {
            code: AEGIS_ERROR_DENIED,
            reason: reason.into(),
        }
    }

    pub fn token_expired(reason: impl Into<String>) -> Self {
        Self {
            code: AEGIS_ERROR_TOKEN_EXPIRED,
            reason: reason.into(),
        }
    }

    pub fn token_revoked(reason: impl Into<String>) -> Self {
        Self {
            code: AEGIS_ERROR_TOKEN_REVOKED,
            reason: reason.into(),
        }
    }

    pub fn unauthorized(reason: impl Into<String>) -> Self {
        Self {
            code: AEGIS_ERROR_UNAUTHORIZED,
            reason: reason.into(),
        }
    }

    pub fn scope_exceeded(reason: impl Into<String>) -> Self {
        Self {
            code: AEGIS_ERROR_SCOPE_EXCEEDED,
            reason: reason.into(),
        }
    }

    pub fn constraint_violation(reason: impl Into<String>) -> Self {
        Self {
            code: AEGIS_ERROR_CONSTRAINT_VIOLATION,
            reason: reason.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// Translation: MCP request → intent
// ---------------------------------------------------------------------------

/// Translate an MCP request into a kernel-level intent.
///
/// Returns `Some(IntentKind)` for `tools/call` and `resources/read` requests.
/// Returns `None` for unrecognized methods (initialize, tools/list, etc.)
/// which should be forwarded without enforcement.
pub fn translate_to_intent(
    request: &McpRequest,
    context: &AgentContext,
) -> Option<IntentKind> {
    if let Some(tc) = extract_tool_call(request) {
        let parameters = flatten_arguments(&tc.arguments);
        return Some(IntentKind::ToolCall(ToolCallIntent {
            agent_id: context.agent_id.clone(),
            token_id: context.token_id.clone(),
            tool_name: tc.name,
            parameters,
            request_id: request.id.clone(),
            raw_arguments: tc.arguments,
        }));
    }

    if let Some(rr) = extract_resource_read(request) {
        return Some(IntentKind::ResourceRead(ResourceReadIntent {
            agent_id: context.agent_id.clone(),
            token_id: context.token_id.clone(),
            uri: rr.uri,
            request_id: request.id.clone(),
        }));
    }

    None
}

/// Flatten a JSON arguments object into a `HashMap<String, String>`.
///
/// Top-level string values are kept as-is. All other types (numbers,
/// booleans, objects, arrays, null) are serialized to their JSON string
/// representation so the kernel can apply parameter constraints uniformly.
fn flatten_arguments(args: &Option<Value>) -> HashMap<String, String> {
    let mut map = HashMap::new();
    if let Some(Value::Object(obj)) = args {
        for (k, v) in obj {
            let s = match v {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            map.insert(k.clone(), s);
        }
    }
    map
}

// ---------------------------------------------------------------------------
// Translation: enforcement decision → MCP response
// ---------------------------------------------------------------------------

/// Build an MCP error response from an enforcement denial.
///
/// The JSON-RPC error `code` is the Aegis-specific code from the
/// `DenyReason`, the `message` is the human-readable reason, and the
/// `data` field carries structured Aegis metadata.
pub fn denial_to_response(request_id: RequestId, deny: &DenyReason) -> McpResponse {
    McpResponse {
        jsonrpc: "2.0".into(),
        id: request_id,
        result: None,
        error: Some(JsonRpcError {
            code: deny.code,
            message: deny.reason.clone(),
            data: Some(serde_json::json!({
                "aegis": true,
                "sub_code": deny.code,
            })),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::{parse_message, McpMessage};

    fn agent_ctx() -> AgentContext {
        AgentContext {
            agent_id: "agent-007".into(),
            token_id: "tok-abc-123".into(),
        }
    }

    fn parse_request(json: &str) -> McpRequest {
        match parse_message(json.as_bytes()).unwrap() {
            McpMessage::Request(r) => r,
            _ => panic!("expected request"),
        }
    }

    // -----------------------------------------------------------------------
    // 1. Normal tool call translation
    // -----------------------------------------------------------------------
    #[test]
    fn translate_normal_tool_call() {
        let req = parse_request(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/test.txt"}}}"#,
        );
        let intent = translate_to_intent(&req, &agent_ctx()).unwrap();
        match intent {
            IntentKind::ToolCall(tc) => {
                assert_eq!(tc.agent_id, "agent-007");
                assert_eq!(tc.token_id, "tok-abc-123");
                assert_eq!(tc.tool_name, "read_file");
                assert_eq!(tc.parameters.get("path").unwrap(), "/tmp/test.txt");
                assert_eq!(tc.request_id, RequestId::Number(1));
            }
            _ => panic!("expected ToolCall"),
        }
    }

    // -----------------------------------------------------------------------
    // 2. Tool call with nested arguments
    // -----------------------------------------------------------------------
    #[test]
    fn translate_tool_call_nested_arguments() {
        let req = parse_request(
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"query_db","arguments":{"table":"users","filter":{"age":{"$gt":18}},"limit":10}}}"#,
        );
        let intent = translate_to_intent(&req, &agent_ctx()).unwrap();
        match intent {
            IntentKind::ToolCall(tc) => {
                assert_eq!(tc.tool_name, "query_db");
                assert_eq!(tc.parameters.get("table").unwrap(), "users");
                // Nested object is JSON-serialized
                let filter = tc.parameters.get("filter").unwrap();
                assert!(filter.contains("$gt"));
                // Number is stringified
                assert_eq!(tc.parameters.get("limit").unwrap(), "10");
                // Raw arguments preserved
                assert!(tc.raw_arguments.is_some());
            }
            _ => panic!("expected ToolCall"),
        }
    }

    // -----------------------------------------------------------------------
    // 3. Tool call with empty arguments
    // -----------------------------------------------------------------------
    #[test]
    fn translate_tool_call_empty_arguments() {
        let req = parse_request(
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_time","arguments":{}}}"#,
        );
        let intent = translate_to_intent(&req, &agent_ctx()).unwrap();
        match intent {
            IntentKind::ToolCall(tc) => {
                assert_eq!(tc.tool_name, "get_time");
                assert!(tc.parameters.is_empty());
            }
            _ => panic!("expected ToolCall"),
        }
    }

    // -----------------------------------------------------------------------
    // 4. Tool call with no arguments field
    // -----------------------------------------------------------------------
    #[test]
    fn translate_tool_call_no_arguments_field() {
        let req = parse_request(
            r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"get_time"}}"#,
        );
        let intent = translate_to_intent(&req, &agent_ctx()).unwrap();
        match intent {
            IntentKind::ToolCall(tc) => {
                assert_eq!(tc.tool_name, "get_time");
                assert!(tc.parameters.is_empty());
                assert!(tc.raw_arguments.is_none());
            }
            _ => panic!("expected ToolCall"),
        }
    }

    // -----------------------------------------------------------------------
    // 5. Resource read translation
    // -----------------------------------------------------------------------
    #[test]
    fn translate_resource_read() {
        let req = parse_request(
            r#"{"jsonrpc":"2.0","id":5,"method":"resources/read","params":{"uri":"file:///etc/hosts"}}"#,
        );
        let intent = translate_to_intent(&req, &agent_ctx()).unwrap();
        match intent {
            IntentKind::ResourceRead(rr) => {
                assert_eq!(rr.agent_id, "agent-007");
                assert_eq!(rr.uri, "file:///etc/hosts");
                assert_eq!(rr.request_id, RequestId::Number(5));
            }
            _ => panic!("expected ResourceRead"),
        }
    }

    // -----------------------------------------------------------------------
    // 6. Unknown method returns None
    // -----------------------------------------------------------------------
    #[test]
    fn translate_unknown_method_returns_none() {
        let req = parse_request(
            r#"{"jsonrpc":"2.0","id":6,"method":"tools/list"}"#,
        );
        assert!(translate_to_intent(&req, &agent_ctx()).is_none());
    }

    // -----------------------------------------------------------------------
    // 7. Initialize method returns None (passthrough)
    // -----------------------------------------------------------------------
    #[test]
    fn translate_initialize_returns_none() {
        let req = parse_request(
            r#"{"jsonrpc":"2.0","id":7,"method":"initialize","params":{"capabilities":{}}}"#,
        );
        assert!(translate_to_intent(&req, &agent_ctx()).is_none());
    }

    // -----------------------------------------------------------------------
    // 8. Prompts/get returns None
    // -----------------------------------------------------------------------
    #[test]
    fn translate_prompts_get_returns_none() {
        let req = parse_request(
            r#"{"jsonrpc":"2.0","id":8,"method":"prompts/get","params":{"name":"summarize"}}"#,
        );
        assert!(translate_to_intent(&req, &agent_ctx()).is_none());
    }

    // -----------------------------------------------------------------------
    // 9. Denial to response: policy deny
    // -----------------------------------------------------------------------
    #[test]
    fn denial_response_policy_deny() {
        let deny = DenyReason::policy("tool read_file is not permitted for this agent");
        let resp = denial_to_response(RequestId::Number(10), &deny);
        assert_eq!(resp.jsonrpc, "2.0");
        assert_eq!(resp.id, RequestId::Number(10));
        assert!(resp.result.is_none());
        let err = resp.error.as_ref().unwrap();
        assert_eq!(err.code, AEGIS_ERROR_DENIED);
        assert!(err.message.contains("not permitted"));
        let data = err.data.as_ref().unwrap();
        assert_eq!(data["aegis"], true);
    }

    // -----------------------------------------------------------------------
    // 10. Denial to response: token expired
    // -----------------------------------------------------------------------
    #[test]
    fn denial_response_token_expired() {
        let deny = DenyReason::token_expired("token expired at 2025-01-01T00:00:00Z");
        let resp = denial_to_response(RequestId::String("req-42".into()), &deny);
        let err = resp.error.as_ref().unwrap();
        assert_eq!(err.code, AEGIS_ERROR_TOKEN_EXPIRED);
        assert_eq!(resp.id, RequestId::String("req-42".into()));
    }

    // -----------------------------------------------------------------------
    // 11. Denial to response: token revoked
    // -----------------------------------------------------------------------
    #[test]
    fn denial_response_token_revoked() {
        let deny = DenyReason::token_revoked("token was revoked by admin");
        let resp = denial_to_response(RequestId::Number(11), &deny);
        assert_eq!(resp.error.as_ref().unwrap().code, AEGIS_ERROR_TOKEN_REVOKED);
    }

    // -----------------------------------------------------------------------
    // 12. Denial to response: scope exceeded
    // -----------------------------------------------------------------------
    #[test]
    fn denial_response_scope_exceeded() {
        let deny = DenyReason::scope_exceeded("Write action not in token scope");
        let resp = denial_to_response(RequestId::Number(12), &deny);
        assert_eq!(resp.error.as_ref().unwrap().code, AEGIS_ERROR_SCOPE_EXCEEDED);
    }

    // -----------------------------------------------------------------------
    // 13. Tool call with array argument
    // -----------------------------------------------------------------------
    #[test]
    fn translate_tool_call_array_argument() {
        let req = parse_request(
            r#"{"jsonrpc":"2.0","id":13,"method":"tools/call","params":{"name":"multi_read","arguments":{"paths":["/a","/b","/c"]}}}"#,
        );
        let intent = translate_to_intent(&req, &agent_ctx()).unwrap();
        match intent {
            IntentKind::ToolCall(tc) => {
                let paths = tc.parameters.get("paths").unwrap();
                assert!(paths.contains("/a"));
                assert!(paths.contains("/b"));
            }
            _ => panic!("expected ToolCall"),
        }
    }

    // -----------------------------------------------------------------------
    // 14. Tool call with boolean and null arguments
    // -----------------------------------------------------------------------
    #[test]
    fn translate_tool_call_mixed_arg_types() {
        let req = parse_request(
            r#"{"jsonrpc":"2.0","id":14,"method":"tools/call","params":{"name":"config","arguments":{"verbose":true,"count":42,"label":null}}}"#,
        );
        let intent = translate_to_intent(&req, &agent_ctx()).unwrap();
        match intent {
            IntentKind::ToolCall(tc) => {
                assert_eq!(tc.parameters.get("verbose").unwrap(), "true");
                assert_eq!(tc.parameters.get("count").unwrap(), "42");
                assert_eq!(tc.parameters.get("label").unwrap(), "null");
            }
            _ => panic!("expected ToolCall"),
        }
    }

    // -----------------------------------------------------------------------
    // 15. Tool call with string ID
    // -----------------------------------------------------------------------
    #[test]
    fn translate_tool_call_string_id() {
        let req = parse_request(
            r#"{"jsonrpc":"2.0","id":"req-uuid-1","method":"tools/call","params":{"name":"echo","arguments":{"text":"hello"}}}"#,
        );
        let intent = translate_to_intent(&req, &agent_ctx()).unwrap();
        match intent {
            IntentKind::ToolCall(tc) => {
                assert_eq!(tc.request_id, RequestId::String("req-uuid-1".into()));
                assert_eq!(tc.parameters.get("text").unwrap(), "hello");
            }
            _ => panic!("expected ToolCall"),
        }
    }

    // -----------------------------------------------------------------------
    // Full roundtrip tests
    // -----------------------------------------------------------------------

    #[test]
    fn roundtrip_tool_call_allow() {
        // Step 1: raw MCP bytes → parse
        let raw = br#"{"jsonrpc":"2.0","id":100,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/data.csv"}}}"#;
        let msg = parse_message(raw).unwrap();

        // Step 2: extract request
        let request = match &msg {
            McpMessage::Request(r) => r,
            _ => panic!("expected request"),
        };

        // Step 3: translate to intent
        let ctx = agent_ctx();
        let intent = translate_to_intent(request, &ctx).unwrap();
        let tc = match &intent {
            IntentKind::ToolCall(tc) => tc,
            _ => panic!("expected ToolCall"),
        };
        assert_eq!(tc.tool_name, "read_file");
        assert_eq!(tc.parameters.get("path").unwrap(), "/tmp/data.csv");

        // Step 4: mock enforcement → Allow
        let decision = EnforcementDecision::Allow;

        // Step 5: for Allow, no error response needed — the request is forwarded.
        assert!(matches!(decision, EnforcementDecision::Allow));
    }

    #[test]
    fn roundtrip_tool_call_deny() {
        // Step 1: raw MCP bytes → parse
        let raw = br#"{"jsonrpc":"2.0","id":101,"method":"tools/call","params":{"name":"delete_file","arguments":{"path":"/etc/passwd"}}}"#;
        let msg = parse_message(raw).unwrap();

        // Step 2: extract request
        let request = match &msg {
            McpMessage::Request(r) => r,
            _ => panic!("expected request"),
        };

        // Step 3: translate to intent
        let ctx = agent_ctx();
        let intent = translate_to_intent(request, &ctx).unwrap();
        let tc = match &intent {
            IntentKind::ToolCall(tc) => tc,
            _ => panic!("expected ToolCall"),
        };
        assert_eq!(tc.tool_name, "delete_file");

        // Step 4: mock enforcement → Deny
        let decision = EnforcementDecision::Deny(DenyReason::policy(
            "delete_file is blocked for /etc/passwd",
        ));

        // Step 5: translate denial → MCP error response
        let deny = match &decision {
            EnforcementDecision::Deny(d) => d,
            _ => panic!("expected Deny"),
        };
        let response = denial_to_response(tc.request_id.clone(), deny);

        // Step 6: serialize back to MCP response bytes
        let response_msg = McpMessage::Response(response);
        let bytes = response_msg.to_json_bytes().unwrap();

        // Step 7: verify the response can be parsed back
        let parsed = parse_message(&bytes).unwrap();
        match parsed {
            McpMessage::Response(resp) => {
                assert_eq!(resp.id, RequestId::Number(101));
                assert!(resp.result.is_none());
                let err = resp.error.unwrap();
                assert_eq!(err.code, AEGIS_ERROR_DENIED);
                assert!(err.message.contains("delete_file"));
                assert!(err.message.contains("/etc/passwd"));
                let data = err.data.unwrap();
                assert_eq!(data["aegis"], true);
                assert_eq!(data["sub_code"], AEGIS_ERROR_DENIED);
            }
            _ => panic!("expected Response"),
        }
    }

    #[test]
    fn roundtrip_resource_read_deny() {
        // Full roundtrip for a resource read denial
        let raw = br#"{"jsonrpc":"2.0","id":102,"method":"resources/read","params":{"uri":"file:///etc/shadow"}}"#;
        let msg = parse_message(raw).unwrap();
        let request = match &msg {
            McpMessage::Request(r) => r,
            _ => panic!("expected request"),
        };

        let ctx = agent_ctx();
        let intent = translate_to_intent(request, &ctx).unwrap();
        let rr = match &intent {
            IntentKind::ResourceRead(rr) => rr,
            _ => panic!("expected ResourceRead"),
        };
        assert_eq!(rr.uri, "file:///etc/shadow");

        let deny = DenyReason::unauthorized("no valid token for /etc/shadow");
        let response = denial_to_response(rr.request_id.clone(), &deny);
        let bytes = McpMessage::Response(response).to_json_bytes().unwrap();

        let parsed = parse_message(&bytes).unwrap();
        match parsed {
            McpMessage::Response(resp) => {
                assert_eq!(resp.id, RequestId::Number(102));
                assert_eq!(resp.error.unwrap().code, AEGIS_ERROR_UNAUTHORIZED);
            }
            _ => panic!("expected Response"),
        }
    }

    #[test]
    fn roundtrip_constraint_violation_deny() {
        let raw = br#"{"jsonrpc":"2.0","id":103,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"/var/log/app.log","content":"data"}}}"#;
        let msg = parse_message(raw).unwrap();
        let request = match &msg {
            McpMessage::Request(r) => r,
            _ => panic!("expected request"),
        };

        let ctx = agent_ctx();
        let intent = translate_to_intent(request, &ctx).unwrap();
        let tc = match &intent {
            IntentKind::ToolCall(tc) => tc,
            _ => panic!("expected ToolCall"),
        };

        let deny = DenyReason::constraint_violation(
            "parameter 'path' must match /tmp/.*",
        );
        let response = denial_to_response(tc.request_id.clone(), &deny);
        let bytes = McpMessage::Response(response).to_json_bytes().unwrap();

        let parsed = parse_message(&bytes).unwrap();
        match parsed {
            McpMessage::Response(resp) => {
                assert_eq!(resp.error.unwrap().code, AEGIS_ERROR_CONSTRAINT_VIOLATION);
            }
            _ => panic!("expected Response"),
        }
    }
}
