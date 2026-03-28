use std::fs;
use std::path::PathBuf;

use aegis_mcp::{
    extract_resource_read, extract_tool_call, parse_message, McpMessage,
};

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/mcp")
}

fn load_fixture(name: &str) -> Vec<u8> {
    let path = fixtures_dir().join(name);
    fs::read(&path).unwrap_or_else(|e| panic!("failed to read fixture {}: {}", name, e))
}

/// Parse every fixture file — zero failures allowed.
#[test]
fn parse_all_fixtures_no_failures() {
    let dir = fixtures_dir();
    let mut count = 0;
    for entry in fs::read_dir(&dir).expect("fixtures dir should exist") {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let bytes = fs::read(&path).unwrap();
        let filename = path.file_name().unwrap().to_string_lossy().to_string();
        parse_message(&bytes)
            .unwrap_or_else(|e| panic!("failed to parse fixture {}: {}", filename, e));
        count += 1;
    }
    assert!(count >= 50, "expected at least 50 fixtures, found {}", count);
}

// --- Initialization ---

#[test]
fn fixture_initialize_request() {
    let msg = parse_message(&load_fixture("01_initialize_request.json")).unwrap();
    assert!(msg.is_initialization());
    assert!(!msg.is_notification());
}

#[test]
fn fixture_initialize_response() {
    let msg = parse_message(&load_fixture("02_initialize_response.json")).unwrap();
    assert!(matches!(msg, McpMessage::Response(_)));
}

#[test]
fn fixture_initialized_notification() {
    let msg = parse_message(&load_fixture("03_initialized_notification.json")).unwrap();
    assert!(msg.is_notification());
}

#[test]
fn fixture_initialize_string_id() {
    let msg = parse_message(&load_fixture("04_initialize_request_string_id.json")).unwrap();
    assert!(msg.is_initialization());
    if let McpMessage::Request(req) = &msg {
        assert!(matches!(&req.id, aegis_mcp::RequestId::String(_)));
    }
}

// --- Tool operations ---

#[test]
fn fixture_tools_list_request() {
    let msg = parse_message(&load_fixture("05_tools_list_request.json")).unwrap();
    assert!(matches!(msg, McpMessage::Request(ref r) if r.method == "tools/list"));
    assert!(!msg.is_tool_call());
}

#[test]
fn fixture_tools_list_response() {
    let msg = parse_message(&load_fixture("06_tools_list_response.json")).unwrap();
    assert!(matches!(msg, McpMessage::Response(_)));
}

#[test]
fn fixture_tools_call_request() {
    let msg = parse_message(&load_fixture("07_tools_call_request.json")).unwrap();
    assert!(msg.is_tool_call());
    if let McpMessage::Request(req) = &msg {
        let tc = extract_tool_call(req).expect("should extract tool call");
        assert_eq!(tc.name, "read_file");
        assert!(tc.arguments.is_some());
    }
}

#[test]
fn fixture_tools_call_response() {
    let msg = parse_message(&load_fixture("08_tools_call_response.json")).unwrap();
    assert!(matches!(msg, McpMessage::Response(_)));
}

#[test]
fn fixture_tools_call_no_args() {
    let msg = parse_message(&load_fixture("09_tools_call_request_no_args.json")).unwrap();
    assert!(msg.is_tool_call());
    if let McpMessage::Request(req) = &msg {
        let tc = extract_tool_call(req).expect("should extract tool call");
        assert_eq!(tc.name, "get_time");
    }
}

#[test]
fn fixture_tools_call_error_response() {
    let msg = parse_message(&load_fixture("10_tools_call_error_response.json")).unwrap();
    assert!(matches!(msg, McpMessage::Response(_)));
}

#[test]
fn fixture_tools_list_changed_notification() {
    let msg = parse_message(&load_fixture("11_tools_list_changed_notification.json")).unwrap();
    assert!(msg.is_notification());
}

#[test]
fn fixture_tools_call_complex_args() {
    let msg = parse_message(&load_fixture("12_tools_call_request_complex_args.json")).unwrap();
    assert!(msg.is_tool_call());
    if let McpMessage::Request(req) = &msg {
        let tc = extract_tool_call(req).unwrap();
        assert!(tc.arguments.is_some());
    }
}

// --- Resource operations ---

#[test]
fn fixture_resources_list_request() {
    let msg = parse_message(&load_fixture("13_resources_list_request.json")).unwrap();
    assert!(matches!(msg, McpMessage::Request(ref r) if r.method == "resources/list"));
}

#[test]
fn fixture_resources_list_response() {
    let msg = parse_message(&load_fixture("14_resources_list_response.json")).unwrap();
    assert!(matches!(msg, McpMessage::Response(_)));
}

#[test]
fn fixture_resources_read_request() {
    let msg = parse_message(&load_fixture("15_resources_read_request.json")).unwrap();
    assert!(msg.is_resource_read());
    if let McpMessage::Request(req) = &msg {
        let rr = extract_resource_read(req).expect("should extract resource read");
        assert_eq!(rr.uri, "file:///project/src/main.rs");
    }
}

#[test]
fn fixture_resources_read_response() {
    let msg = parse_message(&load_fixture("16_resources_read_response.json")).unwrap();
    assert!(matches!(msg, McpMessage::Response(_)));
}

#[test]
fn fixture_resources_subscribe_request() {
    let msg = parse_message(&load_fixture("17_resources_subscribe_request.json")).unwrap();
    assert!(matches!(msg, McpMessage::Request(ref r) if r.method == "resources/subscribe"));
}

#[test]
fn fixture_resources_unsubscribe_request() {
    let msg = parse_message(&load_fixture("18_resources_unsubscribe_request.json")).unwrap();
    assert!(matches!(msg, McpMessage::Request(ref r) if r.method == "resources/unsubscribe"));
}

#[test]
fn fixture_resources_list_changed_notification() {
    let msg = parse_message(&load_fixture("19_resources_list_changed_notification.json")).unwrap();
    assert!(msg.is_notification());
}

#[test]
fn fixture_resources_updated_notification() {
    let msg = parse_message(&load_fixture("20_resources_updated_notification.json")).unwrap();
    assert!(msg.is_notification());
}

// --- Prompt operations ---

#[test]
fn fixture_prompts_list_request() {
    let msg = parse_message(&load_fixture("21_prompts_list_request.json")).unwrap();
    assert!(matches!(msg, McpMessage::Request(ref r) if r.method == "prompts/list"));
}

#[test]
fn fixture_prompts_list_response() {
    let msg = parse_message(&load_fixture("22_prompts_list_response.json")).unwrap();
    assert!(matches!(msg, McpMessage::Response(_)));
}

#[test]
fn fixture_prompts_get_request() {
    let msg = parse_message(&load_fixture("23_prompts_get_request.json")).unwrap();
    assert!(matches!(msg, McpMessage::Request(ref r) if r.method == "prompts/get"));
}

#[test]
fn fixture_prompts_get_response() {
    let msg = parse_message(&load_fixture("24_prompts_get_response.json")).unwrap();
    assert!(matches!(msg, McpMessage::Response(_)));
}

#[test]
fn fixture_prompts_list_changed_notification() {
    let msg = parse_message(&load_fixture("25_prompts_list_changed_notification.json")).unwrap();
    assert!(msg.is_notification());
}

#[test]
fn fixture_prompts_get_no_args() {
    let msg = parse_message(&load_fixture("26_prompts_get_request_no_args.json")).unwrap();
    assert!(matches!(msg, McpMessage::Request(ref r) if r.method == "prompts/get"));
}

// --- Completion ---

#[test]
fn fixture_completion_complete_request() {
    let msg = parse_message(&load_fixture("27_completion_complete_request.json")).unwrap();
    assert!(matches!(msg, McpMessage::Request(ref r) if r.method == "completion/complete"));
}

#[test]
fn fixture_completion_complete_response() {
    let msg = parse_message(&load_fixture("28_completion_complete_response.json")).unwrap();
    assert!(matches!(msg, McpMessage::Response(_)));
}

#[test]
fn fixture_completion_complete_has_more() {
    let msg = parse_message(&load_fixture("29_completion_complete_response_has_more.json")).unwrap();
    assert!(matches!(msg, McpMessage::Response(_)));
}

// --- Logging ---

#[test]
fn fixture_logging_set_level_request() {
    let msg = parse_message(&load_fixture("30_logging_set_level_request.json")).unwrap();
    assert!(matches!(msg, McpMessage::Request(ref r) if r.method == "logging/setLevel"));
}

#[test]
fn fixture_logging_set_level_response() {
    let msg = parse_message(&load_fixture("31_logging_set_level_response.json")).unwrap();
    assert!(matches!(msg, McpMessage::Response(_)));
}

#[test]
fn fixture_logging_message_notification() {
    let msg = parse_message(&load_fixture("32_logging_message_notification.json")).unwrap();
    assert!(msg.is_notification());
}

// --- Sampling ---

#[test]
fn fixture_sampling_create_message_request() {
    let msg = parse_message(&load_fixture("33_sampling_create_message_request.json")).unwrap();
    assert!(matches!(msg, McpMessage::Request(ref r) if r.method == "sampling/createMessage"));
}

#[test]
fn fixture_sampling_create_message_response() {
    let msg = parse_message(&load_fixture("34_sampling_create_message_response.json")).unwrap();
    assert!(matches!(msg, McpMessage::Response(_)));
}

#[test]
fn fixture_sampling_with_system() {
    let msg = parse_message(&load_fixture("35_sampling_create_message_with_system.json")).unwrap();
    assert!(matches!(msg, McpMessage::Request(ref r) if r.method == "sampling/createMessage"));
}

// --- Roots ---

#[test]
fn fixture_roots_list_request() {
    let msg = parse_message(&load_fixture("36_roots_list_request.json")).unwrap();
    assert!(matches!(msg, McpMessage::Request(ref r) if r.method == "roots/list"));
}

#[test]
fn fixture_roots_list_response() {
    let msg = parse_message(&load_fixture("37_roots_list_response.json")).unwrap();
    assert!(matches!(msg, McpMessage::Response(_)));
}

#[test]
fn fixture_roots_list_changed_notification() {
    let msg = parse_message(&load_fixture("38_roots_list_changed_notification.json")).unwrap();
    assert!(msg.is_notification());
}

// --- Progress / Cancelled ---

#[test]
fn fixture_progress_notification() {
    let msg = parse_message(&load_fixture("39_progress_notification.json")).unwrap();
    assert!(msg.is_notification());
}

#[test]
fn fixture_progress_with_message() {
    let msg = parse_message(&load_fixture("40_progress_notification_with_message.json")).unwrap();
    assert!(msg.is_notification());
}

#[test]
fn fixture_cancelled_notification() {
    let msg = parse_message(&load_fixture("41_cancelled_notification.json")).unwrap();
    assert!(msg.is_notification());
}

// --- Error responses ---

#[test]
fn fixture_error_parse_error() {
    let msg = parse_message(&load_fixture("42_error_parse_error.json")).unwrap();
    if let McpMessage::Response(resp) = msg {
        let err = resp.error.unwrap();
        assert_eq!(err.code, -32700);
    } else {
        panic!("expected Response");
    }
}

#[test]
fn fixture_error_invalid_request() {
    let msg = parse_message(&load_fixture("43_error_invalid_request.json")).unwrap();
    if let McpMessage::Response(resp) = msg {
        assert_eq!(resp.error.unwrap().code, -32600);
    } else {
        panic!("expected Response");
    }
}

#[test]
fn fixture_error_method_not_found() {
    let msg = parse_message(&load_fixture("44_error_method_not_found.json")).unwrap();
    if let McpMessage::Response(resp) = msg {
        assert_eq!(resp.error.unwrap().code, -32601);
    } else {
        panic!("expected Response");
    }
}

#[test]
fn fixture_error_invalid_params() {
    let msg = parse_message(&load_fixture("45_error_invalid_params.json")).unwrap();
    if let McpMessage::Response(resp) = msg {
        assert_eq!(resp.error.unwrap().code, -32602);
    } else {
        panic!("expected Response");
    }
}

#[test]
fn fixture_error_internal_error() {
    let msg = parse_message(&load_fixture("46_error_internal_error.json")).unwrap();
    if let McpMessage::Response(resp) = msg {
        assert_eq!(resp.error.unwrap().code, -32603);
    } else {
        panic!("expected Response");
    }
}

#[test]
fn fixture_error_with_data() {
    let msg = parse_message(&load_fixture("47_error_with_data.json")).unwrap();
    if let McpMessage::Response(resp) = msg {
        let err = resp.error.unwrap();
        assert!(err.data.is_some());
    } else {
        panic!("expected Response");
    }
}

// --- Edge cases ---

#[test]
fn fixture_request_with_null_params() {
    let msg = parse_message(&load_fixture("48_request_with_null_params.json")).unwrap();
    assert!(matches!(msg, McpMessage::Request(_)));
}

#[test]
fn fixture_response_with_null_result() {
    let msg = parse_message(&load_fixture("49_response_with_null_result.json")).unwrap();
    assert!(matches!(msg, McpMessage::Response(_)));
}

#[test]
fn fixture_request_large_id() {
    let msg = parse_message(&load_fixture("50_request_large_id.json")).unwrap();
    if let McpMessage::Request(req) = msg {
        assert_eq!(req.id, aegis_mcp::RequestId::Number(999999999));
    } else {
        panic!("expected Request");
    }
}

#[test]
fn fixture_notification_empty_params() {
    let msg = parse_message(&load_fixture("51_notification_empty_params.json")).unwrap();
    assert!(msg.is_notification());
}

#[test]
fn fixture_tools_call_with_array_arg() {
    let msg = parse_message(&load_fixture("52_tools_call_with_array_arg.json")).unwrap();
    assert!(msg.is_tool_call());
    if let McpMessage::Request(req) = &msg {
        let tc = extract_tool_call(req).unwrap();
        assert!(tc.arguments.is_some());
    }
}

#[test]
fn fixture_ping_request() {
    let msg = parse_message(&load_fixture("53_ping_request.json")).unwrap();
    assert!(matches!(msg, McpMessage::Request(ref r) if r.method == "ping"));
}

#[test]
fn fixture_ping_response() {
    let msg = parse_message(&load_fixture("54_ping_response.json")).unwrap();
    assert!(matches!(msg, McpMessage::Response(_)));
}

#[test]
fn fixture_resources_templates_list() {
    let msg = parse_message(&load_fixture("55_resources_templates_list_request.json")).unwrap();
    assert!(matches!(msg, McpMessage::Request(ref r) if r.method == "resources/templates/list"));
}

// --- extract_tool_call on non-tool-call fixtures ---

#[test]
fn extract_tool_call_returns_none_for_non_tool_request() {
    let msg = parse_message(&load_fixture("01_initialize_request.json")).unwrap();
    if let McpMessage::Request(req) = &msg {
        assert!(extract_tool_call(req).is_none());
    }
}

// --- extract_resource_read on non-resource-read fixtures ---

#[test]
fn extract_resource_read_returns_none_for_non_resource_request() {
    let msg = parse_message(&load_fixture("07_tools_call_request.json")).unwrap();
    if let McpMessage::Request(req) = &msg {
        assert!(extract_resource_read(req).is_none());
    }
}
