use std::sync::Arc;
use std::time::Instant;

use chrono::{Duration, Utc};
use uuid::Uuid;

use aegis_audit::store::AuditStore;
use aegis_audit::{AuditLog, AuditQuery, InMemoryAuditStore, JsonLinesExporter, SortOrder};
use aegis_core::{Action, AuditEntry, Decision};

// ── Helpers ────────────────────────────────────────────────────────────

fn make_entry(agent: &str, tool: &str, decision: Decision) -> AuditEntry {
    AuditEntry {
        request_id: Uuid::new_v4(),
        timestamp: Utc::now(),
        agent_id: agent.into(),
        tool_name: tool.into(),
        action: Action::Read,
        resource_path: "test://resource".into(),
        token_id: Uuid::new_v4(),
        decision,
        reason: "test".into(),
        token_chain: vec![],
        latency_us: 42,
    }
}

fn make_entry_at(
    agent: &str,
    tool: &str,
    decision: Decision,
    timestamp: chrono::DateTime<chrono::Utc>,
) -> AuditEntry {
    AuditEntry {
        request_id: Uuid::new_v4(),
        timestamp,
        agent_id: agent.into(),
        tool_name: tool.into(),
        action: Action::Read,
        resource_path: "test://resource".into(),
        token_id: Uuid::new_v4(),
        decision,
        reason: "test".into(),
        token_chain: vec![],
        latency_us: 42,
    }
}

fn make_entry_with_resource(agent: &str, resource: &str) -> AuditEntry {
    AuditEntry {
        request_id: Uuid::new_v4(),
        timestamp: Utc::now(),
        agent_id: agent.into(),
        tool_name: "tool".into(),
        action: Action::Read,
        resource_path: resource.into(),
        token_id: Uuid::new_v4(),
        decision: Decision::Allow,
        reason: "test".into(),
        token_chain: vec![],
        latency_us: 42,
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Step 1: Ring buffer
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn empty_store() {
    let store = InMemoryAuditStore::new();
    assert!(store.is_empty());
    assert_eq!(store.len(), 0);
    assert!(store.all().is_empty());
}

#[test]
fn append_and_retrieve() {
    let store = InMemoryAuditStore::new();
    store.append(make_entry("agent-1", "tool-1", Decision::Allow));
    store.append(make_entry("agent-2", "tool-2", Decision::Deny));

    assert_eq!(store.len(), 2);
    assert!(!store.is_empty());

    let all = store.all();
    assert_eq!(all.len(), 2);
    assert_eq!(all[0].agent_id, "agent-1");
    assert_eq!(all[1].agent_id, "agent-2");
}

#[test]
fn ring_buffer_wraps_at_capacity() {
    let store = InMemoryAuditStore::with_capacity(3);

    for i in 0..5 {
        store.append(make_entry(&format!("agent-{i}"), "tool", Decision::Allow));
    }

    // Should only have the last 3
    assert_eq!(store.len(), 3);
    let all = store.all();
    assert_eq!(all[0].agent_id, "agent-2");
    assert_eq!(all[1].agent_id, "agent-3");
    assert_eq!(all[2].agent_id, "agent-4");
}

#[test]
fn ring_buffer_preserves_insertion_order_after_wrap() {
    let store = InMemoryAuditStore::with_capacity(4);

    for i in 0..10 {
        store.append(make_entry(&format!("a-{i}"), "t", Decision::Allow));
    }

    let all = store.all();
    assert_eq!(all.len(), 4);
    // Should be the last 4 in order
    assert_eq!(all[0].agent_id, "a-6");
    assert_eq!(all[1].agent_id, "a-7");
    assert_eq!(all[2].agent_id, "a-8");
    assert_eq!(all[3].agent_id, "a-9");
}

#[test]
fn clear_empties_store() {
    let store = InMemoryAuditStore::with_capacity(10);
    for i in 0..5 {
        store.append(make_entry(&format!("a-{i}"), "t", Decision::Allow));
    }
    assert_eq!(store.len(), 5);
    store.clear();
    assert_eq!(store.len(), 0);
    assert!(store.is_empty());
}

#[test]
fn capacity_of_one() {
    let store = InMemoryAuditStore::with_capacity(1);
    store.append(make_entry("first", "t", Decision::Allow));
    assert_eq!(store.len(), 1);
    assert_eq!(store.all()[0].agent_id, "first");

    store.append(make_entry("second", "t", Decision::Deny));
    assert_eq!(store.len(), 1);
    assert_eq!(store.all()[0].agent_id, "second");
}

// ═══════════════════════════════════════════════════════════════════════
// Step 2: Query API — filtering
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn query_no_filter_returns_all() {
    let store = InMemoryAuditStore::new();
    for i in 0..5 {
        store.append(make_entry(&format!("a-{i}"), "tool", Decision::Allow));
    }

    let page = store.query(&AuditQuery::new());
    assert_eq!(page.total, 5);
    assert_eq!(page.entries.len(), 5);
}

#[test]
fn query_filter_by_agent() {
    let store = InMemoryAuditStore::new();
    store.append(make_entry("alice", "tool", Decision::Allow));
    store.append(make_entry("bob", "tool", Decision::Deny));
    store.append(make_entry("alice", "other", Decision::Allow));

    let page = store.query(&AuditQuery::new().agent("alice"));
    assert_eq!(page.total, 2);
    assert!(page.entries.iter().all(|e| e.agent_id == "alice"));
}

#[test]
fn query_filter_by_tool() {
    let store = InMemoryAuditStore::new();
    store.append(make_entry("a", "read_file", Decision::Allow));
    store.append(make_entry("a", "write_db", Decision::Allow));
    store.append(make_entry("a", "read_file", Decision::Deny));

    let page = store.query(&AuditQuery::new().tool("read_file"));
    assert_eq!(page.total, 2);
    assert!(page.entries.iter().all(|e| e.tool_name == "read_file"));
}

#[test]
fn query_filter_by_decision() {
    let store = InMemoryAuditStore::new();
    store.append(make_entry("a", "t", Decision::Allow));
    store.append(make_entry("a", "t", Decision::Deny));
    store.append(make_entry("a", "t", Decision::Deny));

    let page = store.query(&AuditQuery::new().decision(Decision::Deny));
    assert_eq!(page.total, 2);
    assert!(page.entries.iter().all(|e| e.decision == Decision::Deny));
}

#[test]
fn query_filter_by_token_id() {
    let store = InMemoryAuditStore::new();
    let target_id = Uuid::new_v4();

    let mut entry1 = make_entry("a", "t", Decision::Allow);
    entry1.token_id = target_id;
    store.append(entry1);
    store.append(make_entry("a", "t", Decision::Allow)); // different token

    let page = store.query(&AuditQuery::new().token(target_id));
    assert_eq!(page.total, 1);
    assert_eq!(page.entries[0].token_id, target_id);
}

#[test]
fn query_filter_by_resource() {
    let store = InMemoryAuditStore::new();
    store.append(make_entry_with_resource("a", "db://finance"));
    store.append(make_entry_with_resource("a", "file:///tmp"));
    store.append(make_entry_with_resource("b", "db://finance"));

    let page = store.query(&AuditQuery::new().resource("db://finance"));
    assert_eq!(page.total, 2);
}

#[test]
fn query_filter_by_time_range() {
    let store = InMemoryAuditStore::new();
    let t1 = Utc::now() - Duration::hours(3);
    let t2 = Utc::now() - Duration::hours(2);
    let t3 = Utc::now() - Duration::hours(1);
    let t4 = Utc::now();

    store.append(make_entry_at("a", "t", Decision::Allow, t1));
    store.append(make_entry_at("a", "t", Decision::Allow, t2));
    store.append(make_entry_at("a", "t", Decision::Allow, t3));
    store.append(make_entry_at("a", "t", Decision::Allow, t4));

    // Query for the middle two
    let page = store
        .query(&AuditQuery::new().time_range(t2 - Duration::seconds(1), t3 + Duration::seconds(1)));
    assert_eq!(page.total, 2);
}

#[test]
fn query_filter_since() {
    let store = InMemoryAuditStore::new();
    let old = Utc::now() - Duration::hours(2);
    let recent = Utc::now();

    store.append(make_entry_at("a", "t", Decision::Allow, old));
    store.append(make_entry_at("a", "t", Decision::Allow, recent));

    let page = store.query(&AuditQuery::new().since(Utc::now() - Duration::hours(1)));
    assert_eq!(page.total, 1);
}

#[test]
fn query_combined_filters() {
    let store = InMemoryAuditStore::new();
    store.append(make_entry("alice", "read_file", Decision::Allow));
    store.append(make_entry("alice", "read_file", Decision::Deny));
    store.append(make_entry("bob", "read_file", Decision::Allow));
    store.append(make_entry("alice", "write_db", Decision::Allow));

    let page = store.query(
        &AuditQuery::new()
            .agent("alice")
            .tool("read_file")
            .decision(Decision::Allow),
    );
    assert_eq!(page.total, 1);
    let e = &page.entries[0];
    assert_eq!(e.agent_id, "alice");
    assert_eq!(e.tool_name, "read_file");
    assert_eq!(e.decision, Decision::Allow);
}

// ═══════════════════════════════════════════════════════════════════════
// Step 2: Query API — sorting
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn query_default_sort_newest_first() {
    let store = InMemoryAuditStore::new();
    let t1 = Utc::now() - Duration::hours(2);
    let t2 = Utc::now() - Duration::hours(1);
    let t3 = Utc::now();

    store.append(make_entry_at("a", "t", Decision::Allow, t1));
    store.append(make_entry_at("b", "t", Decision::Allow, t2));
    store.append(make_entry_at("c", "t", Decision::Allow, t3));

    let page = store.query(&AuditQuery::new());
    assert_eq!(page.entries[0].agent_id, "c");
    assert_eq!(page.entries[2].agent_id, "a");
}

#[test]
fn query_sort_oldest_first() {
    let store = InMemoryAuditStore::new();
    let t1 = Utc::now() - Duration::hours(2);
    let t2 = Utc::now() - Duration::hours(1);
    let t3 = Utc::now();

    store.append(make_entry_at("a", "t", Decision::Allow, t1));
    store.append(make_entry_at("b", "t", Decision::Allow, t2));
    store.append(make_entry_at("c", "t", Decision::Allow, t3));

    let page = store.query(&AuditQuery::new().sort(SortOrder::OldestFirst));
    assert_eq!(page.entries[0].agent_id, "a");
    assert_eq!(page.entries[2].agent_id, "c");
}

// ═══════════════════════════════════════════════════════════════════════
// Step 2: Query API — pagination
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn query_pagination_first_page() {
    let store = InMemoryAuditStore::new();
    for i in 0..10 {
        store.append(make_entry(&format!("a-{i}"), "t", Decision::Allow));
    }

    let page = store.query(&AuditQuery::new().page(0, 3));
    assert_eq!(page.entries.len(), 3);
    assert_eq!(page.total, 10);
    assert_eq!(page.offset, 0);
    assert_eq!(page.limit, 3);
    assert!(page.has_more);
}

#[test]
fn query_pagination_middle_page() {
    let store = InMemoryAuditStore::new();
    for i in 0..10 {
        store.append(make_entry(&format!("a-{i}"), "t", Decision::Allow));
    }

    let page = store.query(&AuditQuery::new().page(3, 3));
    assert_eq!(page.entries.len(), 3);
    assert_eq!(page.offset, 3);
    assert!(page.has_more);
}

#[test]
fn query_pagination_last_page() {
    let store = InMemoryAuditStore::new();
    for i in 0..10 {
        store.append(make_entry(&format!("a-{i}"), "t", Decision::Allow));
    }

    let page = store.query(&AuditQuery::new().page(9, 3));
    assert_eq!(page.entries.len(), 1);
    assert!(!page.has_more);
}

#[test]
fn query_pagination_beyond_end() {
    let store = InMemoryAuditStore::new();
    for i in 0..5 {
        store.append(make_entry(&format!("a-{i}"), "t", Decision::Allow));
    }

    let page = store.query(&AuditQuery::new().page(10, 5));
    assert!(page.entries.is_empty());
    assert_eq!(page.total, 5);
    assert!(!page.has_more);
}

#[test]
fn query_default_limit_is_100() {
    let store = InMemoryAuditStore::new();
    for i in 0..150 {
        store.append(make_entry(&format!("a-{i}"), "t", Decision::Allow));
    }

    let page = store.query(&AuditQuery::new());
    assert_eq!(page.entries.len(), 100);
    assert_eq!(page.limit, 100);
    assert!(page.has_more);
}

// ═══════════════════════════════════════════════════════════════════════
// Step 3: JSON Lines export
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn jsonl_export_empty_store() {
    let store = InMemoryAuditStore::new();
    let output = JsonLinesExporter::export_to_string(&store).unwrap();
    assert!(output.is_empty());
}

#[test]
fn jsonl_export_produces_valid_lines() {
    let store = InMemoryAuditStore::new();
    store.append(make_entry("alice", "read_file", Decision::Allow));
    store.append(make_entry("bob", "write_db", Decision::Deny));

    let output = JsonLinesExporter::export_to_string(&store).unwrap();
    let lines: Vec<&str> = output.trim().split('\n').collect();
    assert_eq!(lines.len(), 2);

    // Each line should be valid JSON
    for line in &lines {
        let parsed: serde_json::Value = serde_json::from_str(line).unwrap();
        assert!(parsed["agent_id"].is_string());
        assert!(parsed["request_id"].is_string());
        assert!(parsed["timestamp"].is_string());
        assert!(parsed["decision"].is_string());
    }

    // First line is alice (insertion order)
    let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(first["agent_id"], "alice");
    let second: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
    assert_eq!(second["agent_id"], "bob");
}

#[test]
fn jsonl_export_to_file() {
    let store = InMemoryAuditStore::new();
    store.append(make_entry("agent", "tool", Decision::Allow));

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let count = JsonLinesExporter::export_to_file(&store, &path).unwrap();
    assert_eq!(count, 1);

    let content = std::fs::read_to_string(&path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
    assert_eq!(parsed["agent_id"], "agent");
}

#[test]
fn jsonl_each_line_deserializes_to_audit_entry() {
    let store = InMemoryAuditStore::new();
    store.append(make_entry("agent", "tool", Decision::Allow));
    store.append(make_entry("agent", "tool", Decision::Deny));

    let output = JsonLinesExporter::export_to_string(&store).unwrap();
    for line in output.trim().split('\n') {
        let entry: AuditEntry = serde_json::from_str(line).unwrap();
        assert_eq!(entry.agent_id, "agent");
    }
}

#[test]
fn jsonl_export_count_matches() {
    let store = InMemoryAuditStore::new();
    for i in 0..50 {
        store.append(make_entry(&format!("a-{i}"), "t", Decision::Allow));
    }

    let mut buf = Vec::new();
    let count = JsonLinesExporter::export_all(&store, &mut buf).unwrap();
    assert_eq!(count, 50);
}

// ═══════════════════════════════════════════════════════════════════════
// AuditLog wrapper
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn audit_log_wrapper_works() {
    let store = Arc::new(InMemoryAuditStore::new());
    let log = AuditLog::new(store);

    log.append(make_entry("a", "t", Decision::Allow));
    log.append(make_entry("b", "t", Decision::Deny));

    assert_eq!(log.len(), 2);
    assert!(!log.is_empty());

    let page = log.query(&AuditQuery::new().agent("a"));
    assert_eq!(page.total, 1);

    log.clear();
    assert_eq!(log.len(), 0);
}

// ═══════════════════════════════════════════════════════════════════════
// Concurrency
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn concurrent_append_and_query() {
    let store = Arc::new(InMemoryAuditStore::with_capacity(10_000));

    let mut handles = vec![];

    // 10 writer threads, 100 entries each
    for t in 0..10 {
        let s = Arc::clone(&store);
        handles.push(std::thread::spawn(move || {
            for i in 0..100 {
                s.append(make_entry(
                    &format!("thread-{t}"),
                    &format!("tool-{i}"),
                    if i % 2 == 0 {
                        Decision::Allow
                    } else {
                        Decision::Deny
                    },
                ));
            }
        }));
    }

    // 5 reader threads querying concurrently
    for _ in 0..5 {
        let s = Arc::clone(&store);
        handles.push(std::thread::spawn(move || {
            for _ in 0..20 {
                let _ = s.query(&AuditQuery::new().page(0, 50));
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    assert_eq!(store.len(), 1000);
}

// ═══════════════════════════════════════════════════════════════════════
// Performance: <10ms for range queries
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn range_query_performance() {
    let store = InMemoryAuditStore::with_capacity(100_000);

    // Insert 10K entries evenly across a 10-hour span (3.6s apart)
    let base = Utc::now() - Duration::hours(10);
    for i in 0..10_000 {
        let ts = base + Duration::milliseconds(i * 3600);
        store.append(make_entry_at(
            &format!("agent-{}", i % 100),
            &format!("tool-{}", i % 10),
            if i % 3 == 0 {
                Decision::Deny
            } else {
                Decision::Allow
            },
            ts,
        ));
    }

    // Time range query: middle 2 hours of the 10-hour span
    let start = base + Duration::hours(4);
    let end = base + Duration::hours(6);

    let timer = Instant::now();
    let page = store.query(&AuditQuery::new().time_range(start, end).page(0, 50));
    let elapsed = timer.elapsed();

    assert!(!page.entries.is_empty());
    assert!(page.total > 100); // Should have ~2000 entries in the range

    let threshold = if cfg!(debug_assertions) {
        std::time::Duration::from_millis(100)
    } else {
        std::time::Duration::from_millis(10)
    };
    assert!(
        elapsed < threshold,
        "range query took {:?}, expected < {:?}",
        elapsed,
        threshold
    );
}

#[test]
fn combined_filter_performance() {
    let store = InMemoryAuditStore::with_capacity(100_000);

    for i in 0..10_000 {
        store.append(make_entry(
            &format!("agent-{}", i % 10),
            &format!("tool-{}", i % 5),
            if i % 2 == 0 {
                Decision::Allow
            } else {
                Decision::Deny
            },
        ));
    }

    let timer = Instant::now();
    let _page = store.query(
        &AuditQuery::new()
            .agent("agent-3")
            .tool("tool-3")
            .decision(Decision::Allow)
            .page(0, 50),
    );
    let elapsed = timer.elapsed();

    let threshold = if cfg!(debug_assertions) {
        std::time::Duration::from_millis(100)
    } else {
        std::time::Duration::from_millis(10)
    };
    assert!(
        elapsed < threshold,
        "combined filter query took {:?}, expected < {:?}",
        elapsed,
        threshold
    );
    // agent-3 every 10, tool-3 every 5, allow every 2
    // i%10==3 && i%5==3 && i%2==0 → i%10==3 && i%2==0 → never (3 is odd)
    // Actually agent-3 + tool-3 + Deny: i%10==3 && i%5==3 && i%2==1 → i=3,13,23,...
    // Let's just query agent + tool without decision filter
    let page2 = store.query(
        &AuditQuery::new()
            .agent("agent-3")
            .tool("tool-3")
            .page(0, 50),
    );
    assert!(page2.total > 0, "agent-3 + tool-3 should have matches");
}

#[test]
fn jsonl_export_performance() {
    let store = InMemoryAuditStore::with_capacity(100_000);
    for i in 0..10_000 {
        store.append(make_entry(&format!("a-{i}"), "tool", Decision::Allow));
    }

    let timer = Instant::now();
    let output = JsonLinesExporter::export_to_string(&store).unwrap();
    let elapsed = timer.elapsed();

    let lines: Vec<&str> = output.trim().split('\n').collect();
    assert_eq!(lines.len(), 10_000);

    let threshold = if cfg!(debug_assertions) {
        std::time::Duration::from_millis(500)
    } else {
        std::time::Duration::from_millis(100)
    };
    assert!(
        elapsed < threshold,
        "JSONL export of 10K entries took {:?}, expected < {:?}",
        elapsed,
        threshold
    );
}
