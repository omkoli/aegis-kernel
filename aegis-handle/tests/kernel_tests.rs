use std::collections::HashMap;
use std::time::Duration;

use aegis_handle::{
    Action, AuditQuery, Constraints, Decision, KernelHandle, ParamConstraint, Resource,
    SignedToken, SortOrder, TokenRequest, ToolCallRequest,
};

// ═══════════════════════════════════════════════════════════════════════
// Step 1: KernelHandle construction
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn new_creates_empty_handle() {
    let handle = KernelHandle::new();
    assert_eq!(handle.token_count(), 0);
    assert_eq!(handle.audit_len(), 0);
}

#[test]
fn builder_default_config() {
    let handle = KernelHandle::builder().build().unwrap();
    assert_eq!(handle.token_count(), 0);
}

#[test]
fn from_policy_yaml() {
    let yaml = r#"
policies:
  - name: test-read
    agent: agent-1
    resource: "db://test"
    actions: [read]
    ttl: 1h
"#;
    let handle = KernelHandle::from_policy_yaml(yaml).unwrap();
    assert_eq!(handle.token_count(), 1);
}

#[test]
fn from_policy_file() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("policies.yaml");
    std::fs::write(
        &file,
        r#"
policies:
  - name: file-policy
    agent: agent-file
    resource: "file:///data"
    actions: [read, write]
    ttl: 30m
"#,
    )
    .unwrap();

    let handle = KernelHandle::from_policy_file(&file).unwrap();
    assert_eq!(handle.token_count(), 1);
}

#[test]
fn builder_with_audit_capacity() {
    let handle = KernelHandle::builder().audit_capacity(100).build().unwrap();
    // Insert 200 audit entries by evaluating with a nonexistent token
    for _ in 0..200 {
        let req = ToolCallRequest {
            agent_id: "a".into(),
            tool_name: "t".into(),
            action: Action::Read,
            resource: Resource::new("test://r").unwrap(),
            parameters: HashMap::new(),
            token_id: uuid::Uuid::new_v4(),
        };
        handle.evaluate(&req);
    }
    // Ring buffer capped at 100
    assert_eq!(handle.audit_len(), 100);
}

#[test]
fn invalid_policy_yaml_returns_error() {
    let result = KernelHandle::from_policy_yaml("not valid yaml [[[");
    assert!(result.is_err());
}

// ═══════════════════════════════════════════════════════════════════════
// Step 1: Token lifecycle
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn issue_and_get_token() {
    let handle = KernelHandle::new();
    let signed = handle
        .issue_token(TokenRequest {
            subject: "agent-1".into(),
            resource: Resource::new("db://test").unwrap(),
            actions: vec![Action::Read],
            constraints: Constraints::new(),
            ttl: Some(Duration::from_secs(3600)),
            delegatable: false,
            max_uses: None,
        })
        .unwrap();

    let id = signed.token.id();
    let fetched = handle.get_token(id).unwrap();
    assert_eq!(fetched.token.subject(), "agent-1");
}

#[test]
fn list_tokens() {
    let handle = KernelHandle::new();
    for i in 0..3 {
        handle
            .issue_token(TokenRequest {
                subject: format!("agent-{i}"),
                resource: Resource::new("test://r").unwrap(),
                actions: vec![Action::Read],
                constraints: Constraints::new(),
                ttl: Some(Duration::from_secs(3600)),
                delegatable: false,
                max_uses: None,
            })
            .unwrap();
    }
    assert_eq!(handle.list_tokens().len(), 3);
}

#[test]
fn delete_token() {
    let handle = KernelHandle::new();
    let signed = handle
        .issue_token(TokenRequest {
            subject: "agent-1".into(),
            resource: Resource::new("test://r").unwrap(),
            actions: vec![Action::Read],
            constraints: Constraints::new(),
            ttl: Some(Duration::from_secs(3600)),
            delegatable: false,
            max_uses: None,
        })
        .unwrap();

    let id = signed.token.id();
    handle.delete_token(id).unwrap();
    assert!(handle.get_token(id).is_err());
}

#[test]
fn revoke_token_cascades() {
    let handle = KernelHandle::new();
    let parent = handle
        .issue_token(TokenRequest {
            subject: "parent".into(),
            resource: Resource::new("test://r").unwrap(),
            actions: vec![Action::Read, Action::Write],
            constraints: Constraints::new(),
            ttl: Some(Duration::from_secs(3600)),
            delegatable: true,
            max_uses: None,
        })
        .unwrap();

    let child = handle
        .delegate_token(aegis_core::DelegationRequest {
            parent_token_id: parent.token.id(),
            new_subject: "child".into(),
            actions: vec![Action::Read],
            constraints: Constraints::new(),
            delegatable: false,
            max_uses: None,
            ttl_secs: Some(600),
        })
        .unwrap();

    let revoked = handle.revoke_token(parent.token.id()).unwrap();
    assert!(revoked.contains(&parent.token.id()));
    assert!(revoked.contains(&child.token.id()));

    // Both should be revoked
    assert!(handle
        .get_token(parent.token.id())
        .unwrap()
        .token
        .is_revoked());
    assert!(handle
        .get_token(child.token.id())
        .unwrap()
        .token
        .is_revoked());
}

// ═══════════════════════════════════════════════════════════════════════
// Step 1: evaluate()
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn evaluate_allow() {
    let handle = KernelHandle::new();
    let signed = handle
        .issue_token(TokenRequest {
            subject: "agent-1".into(),
            resource: Resource::new("db://test").unwrap(),
            actions: vec![Action::Read],
            constraints: Constraints::new(),
            ttl: Some(Duration::from_secs(3600)),
            delegatable: false,
            max_uses: None,
        })
        .unwrap();

    let result = handle.evaluate(&ToolCallRequest {
        agent_id: "agent-1".into(),
        tool_name: "query".into(),
        action: Action::Read,
        resource: Resource::new("db://test").unwrap(),
        parameters: HashMap::new(),
        token_id: signed.token.id(),
    });

    assert_eq!(result.decision, Decision::Allow);
    assert_eq!(handle.audit_len(), 1);
}

#[test]
fn evaluate_deny_wrong_action() {
    let handle = KernelHandle::new();
    let signed = handle
        .issue_token(TokenRequest {
            subject: "agent-1".into(),
            resource: Resource::new("db://test").unwrap(),
            actions: vec![Action::Read],
            constraints: Constraints::new(),
            ttl: Some(Duration::from_secs(3600)),
            delegatable: false,
            max_uses: None,
        })
        .unwrap();

    let result = handle.evaluate(&ToolCallRequest {
        agent_id: "agent-1".into(),
        tool_name: "delete".into(),
        action: Action::Delete,
        resource: Resource::new("db://test").unwrap(),
        parameters: HashMap::new(),
        token_id: signed.token.id(),
    });

    assert_eq!(result.decision, Decision::Deny);
}

#[test]
fn evaluate_deny_nonexistent_token() {
    let handle = KernelHandle::new();
    let result = handle.evaluate(&ToolCallRequest {
        agent_id: "agent-1".into(),
        tool_name: "tool".into(),
        action: Action::Read,
        resource: Resource::new("test://r").unwrap(),
        parameters: HashMap::new(),
        token_id: uuid::Uuid::new_v4(),
    });
    assert_eq!(result.decision, Decision::Deny);
}

#[test]
fn evaluate_deny_wrong_agent() {
    let handle = KernelHandle::new();
    let signed = handle
        .issue_token(TokenRequest {
            subject: "agent-1".into(),
            resource: Resource::new("db://test").unwrap(),
            actions: vec![Action::Read],
            constraints: Constraints::new(),
            ttl: Some(Duration::from_secs(3600)),
            delegatable: false,
            max_uses: None,
        })
        .unwrap();

    let result = handle.evaluate(&ToolCallRequest {
        agent_id: "wrong-agent".into(),
        tool_name: "tool".into(),
        action: Action::Read,
        resource: Resource::new("db://test").unwrap(),
        parameters: HashMap::new(),
        token_id: signed.token.id(),
    });

    assert_eq!(result.decision, Decision::Deny);
}

#[test]
fn evaluate_with_constraints() {
    let handle = KernelHandle::new();
    let signed = handle
        .issue_token(TokenRequest {
            subject: "agent-1".into(),
            resource: Resource::new("api://payments").unwrap(),
            actions: vec![Action::Execute],
            constraints: Constraints::new()
                .add(
                    "amount",
                    ParamConstraint::Range {
                        min: 0.0,
                        max: 1000.0,
                    },
                )
                .unwrap(),
            ttl: Some(Duration::from_secs(3600)),
            delegatable: false,
            max_uses: None,
        })
        .unwrap();

    // Within range → Allow
    let result = handle.evaluate(&ToolCallRequest {
        agent_id: "agent-1".into(),
        tool_name: "charge".into(),
        action: Action::Execute,
        resource: Resource::new("api://payments").unwrap(),
        parameters: [("amount".into(), "500".into())].into(),
        token_id: signed.token.id(),
    });
    assert_eq!(result.decision, Decision::Allow);

    // Over range → Deny
    let result = handle.evaluate(&ToolCallRequest {
        agent_id: "agent-1".into(),
        tool_name: "charge".into(),
        action: Action::Execute,
        resource: Resource::new("api://payments").unwrap(),
        parameters: [("amount".into(), "5000".into())].into(),
        token_id: signed.token.id(),
    });
    assert_eq!(result.decision, Decision::Deny);
}

// ═══════════════════════════════════════════════════════════════════════
// Step 1: Policy management
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn load_policies_yaml() {
    let handle = KernelHandle::new();
    assert_eq!(handle.token_count(), 0);

    let tokens = handle
        .load_policies_yaml(
            r#"
policies:
  - name: p1
    agent: agent-1
    resource: "test://r"
    actions: [read]
    ttl: 1h
  - name: p2
    agent: agent-2
    resource: "test://r2"
    actions: [write]
    ttl: 30m
"#,
        )
        .unwrap();

    assert_eq!(tokens.len(), 2);
    assert_eq!(handle.token_count(), 2);
}

#[test]
fn load_policies_file() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("reload.yaml");
    std::fs::write(
        &file,
        r#"
policies:
  - name: reloaded
    agent: agent-new
    resource: "test://r"
    actions: [read]
    ttl: 1h
"#,
    )
    .unwrap();

    let handle = KernelHandle::new();
    let tokens = handle.load_policies_file(&file).unwrap();
    assert_eq!(tokens.len(), 1);
    assert_eq!(tokens[0].token.subject(), "agent-new");
}

#[test]
fn compile_policies_dry_run() {
    let handle = KernelHandle::new();
    let requests = handle
        .compile_policies(
            r#"
policies:
  - name: dry-run
    agent: agent
    resource: "test://r"
    actions: [read]
    ttl: 1h
"#,
        )
        .unwrap();

    assert_eq!(requests.len(), 1);
    // Dry run — no tokens issued
    assert_eq!(handle.token_count(), 0);
}

// ═══════════════════════════════════════════════════════════════════════
// Step 1: Audit queries
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn audit_query_filters() {
    let handle = KernelHandle::new();

    // Issue two tokens for different agents
    let t1 = issue_simple(&handle, "alice", "db://data");
    let t2 = issue_simple(&handle, "bob", "file:///tmp");

    // Evaluate both
    eval(
        &handle,
        "alice",
        "query",
        Action::Read,
        "db://data",
        t1.token.id(),
    );
    eval(
        &handle,
        "bob",
        "read_file",
        Action::Read,
        "file:///tmp",
        t2.token.id(),
    );
    eval(
        &handle,
        "alice",
        "delete",
        Action::Delete,
        "db://data",
        t1.token.id(),
    ); // deny

    // Filter by agent
    let page = handle.query_audit(&AuditQuery::new().agent("alice"));
    assert_eq!(page.total, 2);

    // Filter by decision
    let page = handle.query_audit(&AuditQuery::new().decision(Decision::Deny));
    assert_eq!(page.total, 1);

    // Filter by tool
    let page = handle.query_audit(&AuditQuery::new().tool("query"));
    assert_eq!(page.total, 1);
}

#[test]
fn audit_query_pagination() {
    let handle = KernelHandle::new();
    for _ in 0..20 {
        handle.evaluate(&ToolCallRequest {
            agent_id: "a".into(),
            tool_name: "t".into(),
            action: Action::Read,
            resource: Resource::new("test://r").unwrap(),
            parameters: HashMap::new(),
            token_id: uuid::Uuid::new_v4(),
        });
    }

    let page = handle.query_audit(&AuditQuery::new().page(0, 5));
    assert_eq!(page.entries.len(), 5);
    assert_eq!(page.total, 20);
    assert!(page.has_more);

    let page2 = handle.query_audit(&AuditQuery::new().page(15, 10));
    assert_eq!(page2.entries.len(), 5);
    assert!(!page2.has_more);
}

#[test]
fn audit_export_jsonl() {
    let handle = KernelHandle::new();
    let t = issue_simple(&handle, "agent", "test://r");
    eval(
        &handle,
        "agent",
        "tool",
        Action::Read,
        "test://r",
        t.token.id(),
    );

    let mut buf = Vec::new();
    let count = handle.export_audit(&mut buf).unwrap();
    assert_eq!(count, 1);

    let line = String::from_utf8(buf).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(parsed["agent_id"], "agent");
}

#[test]
fn clear_audit() {
    let handle = KernelHandle::new();
    handle.evaluate(&ToolCallRequest {
        agent_id: "a".into(),
        tool_name: "t".into(),
        action: Action::Read,
        resource: Resource::new("test://r").unwrap(),
        parameters: HashMap::new(),
        token_id: uuid::Uuid::new_v4(),
    });
    assert_eq!(handle.audit_len(), 1);
    handle.clear_audit();
    assert_eq!(handle.audit_len(), 0);
}

// ═══════════════════════════════════════════════════════════════════════
// Step 3: End-to-end demo — 100 calls from policy-loaded tokens
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn end_to_end_demo_100_calls() {
    // 1. Load policies from YAML
    let handle = KernelHandle::from_policy_yaml(
        r#"
policies:
  - name: finance-read
    agent: finance-agent
    resource: "db://finance/transactions"
    actions: [read]
    constraints:
      max_amount: 1000
    ttl: 1h
    delegatable: true
    max_uses: 200

  - name: email-send
    agent: email-agent
    resource: "email://smtp.corp.com"
    actions: [execute]
    constraints:
      domain:
        type: one_of
        values: ["corp.com", "partner.com"]
    ttl: 30m

  - name: file-access
    agent: file-agent
    resource: "file:///data/reports"
    actions: [read, write]
    ttl: 2h
    max_uses: 500
"#,
    )
    .unwrap();

    assert_eq!(handle.token_count(), 3);

    // 2. Find the tokens by subject
    let tokens = handle.list_tokens();
    let finance_token = tokens
        .iter()
        .find(|t| t.token.subject() == "finance-agent")
        .unwrap();
    let email_token = tokens
        .iter()
        .find(|t| t.token.subject() == "email-agent")
        .unwrap();
    let file_token = tokens
        .iter()
        .find(|t| t.token.subject() == "file-agent")
        .unwrap();

    // 3. Delegate finance token to an analyst
    let analyst_token = handle
        .delegate_token(aegis_core::DelegationRequest {
            parent_token_id: finance_token.token.id(),
            new_subject: "analyst-agent".into(),
            actions: vec![Action::Read],
            constraints: Constraints::new(),
            delegatable: false,
            max_uses: Some(50),
            ttl_secs: Some(1800),
        })
        .unwrap();

    assert_eq!(handle.token_count(), 4);

    // 4. Evaluate 100 calls across all agents
    let mut allow_count = 0;
    let mut deny_count = 0;

    for i in 0..100 {
        let result = match i % 5 {
            // Finance agent: valid read within constraints → Allow
            0 => handle.evaluate(&ToolCallRequest {
                agent_id: "finance-agent".into(),
                tool_name: "query_db".into(),
                action: Action::Read,
                resource: Resource::new("db://finance/transactions").unwrap(),
                parameters: [("max_amount".into(), format!("{}", (i * 10) % 999))].into(),
                token_id: finance_token.token.id(),
            }),
            // Email agent: valid execute → Allow
            1 => handle.evaluate(&ToolCallRequest {
                agent_id: "email-agent".into(),
                tool_name: "send_email".into(),
                action: Action::Execute,
                resource: Resource::new("email://smtp.corp.com").unwrap(),
                parameters: [("domain".into(), "corp.com".into())].into(),
                token_id: email_token.token.id(),
            }),
            // File agent: valid read → Allow
            2 => handle.evaluate(&ToolCallRequest {
                agent_id: "file-agent".into(),
                tool_name: "read_report".into(),
                action: Action::Read,
                resource: Resource::new("file:///data/reports").unwrap(),
                parameters: HashMap::new(),
                token_id: file_token.token.id(),
            }),
            // Analyst (delegated): valid read → Allow
            3 => handle.evaluate(&ToolCallRequest {
                agent_id: "analyst-agent".into(),
                tool_name: "query_db".into(),
                action: Action::Read,
                resource: Resource::new("db://finance/transactions").unwrap(),
                parameters: [("max_amount".into(), "100".into())].into(),
                token_id: analyst_token.token.id(),
            }),
            // Intentional deny: wrong action for finance-agent
            _ => handle.evaluate(&ToolCallRequest {
                agent_id: "finance-agent".into(),
                tool_name: "delete_records".into(),
                action: Action::Delete,
                resource: Resource::new("db://finance/transactions").unwrap(),
                parameters: HashMap::new(),
                token_id: finance_token.token.id(),
            }),
        };

        match result.decision {
            Decision::Allow => allow_count += 1,
            Decision::Deny => deny_count += 1,
        }
    }

    // 80 should be allowed (indices 0,1,2,3 of each 5), 20 denied (index 4)
    assert_eq!(allow_count, 80, "expected 80 allows");
    assert_eq!(deny_count, 20, "expected 20 denies");

    // 5. Query audit log
    assert_eq!(handle.audit_len(), 100);

    // Filter by decision
    let allows = handle.query_audit(&AuditQuery::new().decision(Decision::Allow).page(0, 200));
    assert_eq!(allows.total, 80);

    let denies = handle.query_audit(&AuditQuery::new().decision(Decision::Deny).page(0, 200));
    assert_eq!(denies.total, 20);

    // Filter by agent
    let finance_entries =
        handle.query_audit(&AuditQuery::new().agent("finance-agent").page(0, 200));
    assert_eq!(finance_entries.total, 40); // 20 reads + 20 deletes

    let analyst_entries =
        handle.query_audit(&AuditQuery::new().agent("analyst-agent").page(0, 200));
    assert_eq!(analyst_entries.total, 20);

    // Sorted newest first by default
    let page = handle.query_audit(&AuditQuery::new().page(0, 5));
    assert!(page.entries[0].timestamp >= page.entries[4].timestamp);

    // Sorted oldest first
    let page = handle.query_audit(&AuditQuery::new().sort(SortOrder::OldestFirst).page(0, 5));
    assert!(page.entries[0].timestamp <= page.entries[4].timestamp);

    // 6. JSONL export
    let mut buf = Vec::new();
    let exported = handle.export_audit(&mut buf).unwrap();
    assert_eq!(exported, 100);
    let jsonl = String::from_utf8(buf).unwrap();
    let lines: Vec<&str> = jsonl.trim().split('\n').collect();
    assert_eq!(lines.len(), 100);

    // 7. Revoke finance token → cascades to analyst
    let revoked = handle.revoke_token(finance_token.token.id()).unwrap();
    assert_eq!(revoked.len(), 2);

    // 8. Subsequent calls from analyst should be denied
    let result = handle.evaluate(&ToolCallRequest {
        agent_id: "analyst-agent".into(),
        tool_name: "query_db".into(),
        action: Action::Read,
        resource: Resource::new("db://finance/transactions").unwrap(),
        parameters: HashMap::new(),
        token_id: analyst_token.token.id(),
    });
    assert_eq!(result.decision, Decision::Deny);
    assert!(result.audit.reason.contains("revoked"));

    // 9. Reload new policies
    let new_tokens = handle
        .load_policies_yaml(
            r#"
policies:
  - name: new-finance
    agent: finance-agent-v2
    resource: "db://finance/transactions"
    actions: [read]
    ttl: 2h
"#,
        )
        .unwrap();
    assert_eq!(new_tokens.len(), 1);
    // Old tokens still exist (3 original + 1 delegated + 1 new)
    assert_eq!(handle.token_count(), 5);
}

// ═══════════════════════════════════════════════════════════════════════
// Thread safety
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn concurrent_evaluate() {
    use std::sync::Arc;

    let handle = Arc::new(KernelHandle::new());
    let signed = handle
        .issue_token(TokenRequest {
            subject: "agent".into(),
            resource: Resource::new("test://r").unwrap(),
            actions: vec![Action::Read],
            constraints: Constraints::new(),
            ttl: Some(Duration::from_secs(3600)),
            delegatable: false,
            max_uses: None,
        })
        .unwrap();
    let token_id = signed.token.id();

    let mut handles = vec![];
    for t in 0..10 {
        let h = Arc::clone(&handle);
        handles.push(std::thread::spawn(move || {
            for i in 0..10 {
                let result = h.evaluate(&ToolCallRequest {
                    agent_id: "agent".into(),
                    tool_name: format!("tool-{t}-{i}"),
                    action: Action::Read,
                    resource: Resource::new("test://r").unwrap(),
                    parameters: HashMap::new(),
                    token_id,
                });
                assert_eq!(result.decision, Decision::Allow);
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    assert_eq!(handle.audit_len(), 100);
}

// ═══════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════

fn issue_simple(handle: &KernelHandle, subject: &str, resource: &str) -> SignedToken {
    handle
        .issue_token(TokenRequest {
            subject: subject.into(),
            resource: Resource::new(resource).unwrap(),
            actions: vec![Action::Read, Action::Write],
            constraints: Constraints::new(),
            ttl: Some(Duration::from_secs(3600)),
            delegatable: false,
            max_uses: None,
        })
        .unwrap()
}

fn eval(
    handle: &KernelHandle,
    agent: &str,
    tool: &str,
    action: Action,
    resource: &str,
    token_id: uuid::Uuid,
) -> aegis_handle::EnforcementResult {
    handle.evaluate(&ToolCallRequest {
        agent_id: agent.into(),
        tool_name: tool.into(),
        action,
        resource: Resource::new(resource).unwrap(),
        parameters: HashMap::new(),
        token_id,
    })
}
