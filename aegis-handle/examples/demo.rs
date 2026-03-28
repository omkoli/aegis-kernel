use std::collections::HashMap;

use aegis_handle::{
    Action, AuditQuery, Decision, KernelHandle, Resource, SortOrder, ToolCallRequest,
};

fn main() {
    println!("=== Aegis Kernel Demo ===\n");

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
    max_uses: 50

  - name: email-send
    agent: email-agent
    resource: "email://smtp.corp.com"
    actions: [execute]
    constraints:
      domain:
        type: one_of
        values: ["corp.com", "partner.com"]
    ttl: 30m
"#,
    )
    .expect("failed to load policies");

    println!("Loaded {} tokens from policy YAML\n", handle.token_count());

    // 2. List issued tokens
    for token in handle.list_tokens() {
        println!(
            "  Token {} → subject={}, resource={}, actions={:?}",
            token.token.id(),
            token.token.subject(),
            token.token.resource().path(),
            token.token.actions(),
        );
    }
    println!();

    // 3. Find the finance token
    let tokens = handle.list_tokens();
    let finance = tokens
        .iter()
        .find(|t| t.token.subject() == "finance-agent")
        .expect("finance token not found");
    let email = tokens
        .iter()
        .find(|t| t.token.subject() == "email-agent")
        .expect("email token not found");

    // 4. Evaluate some tool calls
    let calls: Vec<(&str, ToolCallRequest)> = vec![
        (
            "Finance: read $500 (should ALLOW)",
            ToolCallRequest {
                agent_id: "finance-agent".into(),
                tool_name: "query_db".into(),
                action: Action::Read,
                resource: Resource::new("db://finance/transactions").unwrap(),
                parameters: [("max_amount".into(), "500".into())].into(),
                token_id: finance.token.id(),
            },
        ),
        (
            "Finance: read $5000 (should DENY — over constraint)",
            ToolCallRequest {
                agent_id: "finance-agent".into(),
                tool_name: "query_db".into(),
                action: Action::Read,
                resource: Resource::new("db://finance/transactions").unwrap(),
                parameters: [("max_amount".into(), "5000".into())].into(),
                token_id: finance.token.id(),
            },
        ),
        (
            "Finance: write (should DENY — wrong action)",
            ToolCallRequest {
                agent_id: "finance-agent".into(),
                tool_name: "insert_row".into(),
                action: Action::Write,
                resource: Resource::new("db://finance/transactions").unwrap(),
                parameters: HashMap::new(),
                token_id: finance.token.id(),
            },
        ),
        (
            "Email: send to corp.com (should ALLOW)",
            ToolCallRequest {
                agent_id: "email-agent".into(),
                tool_name: "send_email".into(),
                action: Action::Execute,
                resource: Resource::new("email://smtp.corp.com").unwrap(),
                parameters: [("domain".into(), "corp.com".into())].into(),
                token_id: email.token.id(),
            },
        ),
        (
            "Email: send to evil.com (should DENY — constraint)",
            ToolCallRequest {
                agent_id: "email-agent".into(),
                tool_name: "send_email".into(),
                action: Action::Execute,
                resource: Resource::new("email://smtp.corp.com").unwrap(),
                parameters: [("domain".into(), "evil.com".into())].into(),
                token_id: email.token.id(),
            },
        ),
        (
            "Wrong agent (should DENY — subject mismatch)",
            ToolCallRequest {
                agent_id: "rogue-agent".into(),
                tool_name: "query_db".into(),
                action: Action::Read,
                resource: Resource::new("db://finance/transactions").unwrap(),
                parameters: HashMap::new(),
                token_id: finance.token.id(),
            },
        ),
    ];

    println!("--- Evaluating {} tool calls ---\n", calls.len());
    for (label, req) in &calls {
        let result = handle.evaluate(req);
        let icon = match result.decision {
            Decision::Allow => "ALLOW",
            Decision::Deny => "DENY ",
        };
        println!(
            "  [{}] {} ({}us)\n         reason: {}\n",
            icon, label, result.audit.latency_us, result.audit.reason
        );
    }

    // 5. Query audit log
    println!("--- Audit Log Summary ---\n");
    let allows = handle
        .query_audit(&AuditQuery::new().decision(Decision::Allow).page(0, 100));
    let denies = handle
        .query_audit(&AuditQuery::new().decision(Decision::Deny).page(0, 100));
    println!("  Total entries: {}", handle.audit_len());
    println!("  Allowed: {}", allows.total);
    println!("  Denied:  {}", denies.total);

    println!("\n  Most recent 3 entries (newest first):");
    let recent = handle.query_audit(&AuditQuery::new().sort(SortOrder::NewestFirst).page(0, 3));
    for entry in &recent.entries {
        println!(
            "    {} | {} | {} | {} | {}",
            entry.timestamp.format("%H:%M:%S"),
            entry.agent_id,
            entry.tool_name,
            match entry.decision {
                Decision::Allow => "ALLOW",
                Decision::Deny => "DENY",
            },
            entry.reason,
        );
    }

    // 6. JSONL export
    let mut jsonl = Vec::new();
    let count = handle.export_audit(&mut jsonl).unwrap();
    println!("\n  Exported {} entries as JSONL ({} bytes)", count, jsonl.len());

    // 7. Revocation demo
    println!("\n--- Revocation Demo ---\n");
    let revoked = handle.revoke_token(finance.token.id()).unwrap();
    println!("  Revoked {} token(s): {:?}", revoked.len(), revoked);

    let result = handle.evaluate(&calls[0].1);
    println!(
        "  Finance read after revocation: {} ({})",
        match result.decision {
            Decision::Allow => "ALLOW",
            Decision::Deny => "DENY",
        },
        result.audit.reason
    );

    println!("\n=== Demo complete ===");
}
