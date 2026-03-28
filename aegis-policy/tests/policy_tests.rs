use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use aegis_core::{Action, ParamConstraint};
use aegis_policy::{PolicyCompiler, PolicyError, PolicyWatcher};

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

// ═══════════════════════════════════════════════════════════════════════
// Step 1: YAML DSL parsing
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn parse_basic_policy_file() {
    let compiler = PolicyCompiler::new();
    let requests = compiler
        .compile_file(&fixtures_dir().join("basic.yaml"))
        .unwrap();
    assert_eq!(requests.len(), 2);
}

#[test]
fn basic_policy_finance_agent() {
    let compiler = PolicyCompiler::new();
    let requests = compiler
        .compile_file(&fixtures_dir().join("basic.yaml"))
        .unwrap();

    let finance = &requests[0];
    assert_eq!(finance.subject, "finance-agent");
    assert_eq!(finance.resource.path(), "db://finance/transactions");
    assert_eq!(finance.actions, vec![Action::Read]);
    assert_eq!(finance.ttl, Some(Duration::from_secs(60)));
    assert!(!finance.delegatable);
    assert_eq!(finance.max_uses, Some(100));

    // Constraint: max_amount as Number(1000) → Range(0, 1000)
    let max_amount = finance.constraints.get("max_amount").unwrap();
    assert_eq!(
        *max_amount,
        ParamConstraint::Range {
            min: 0.0,
            max: 1000.0
        }
    );
}

#[test]
fn basic_policy_email_agent() {
    let compiler = PolicyCompiler::new();
    let requests = compiler
        .compile_file(&fixtures_dir().join("basic.yaml"))
        .unwrap();

    let email = &requests[1];
    assert_eq!(email.subject, "email-agent");
    assert_eq!(email.resource.path(), "email://smtp.corp.com");
    assert_eq!(email.actions, vec![Action::Execute]);
    assert_eq!(email.ttl, Some(Duration::from_secs(300)));
    assert!(email.delegatable);

    // OneOf constraint
    let domain = email.constraints.get("domain").unwrap();
    assert_eq!(
        *domain,
        ParamConstraint::OneOf(vec!["corp.com".into(), "partner.com".into()])
    );

    // Range constraint
    let body_length = email.constraints.get("body_length").unwrap();
    assert_eq!(
        *body_length,
        ParamConstraint::Range {
            min: 1.0,
            max: 10000.0
        }
    );
}

#[test]
fn structured_resource_compiles_to_provider_path() {
    let compiler = PolicyCompiler::new();
    let requests = compiler
        .compile_file(&fixtures_dir().join("structured_resource.yaml"))
        .unwrap();

    assert_eq!(requests.len(), 1);
    let req = &requests[0];
    assert_eq!(req.subject, "data-agent");
    assert_eq!(req.resource.path(), "postgres://postgres.query");
    assert_eq!(req.actions, vec![Action::Read, Action::Write]);
    assert_eq!(req.ttl, Some(Duration::from_secs(3600)));
}

#[test]
fn compile_from_string() {
    let yaml = r#"
policies:
  - name: inline-test
    agent: test-agent
    resource: "test://resource"
    actions: [read, write, delete]
    ttl: 1d
    delegatable: true
    max_uses: 50
"#;
    let compiler = PolicyCompiler::new();
    let requests = compiler.compile_str(yaml).unwrap();
    assert_eq!(requests.len(), 1);
    let req = &requests[0];
    assert_eq!(req.subject, "test-agent");
    assert_eq!(
        req.actions,
        vec![Action::Read, Action::Write, Action::Delete]
    );
    assert_eq!(req.ttl, Some(Duration::from_secs(86400)));
    assert!(req.delegatable);
    assert_eq!(req.max_uses, Some(50));
}

#[test]
fn custom_action_parsing() {
    let yaml = r#"
policies:
  - name: custom-actions
    agent: agent
    resource: "api://service"
    actions: [read, approve, escalate]
"#;
    let compiler = PolicyCompiler::new();
    let requests = compiler.compile_str(yaml).unwrap();
    assert_eq!(
        requests[0].actions,
        vec![
            Action::Read,
            Action::Custom("approve".into()),
            Action::Custom("escalate".into()),
        ]
    );
}

#[test]
fn string_constraint_is_exact() {
    let yaml = r#"
policies:
  - name: exact-test
    agent: agent
    resource: "test://r"
    actions: [read]
    constraints:
      region: "us-east-1"
"#;
    let compiler = PolicyCompiler::new();
    let requests = compiler.compile_str(yaml).unwrap();
    let c = requests[0].constraints.get("region").unwrap();
    assert_eq!(*c, ParamConstraint::Exact("us-east-1".into()));
}

#[test]
fn bool_constraint_is_exact_string() {
    let yaml = r#"
policies:
  - name: bool-test
    agent: agent
    resource: "test://r"
    actions: [read]
    constraints:
      verbose: true
"#;
    let compiler = PolicyCompiler::new();
    let requests = compiler.compile_str(yaml).unwrap();
    let c = requests[0].constraints.get("verbose").unwrap();
    assert_eq!(*c, ParamConstraint::Exact("true".into()));
}

#[test]
fn regex_constraint() {
    let yaml = r#"
policies:
  - name: regex-test
    agent: agent
    resource: "test://r"
    actions: [read]
    constraints:
      filename:
        type: regex
        pattern: "^report_\\d{4}\\.csv$"
"#;
    let compiler = PolicyCompiler::new();
    let requests = compiler.compile_str(yaml).unwrap();
    let c = requests[0].constraints.get("filename").unwrap();
    assert_eq!(*c, ParamConstraint::Regex("^report_\\d{4}\\.csv$".into()));
}

#[test]
fn explicit_exact_constraint() {
    let yaml = r#"
policies:
  - name: explicit-exact
    agent: agent
    resource: "test://r"
    actions: [read]
    constraints:
      env:
        type: exact
        value: production
"#;
    let compiler = PolicyCompiler::new();
    let requests = compiler.compile_str(yaml).unwrap();
    let c = requests[0].constraints.get("env").unwrap();
    assert_eq!(*c, ParamConstraint::Exact("production".into()));
}

#[test]
fn no_ttl_means_none() {
    let yaml = r#"
policies:
  - name: no-ttl
    agent: agent
    resource: "test://r"
    actions: [read]
"#;
    let compiler = PolicyCompiler::new();
    let requests = compiler.compile_str(yaml).unwrap();
    assert_eq!(requests[0].ttl, None);
}

#[test]
fn no_constraints_means_empty() {
    let yaml = r#"
policies:
  - name: no-constraints
    agent: agent
    resource: "test://r"
    actions: [read]
"#;
    let compiler = PolicyCompiler::new();
    let requests = compiler.compile_str(yaml).unwrap();
    assert!(requests[0].constraints.is_empty());
}

#[test]
fn numeric_ttl_string() {
    let yaml = r#"
policies:
  - name: numeric-ttl
    agent: agent
    resource: "test://r"
    actions: [read]
    ttl: "120"
"#;
    let compiler = PolicyCompiler::new();
    let requests = compiler.compile_str(yaml).unwrap();
    assert_eq!(requests[0].ttl, Some(Duration::from_secs(120)));
}

// ═══════════════════════════════════════════════════════════════════════
// Step 2: Validation errors
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn reject_empty_agent() {
    let compiler = PolicyCompiler::new();
    let err = compiler
        .compile_file(&fixtures_dir().join("invalid_empty_agent.yaml"))
        .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("agent must not be empty"), "got: {msg}");
}

#[test]
fn reject_empty_actions() {
    let compiler = PolicyCompiler::new();
    let err = compiler
        .compile_file(&fixtures_dir().join("invalid_no_actions.yaml"))
        .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("actions must not be empty"), "got: {msg}");
}

#[test]
fn reject_duplicate_names() {
    let compiler = PolicyCompiler::new();
    let err = compiler
        .compile_file(&fixtures_dir().join("duplicate_names.yaml"))
        .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("duplicate policy name"), "got: {msg}");
}

#[test]
fn reject_empty_policy_name() {
    let yaml = r#"
policies:
  - name: ""
    agent: agent
    resource: "test://r"
    actions: [read]
"#;
    let compiler = PolicyCompiler::new();
    let err = compiler.compile_str(yaml).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("name must not be empty"), "got: {msg}");
}

#[test]
fn reject_empty_resource() {
    let yaml = r#"
policies:
  - name: bad
    agent: agent
    resource: ""
    actions: [read]
"#;
    let compiler = PolicyCompiler::new();
    let err = compiler.compile_str(yaml).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("resource"), "got: {msg}");
}

#[test]
fn reject_zero_max_uses() {
    let yaml = r#"
policies:
  - name: bad
    agent: agent
    resource: "test://r"
    actions: [read]
    max_uses: 0
"#;
    let compiler = PolicyCompiler::new();
    let err = compiler.compile_str(yaml).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("max_uses"), "got: {msg}");
}

#[test]
fn reject_invalid_range_constraint() {
    let yaml = r#"
policies:
  - name: bad-range
    agent: agent
    resource: "test://r"
    actions: [read]
    constraints:
      amount:
        type: range
        min: 100
        max: 10
"#;
    let compiler = PolicyCompiler::new();
    let err = compiler.compile_str(yaml).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("invalid range"), "got: {msg}");
}

#[test]
fn reject_invalid_ttl() {
    let yaml = r#"
policies:
  - name: bad-ttl
    agent: agent
    resource: "test://r"
    actions: [read]
    ttl: "5x"
"#;
    let compiler = PolicyCompiler::new();
    let err = compiler.compile_str(yaml).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("ttl"), "got: {msg}");
}

#[test]
fn reject_malformed_yaml() {
    let yaml = "not: valid: yaml: [[[";
    let compiler = PolicyCompiler::new();
    let err = compiler.compile_str(yaml).unwrap_err();
    assert!(matches!(err, PolicyError::Yaml(_)));
}

// ═══════════════════════════════════════════════════════════════════════
// Step 3: Directory loading
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn compile_directory_loads_all_yaml_files() {
    // Create a temp dir with two policy files
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("a.yaml"),
        r#"
policies:
  - name: policy-a
    agent: agent-a
    resource: "test://a"
    actions: [read]
"#,
    )
    .unwrap();
    std::fs::write(
        dir.path().join("b.yml"),
        r#"
policies:
  - name: policy-b
    agent: agent-b
    resource: "test://b"
    actions: [write]
"#,
    )
    .unwrap();
    // Non-YAML file should be ignored
    std::fs::write(dir.path().join("readme.txt"), "not a policy").unwrap();

    let watcher = PolicyWatcher::new(dir.path(), None).unwrap();
    let policies = watcher.policies();
    assert_eq!(policies.len(), 2);
}

// ═══════════════════════════════════════════════════════════════════════
// Step 3: Hot-reload watcher
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn watcher_initial_load() {
    let watcher = PolicyWatcher::new(fixtures_dir().join("basic.yaml"), None).unwrap();
    let policies = watcher.policies();
    assert_eq!(policies.len(), 2);
    assert_eq!(policies[0].subject, "finance-agent");
}

#[test]
fn watcher_manual_reload() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("policies.yaml");
    std::fs::write(
        &file,
        r#"
policies:
  - name: initial
    agent: agent-1
    resource: "test://r"
    actions: [read]
"#,
    )
    .unwrap();

    let watcher = PolicyWatcher::new(&file, None).unwrap();
    assert_eq!(watcher.policies().len(), 1);
    assert_eq!(watcher.policies()[0].subject, "agent-1");

    // Overwrite with two policies
    std::fs::write(
        &file,
        r#"
policies:
  - name: updated-1
    agent: agent-updated
    resource: "test://r"
    actions: [read]
  - name: updated-2
    agent: agent-2
    resource: "test://r2"
    actions: [write]
"#,
    )
    .unwrap();

    let reloaded = watcher.reload().unwrap();
    assert_eq!(reloaded.len(), 2);
    assert_eq!(reloaded[0].subject, "agent-updated");
    assert_eq!(watcher.policies().len(), 2);
}

#[test]
fn watcher_fs_hot_reload() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("policies.yaml");
    std::fs::write(
        &file,
        r#"
policies:
  - name: v1
    agent: agent-1
    resource: "test://r"
    actions: [read]
"#,
    )
    .unwrap();

    let reload_count = Arc::new(AtomicUsize::new(0));
    let reload_count_clone = Arc::clone(&reload_count);

    let watcher = PolicyWatcher::new(
        &file,
        Some(Box::new(move |_policies| {
            reload_count_clone.fetch_add(1, Ordering::SeqCst);
        })),
    )
    .unwrap();

    assert_eq!(watcher.policies().len(), 1);

    // Modify the file
    std::fs::write(
        &file,
        r#"
policies:
  - name: v2-a
    agent: agent-new
    resource: "test://r"
    actions: [read]
  - name: v2-b
    agent: agent-2
    resource: "test://r2"
    actions: [write]
"#,
    )
    .unwrap();

    // Wait for the filesystem event to fire
    std::thread::sleep(Duration::from_secs(2));

    // The watcher should have reloaded
    let policies = watcher.policies();
    assert_eq!(policies.len(), 2, "expected 2 policies after hot reload");
    assert_eq!(policies[0].subject, "agent-new");
    assert!(reload_count.load(Ordering::SeqCst) >= 1);
}

#[test]
fn watcher_invalid_update_keeps_old_policies() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("policies.yaml");
    std::fs::write(
        &file,
        r#"
policies:
  - name: good
    agent: agent-1
    resource: "test://r"
    actions: [read]
"#,
    )
    .unwrap();

    let watcher = PolicyWatcher::new(&file, None).unwrap();
    assert_eq!(watcher.policies().len(), 1);

    // Write invalid YAML
    std::fs::write(&file, "not valid yaml [[[").unwrap();
    std::thread::sleep(Duration::from_secs(2));

    // Should still have the old valid policies
    let policies = watcher.policies();
    assert_eq!(policies.len(), 1);
    assert_eq!(policies[0].subject, "agent-1");
}

#[test]
fn watcher_path_is_correct() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("test.yaml");
    std::fs::write(
        &file,
        r#"
policies:
  - name: test
    agent: agent
    resource: "test://r"
    actions: [read]
"#,
    )
    .unwrap();

    let watcher = PolicyWatcher::new(&file, None).unwrap();
    assert_eq!(watcher.path(), file.as_path());
}

// ═══════════════════════════════════════════════════════════════════════
// End-to-end: compile policies then issue tokens
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn compiled_policies_can_issue_tokens() {
    use aegis_core::{Ed25519TokenSigner, InMemoryTokenStore, IssuerConfig, TokenIssuer};
    use std::sync::Arc;

    let compiler = PolicyCompiler::new();
    let requests = compiler
        .compile_file(&fixtures_dir().join("basic.yaml"))
        .unwrap();

    let signer = Ed25519TokenSigner::generate();
    let store = Arc::new(InMemoryTokenStore::new());
    let issuer = TokenIssuer::new(signer, store, IssuerConfig::default());

    for request in requests {
        let signed = issuer.issue(request).unwrap();
        assert!(!signed.token.is_revoked());
    }
}

#[test]
fn multiple_constraint_types_in_one_policy() {
    let yaml = r#"
policies:
  - name: multi-constraint
    agent: agent
    resource: "api://service"
    actions: [execute]
    constraints:
      amount: 500
      currency: "USD"
      env:
        type: exact
        value: production
      region:
        type: one_of
        values: [us-east-1, eu-west-1]
      filename:
        type: regex
        pattern: "^data_.*\\.csv$"
      score:
        type: range
        min: 0
        max: 100
    ttl: 30m
"#;
    let compiler = PolicyCompiler::new();
    let requests = compiler.compile_str(yaml).unwrap();
    let req = &requests[0];

    assert_eq!(req.constraints.len(), 6);
    assert_eq!(
        *req.constraints.get("amount").unwrap(),
        ParamConstraint::Range {
            min: 0.0,
            max: 500.0
        }
    );
    assert_eq!(
        *req.constraints.get("currency").unwrap(),
        ParamConstraint::Exact("USD".into())
    );
    assert_eq!(
        *req.constraints.get("env").unwrap(),
        ParamConstraint::Exact("production".into())
    );
    assert_eq!(
        *req.constraints.get("region").unwrap(),
        ParamConstraint::OneOf(vec!["us-east-1".into(), "eu-west-1".into()])
    );
    assert_eq!(
        *req.constraints.get("filename").unwrap(),
        ParamConstraint::Regex("^data_.*\\.csv$".into())
    );
    assert_eq!(
        *req.constraints.get("score").unwrap(),
        ParamConstraint::Range {
            min: 0.0,
            max: 100.0
        }
    );
}
