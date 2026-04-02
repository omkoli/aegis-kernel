//! Gateway-level audit log: JSONL writer with buffering, log rotation, and
//! a SHA-256 hash chain for tamper detection.
//!
//! ## Record format
//!
//! Each tool call produces one [`AuditRecord`] serialised as a single JSON line
//! and appended to `<audit_dir>/audit.jsonl`.  The record carries all fields
//! required to reconstruct what happened:
//!
//! ```json
//! {
//!   "timestamp": "2026-04-02T12:00:00.000Z",
//!   "trace_id": "018e8d40-1234-7abc-...",
//!   "agent_id": "agent-alpha",
//!   "server_name": "github",
//!   "tool_name": "search_repositories",
//!   "parameters": { "query": "[REDACTED]" },
//!   "decision": "ALLOW",
//!   "deny_reason": null,
//!   "capability_token_id": null,
//!   "latency_us": 312,
//!   "rate_limit_remaining": 97,
//!   "upstream_status": "SUCCESS",
//!   "upstream_latency_us": 287,
//!   "prev_hash": "a3f4..."
//! }
//! ```
//!
//! ## Hash chain
//!
//! The `prev_hash` field is the hex-encoded SHA-256 of the previous record's
//! serialised JSON line.  The first record uses
//! `SHA-256("aegis-audit-genesis-v1")` as its `prev_hash`.  Any modification
//! to a historical record will invalidate all subsequent hashes, making
//! tampering detectable.
//!
//! ## Parameter redaction
//!
//! All parameter values are replaced with `"[REDACTED]"` by default.  The
//! caller can pass a list of *safe field names* (see [`redact_parameters`])
//! whose values are preserved verbatim.  Safe fields are configured per-tool
//! in `[servers.<name>.tools.<tool>.safe_log_fields]`.
//!
//! ## Async writer
//!
//! [`spawn_audit_writer`] starts a background tokio task that owns the file
//! handle.  Callers interact through [`AuditWriterHandle`] which is cheap to
//! clone.  Records are flushed when:
//! - the internal buffer reaches **100 records**, or
//! - **1 second** elapses since the last flush.
//!
//! ## Log rotation
//!
//! The active file is rotated when:
//! - the calendar date (UTC) changes, or
//! - the file exceeds **100 MB**.
//!
//! Rotated files are renamed `audit.<YYYY-MM-DD>T<HH-MM-SS>Z.jsonl`.
//! Files older than **30 days** are deleted automatically.

use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Well-known input hashed to produce the genesis `prev_hash` value.
pub const GENESIS_INPUT: &str = "aegis-audit-genesis-v1";

/// Records are flushed when this many are buffered.
const FLUSH_BATCH: usize = 100;

/// Max file size before rotation (100 MiB).
const DEFAULT_MAX_SIZE_BYTES: u64 = 100 * 1024 * 1024;

/// Days of rotated files to retain.
const DEFAULT_RETENTION_DAYS: u32 = 30;

/// mpsc channel capacity (number of in-flight records).
const DEFAULT_CHANNEL_CAPACITY: usize = 4096;

// ---------------------------------------------------------------------------
// Enumerations
// ---------------------------------------------------------------------------

/// Enforcement outcome recorded in the audit log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuditDecision {
    Allow,
    Deny,
}

/// Whether the upstream MCP server responded successfully.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UpstreamStatus {
    Success,
    Error,
    Timeout,
}

// ---------------------------------------------------------------------------
// AuditRecord
// ---------------------------------------------------------------------------

/// A single gateway-level audit entry for one tool call.
///
/// Construct with the public fields, leaving `prev_hash` as
/// [`String::new()`].  The [`AuditWriterHandle`] fills in `prev_hash`
/// before serialising.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    /// When the tool call was received by the gateway (UTC).
    pub timestamp: DateTime<Utc>,

    /// UUID v7 unique identifier for this request (time-sortable).
    pub trace_id: Uuid,

    /// Resolved agent identity (from [`crate::identity::AgentIdentifier`]).
    pub agent_id: String,

    /// Name of the MCP server that was targeted.
    pub server_name: String,

    /// Name of the tool that was invoked.
    pub tool_name: String,

    /// Tool parameters with sensitive values masked (see [`redact_parameters`]).
    pub parameters: serde_json::Value,

    /// Enforcement outcome.
    pub decision: AuditDecision,

    /// If denied: the specific reason and check that failed.
    pub deny_reason: Option<String>,

    /// The capability token that authorised this call, if any.
    pub capability_token_id: Option<Uuid>,

    /// Total gateway processing time in microseconds.
    pub latency_us: u64,

    /// Remaining calls in the current rate-limit window, if applicable.
    pub rate_limit_remaining: Option<u32>,

    /// Whether the upstream MCP server responded successfully.
    pub upstream_status: Option<UpstreamStatus>,

    /// Time the upstream MCP server took to respond, in microseconds.
    pub upstream_latency_us: Option<u64>,

    /// Hex-encoded SHA-256 of the previous record's serialised JSON line.
    ///
    /// Set by the writer — leave as [`String::new()`] when constructing.
    pub prev_hash: String,
}

impl AuditRecord {
    /// Create a new record for an **allowed** tool call.
    pub fn allow(
        agent_id: impl Into<String>,
        server_name: impl Into<String>,
        tool_name: impl Into<String>,
        parameters: serde_json::Value,
        latency_us: u64,
    ) -> Self {
        Self {
            timestamp: Utc::now(),
            trace_id: new_trace_id(),
            agent_id: agent_id.into(),
            server_name: server_name.into(),
            tool_name: tool_name.into(),
            parameters,
            decision: AuditDecision::Allow,
            deny_reason: None,
            capability_token_id: None,
            latency_us,
            rate_limit_remaining: None,
            upstream_status: None,
            upstream_latency_us: None,
            prev_hash: String::new(),
        }
    }

    /// Create a new record for a **denied** tool call.
    pub fn deny(
        agent_id: impl Into<String>,
        server_name: impl Into<String>,
        tool_name: impl Into<String>,
        parameters: serde_json::Value,
        latency_us: u64,
        deny_reason: impl Into<String>,
    ) -> Self {
        Self {
            timestamp: Utc::now(),
            trace_id: new_trace_id(),
            agent_id: agent_id.into(),
            server_name: server_name.into(),
            tool_name: tool_name.into(),
            parameters,
            decision: AuditDecision::Deny,
            deny_reason: Some(deny_reason.into()),
            capability_token_id: None,
            latency_us,
            rate_limit_remaining: None,
            upstream_status: None,
            upstream_latency_us: None,
            prev_hash: String::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Hash chain helpers
// ---------------------------------------------------------------------------

/// Generate a UUID v7 (time-sortable) for `trace_id`.
pub fn new_trace_id() -> Uuid {
    let ts = uuid::Timestamp::now(uuid::NoContext);
    Uuid::new_v7(ts)
}

/// SHA-256 of [`GENESIS_INPUT`], used as `prev_hash` for the very first record.
pub fn genesis_hash() -> String {
    let hash = Sha256::digest(GENESIS_INPUT.as_bytes());
    hex::encode(hash)
}

/// SHA-256 of an already-serialised JSON line, used as the next `prev_hash`.
pub fn hash_record(serialized_line: &str) -> String {
    let hash = Sha256::digest(serialized_line.as_bytes());
    hex::encode(hash)
}

/// Verify the hash chain in an ordered slice of serialised JSON lines.
///
/// Returns `Ok(())` if every `prev_hash` matches the SHA-256 of the preceding
/// line (and the first line matches the genesis hash).  Returns the index of
/// the first broken link on failure.
pub fn verify_chain(lines: &[&str]) -> Result<(), usize> {
    let mut expected = genesis_hash();
    for (i, line) in lines.iter().enumerate() {
        let record: serde_json::Value = serde_json::from_str(line).map_err(|_| i)?;
        let actual = record["prev_hash"].as_str().unwrap_or("").to_string();
        if actual != expected {
            return Err(i);
        }
        expected = hash_record(line);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Parameter redaction
// ---------------------------------------------------------------------------

/// Replace parameter values with `"[REDACTED]"`, preserving only safe fields.
///
/// - If `params` is a JSON object, every value whose key is **not** in
///   `safe_fields` is replaced with the literal string `"[REDACTED]"`.
/// - If `params` is any other JSON type (string, array, …), the entire value
///   is replaced with `"[REDACTED]"`.
///
/// Keys are compared case-sensitively.  `safe_fields` should match the exact
/// key names as they appear in the `parameters` object.
pub fn redact_parameters(params: &serde_json::Value, safe_fields: &[String]) -> serde_json::Value {
    match params {
        serde_json::Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (k, v) in map {
                if safe_fields.iter().any(|f| f == k) {
                    out.insert(k.clone(), v.clone());
                } else {
                    out.insert(k.clone(), serde_json::json!("[REDACTED]"));
                }
            }
            serde_json::Value::Object(out)
        }
        _ => serde_json::json!("[REDACTED]"),
    }
}

// ---------------------------------------------------------------------------
// AuditWriterConfig
// ---------------------------------------------------------------------------

/// Configuration for [`spawn_audit_writer`].
#[derive(Debug, Clone)]
pub struct AuditWriterConfig {
    /// Directory where audit log files are written.
    pub dir: PathBuf,
    /// Maximum size of the active log file before rotation.  Default: 100 MiB.
    pub max_size_bytes: u64,
    /// Number of days of rotated files to keep.  Default: 30.
    pub retention_days: u32,
    /// mpsc channel capacity (in-flight records).  Default: 4096.
    pub channel_capacity: usize,
}

impl Default for AuditWriterConfig {
    fn default() -> Self {
        Self {
            dir: PathBuf::from("./audit"),
            max_size_bytes: DEFAULT_MAX_SIZE_BYTES,
            retention_days: DEFAULT_RETENTION_DAYS,
            channel_capacity: DEFAULT_CHANNEL_CAPACITY,
        }
    }
}

impl AuditWriterConfig {
    /// Construct with a specific directory and all other fields at their defaults.
    pub fn with_dir(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            ..Default::default()
        }
    }
}

// ---------------------------------------------------------------------------
// AuditError
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("audit writer channel is closed")]
    ChannelClosed,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

// ---------------------------------------------------------------------------
// Internal writer message
// ---------------------------------------------------------------------------

enum WriterMessage {
    Record(AuditRecord),
    Shutdown(oneshot::Sender<()>),
}

// ---------------------------------------------------------------------------
// AuditWriterHandle
// ---------------------------------------------------------------------------

/// Cheap-to-clone handle for sending records to the background audit writer.
///
/// Obtain one from [`spawn_audit_writer`].  Drop the last handle (or call
/// [`shutdown`]) to stop the writer cleanly.
#[derive(Clone)]
pub struct AuditWriterHandle {
    sender: mpsc::Sender<WriterMessage>,
}

impl AuditWriterHandle {
    /// Send one audit record to the writer.
    ///
    /// Blocks asynchronously if the channel is full (back-pressure).
    /// The `prev_hash` field is filled in by the writer — callers should
    /// leave it as [`String::new()`].
    pub async fn append(&self, record: AuditRecord) -> Result<(), AuditError> {
        self.sender
            .send(WriterMessage::Record(record))
            .await
            .map_err(|_| AuditError::ChannelClosed)
    }

    /// Flush all pending records to disk and stop the background writer.
    ///
    /// Waits until all previously sent records have been written.
    pub async fn shutdown(&self) {
        let (tx, rx) = oneshot::channel();
        let _ = self.sender.send(WriterMessage::Shutdown(tx)).await;
        let _ = rx.await;
    }
}

// ---------------------------------------------------------------------------
// spawn_audit_writer
// ---------------------------------------------------------------------------

/// Spawn the background audit writer task and return a handle.
///
/// Creates `config.dir` if it does not exist, then spawns a tokio task that
/// manages the audit file.  The task exits when all handles are dropped or
/// [`AuditWriterHandle::shutdown`] is called.
pub async fn spawn_audit_writer(
    config: AuditWriterConfig,
) -> Result<AuditWriterHandle, AuditError> {
    tokio::fs::create_dir_all(&config.dir)
        .await
        .map_err(AuditError::Io)?;

    let (tx, rx) = mpsc::channel(config.channel_capacity);
    tokio::spawn(writer_task(rx, config));

    Ok(AuditWriterHandle { sender: tx })
}

// ---------------------------------------------------------------------------
// Background writer task
// ---------------------------------------------------------------------------

async fn writer_task(mut rx: mpsc::Receiver<WriterMessage>, config: AuditWriterConfig) {
    let active_path = config.dir.join("audit.jsonl");

    let mut file = match open_append(&active_path).await {
        Ok(f) => f,
        Err(e) => {
            tracing::error!(path = %active_path.display(), error = %e, "audit writer: failed to open log");
            return;
        }
    };

    let mut prev_hash = genesis_hash();
    let mut buf: Vec<String> = Vec::with_capacity(FLUSH_BATCH + 4);
    let mut current_date = Utc::now().date_naive();

    // 1-second periodic flush timer
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            biased;

            msg = rx.recv() => {
                match msg {
                    Some(WriterMessage::Record(mut record)) => {
                        // Assign hash chain position before serialising
                        record.prev_hash = prev_hash.clone();
                        match serde_json::to_string(&record) {
                            Ok(json) => {
                                prev_hash = hash_record(&json);
                                buf.push(json);
                                if buf.len() >= FLUSH_BATCH {
                                    flush_buf(&mut file, &mut buf).await;
                                }
                            }
                            Err(e) => {
                                tracing::error!(error = %e, "audit: failed to serialise record — dropping");
                            }
                        }
                    }
                    Some(WriterMessage::Shutdown(reply)) => {
                        flush_buf(&mut file, &mut buf).await;
                        let _ = file.flush().await;
                        let _ = reply.send(());
                        return;
                    }
                    None => {
                        // All senders dropped
                        flush_buf(&mut file, &mut buf).await;
                        let _ = file.flush().await;
                        return;
                    }
                }
            }

            _ = interval.tick() => {
                // Flush the buffer first so the file size check is accurate
                if !buf.is_empty() {
                    flush_buf(&mut file, &mut buf).await;
                }

                // Check rotation conditions
                let today = Utc::now().date_naive();
                let size_exceeded = tokio::fs::metadata(&active_path)
                    .await
                    .map(|m| m.len() >= config.max_size_bytes)
                    .unwrap_or(false);

                if today != current_date || size_exceeded {
                    // Close the current file handle before renaming
                    drop(std::mem::replace(
                        &mut file,
                        // Temporary placeholder — will be replaced below
                        open_append(&active_path).await.unwrap_or_else(|_| {
                            // If we can't reopen, the next write will silently
                            // fail.  A real deployment would alert here.
                            panic!("audit writer: cannot open log file during rotation")
                        }),
                    ));

                    if let Err(e) = rotate_log(&active_path, &config).await {
                        tracing::error!(error = %e, "audit: log rotation failed");
                    }

                    file = match open_append(&active_path).await {
                        Ok(f) => f,
                        Err(e) => {
                            tracing::error!(error = %e, "audit writer: cannot open new log after rotation");
                            return;
                        }
                    };
                    current_date = today;
                }
            }
        }
    }
}

/// Write all buffered lines to the file in a single write call.
async fn flush_buf(file: &mut tokio::fs::File, buf: &mut Vec<String>) {
    if buf.is_empty() {
        return;
    }
    // Join with newlines in one allocation
    let mut bytes = String::with_capacity(buf.iter().map(|s| s.len() + 1).sum());
    for line in buf.drain(..) {
        bytes.push_str(&line);
        bytes.push('\n');
    }
    if let Err(e) = file.write_all(bytes.as_bytes()).await {
        tracing::error!(error = %e, "audit: write failed — records may be lost");
    }
}

/// Open an audit log file for appending, creating it if necessary.
async fn open_append(path: &Path) -> std::io::Result<tokio::fs::File> {
    tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await
}

// ---------------------------------------------------------------------------
// Log rotation
// ---------------------------------------------------------------------------

async fn rotate_log(active_path: &Path, config: &AuditWriterConfig) -> std::io::Result<()> {
    // Only rename if the active file exists and is non-empty
    let size = tokio::fs::metadata(active_path)
        .await
        .map(|m| m.len())
        .unwrap_or(0);
    if size > 0 {
        let stamp = Utc::now().format("%Y-%m-%dT%H-%M-%SZ");
        let rotated = config.dir.join(format!("audit.{stamp}.jsonl"));
        tokio::fs::rename(active_path, &rotated).await?;
        tracing::info!(rotated = %rotated.display(), "audit: rotated log file");
    }

    // Prune files older than `retention_days`
    if let Err(e) = prune_old_logs(&config.dir, config.retention_days).await {
        tracing::warn!(error = %e, "audit: pruning old files failed");
    }

    Ok(())
}

async fn prune_old_logs(dir: &Path, retention_days: u32) -> std::io::Result<()> {
    use chrono::Duration;

    let cutoff = (Utc::now() - Duration::days(i64::from(retention_days)))
        .format("%Y-%m-%d")
        .to_string();

    let mut rd = tokio::fs::read_dir(dir).await?;
    while let Ok(Some(entry)) = rd.next_entry().await {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        // Match rotated files: "audit.<date>T...jsonl" but not "audit.jsonl"
        if name.starts_with("audit.")
            && name.ends_with(".jsonl")
            && name != "audit.jsonl"
            && name.len() > 16
        {
            // Date is chars 6..16 in "audit.YYYY-MM-DDT..."
            let date_part = &name[6..16];
            if date_part.len() == 10 && date_part < cutoff.as_str() {
                let _ = tokio::fs::remove_file(entry.path()).await;
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn sample_record(i: u64) -> AuditRecord {
        AuditRecord {
            timestamp: Utc::now(),
            trace_id: new_trace_id(),
            agent_id: format!("agent-{}", i % 4),
            server_name: "test-server".into(),
            tool_name: "do_thing".into(),
            parameters: json!({ "x": "[REDACTED]" }),
            decision: if i % 3 == 0 {
                AuditDecision::Deny
            } else {
                AuditDecision::Allow
            },
            deny_reason: if i % 3 == 0 {
                Some("rate_limited".into())
            } else {
                None
            },
            capability_token_id: None,
            latency_us: i * 10,
            rate_limit_remaining: Some(100 - (i as u32 % 100)),
            upstream_status: Some(UpstreamStatus::Success),
            upstream_latency_us: Some(i * 5),
            prev_hash: String::new(),
        }
    }

    // -----------------------------------------------------------------------
    // 1. genesis_hash is deterministic
    // -----------------------------------------------------------------------

    #[test]
    fn genesis_hash_is_deterministic() {
        assert_eq!(genesis_hash(), genesis_hash());
        assert!(!genesis_hash().is_empty());
    }

    // -----------------------------------------------------------------------
    // 2. hash_record differs for different content
    // -----------------------------------------------------------------------

    #[test]
    fn hash_record_differs_for_different_content() {
        let h1 = hash_record(r#"{"decision":"ALLOW"}"#);
        let h2 = hash_record(r#"{"decision":"DENY"}"#);
        assert_ne!(h1, h2);
        assert_eq!(h1.len(), 64, "SHA-256 hex is 64 chars");
    }

    // -----------------------------------------------------------------------
    // 3. redact_parameters: all values masked by default
    // -----------------------------------------------------------------------

    #[test]
    fn redact_parameters_masks_all_by_default() {
        let params = json!({ "query": "SELECT *", "api_key": "sk-1234", "count": 10 });
        let redacted = redact_parameters(&params, &[]);
        assert_eq!(redacted["query"], "[REDACTED]");
        assert_eq!(redacted["api_key"], "[REDACTED]");
        assert_eq!(redacted["count"], "[REDACTED]");
    }

    // -----------------------------------------------------------------------
    // 4. redact_parameters: safe fields pass through unchanged
    // -----------------------------------------------------------------------

    #[test]
    fn redact_parameters_safe_fields_preserved() {
        let params = json!({
            "query": "hello",
            "per_page": 10,
            "api_key": "secret"
        });
        let safe = vec!["query".to_string(), "per_page".to_string()];
        let redacted = redact_parameters(&params, &safe);
        assert_eq!(redacted["query"], "hello");
        assert_eq!(redacted["per_page"], 10);
        assert_eq!(redacted["api_key"], "[REDACTED]");
    }

    // -----------------------------------------------------------------------
    // 5. redact_parameters: non-object input
    // -----------------------------------------------------------------------

    #[test]
    fn redact_parameters_non_object_returns_redacted() {
        assert_eq!(redact_parameters(&json!("raw string"), &[]), "[REDACTED]");
        assert_eq!(redact_parameters(&json!([1, 2, 3]), &[]), "[REDACTED]");
        assert_eq!(redact_parameters(&json!(null), &[]), "[REDACTED]");
        assert_eq!(redact_parameters(&json!(42), &[]), "[REDACTED]");
    }

    // -----------------------------------------------------------------------
    // 6. AuditDecision serialises as ALLOW / DENY
    // -----------------------------------------------------------------------

    #[test]
    fn audit_decision_serialises_uppercase() {
        let allow = serde_json::to_string(&AuditDecision::Allow).unwrap();
        let deny = serde_json::to_string(&AuditDecision::Deny).unwrap();
        assert_eq!(allow, "\"ALLOW\"");
        assert_eq!(deny, "\"DENY\"");
    }

    // -----------------------------------------------------------------------
    // 7. UpstreamStatus serialises as SUCCESS / ERROR / TIMEOUT
    // -----------------------------------------------------------------------

    #[test]
    fn upstream_status_serialises_uppercase() {
        assert_eq!(
            serde_json::to_string(&UpstreamStatus::Success).unwrap(),
            "\"SUCCESS\""
        );
        assert_eq!(
            serde_json::to_string(&UpstreamStatus::Error).unwrap(),
            "\"ERROR\""
        );
        assert_eq!(
            serde_json::to_string(&UpstreamStatus::Timeout).unwrap(),
            "\"TIMEOUT\""
        );
    }

    // -----------------------------------------------------------------------
    // 8. AuditRecord round-trips through JSON correctly
    // -----------------------------------------------------------------------

    #[test]
    fn audit_record_roundtrip() {
        let mut r = sample_record(1);
        r.prev_hash = genesis_hash();
        let json = serde_json::to_string(&r).unwrap();
        let back: AuditRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back.agent_id, r.agent_id);
        assert_eq!(back.tool_name, r.tool_name);
        assert_eq!(back.decision, r.decision);
        assert_eq!(back.prev_hash, r.prev_hash);
        assert_eq!(back.trace_id, r.trace_id);
    }

    // -----------------------------------------------------------------------
    // 9. AuditRecord::allow / deny constructors
    // -----------------------------------------------------------------------

    #[test]
    fn allow_constructor() {
        let r = AuditRecord::allow("agent", "server", "tool", json!({}), 100);
        assert_eq!(r.decision, AuditDecision::Allow);
        assert!(r.deny_reason.is_none());
        assert_eq!(r.latency_us, 100);
    }

    #[test]
    fn deny_constructor() {
        let r = AuditRecord::deny("agent", "server", "tool", json!({}), 50, "not_allowed");
        assert_eq!(r.decision, AuditDecision::Deny);
        assert_eq!(r.deny_reason.as_deref(), Some("not_allowed"));
    }

    // -----------------------------------------------------------------------
    // 10. Writer: records are persisted to JSONL file
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn writer_persists_records() {
        let dir = tempfile::TempDir::new().unwrap();
        let handle = spawn_audit_writer(AuditWriterConfig::with_dir(dir.path())).await.unwrap();

        for i in 0..10u64 {
            handle.append(sample_record(i)).await.unwrap();
        }
        handle.shutdown().await;

        let content = std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 10, "expected 10 records, got {}", lines.len());

        // All lines must parse
        for line in &lines {
            serde_json::from_str::<AuditRecord>(line)
                .expect("each line must be a valid AuditRecord");
        }
    }

    // -----------------------------------------------------------------------
    // 11. Writer: first record gets genesis hash
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn writer_first_record_has_genesis_prev_hash() {
        let dir = tempfile::TempDir::new().unwrap();
        let handle = spawn_audit_writer(AuditWriterConfig::with_dir(dir.path())).await.unwrap();

        handle.append(sample_record(0)).await.unwrap();
        handle.shutdown().await;

        let content = std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap();
        let record: AuditRecord = serde_json::from_str(content.trim()).unwrap();
        assert_eq!(
            record.prev_hash,
            genesis_hash(),
            "first record prev_hash must equal genesis_hash()"
        );
    }

    // -----------------------------------------------------------------------
    // 12. Writer: hash chain is valid for a small sequence
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn writer_hash_chain_valid_small() {
        let dir = tempfile::TempDir::new().unwrap();
        let handle = spawn_audit_writer(AuditWriterConfig::with_dir(dir.path())).await.unwrap();

        for i in 0..20u64 {
            handle.append(sample_record(i)).await.unwrap();
        }
        handle.shutdown().await;

        let content = std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 20);

        verify_chain(&lines).expect("hash chain must be intact");
    }

    // -----------------------------------------------------------------------
    // 13. verify_chain detects tampering
    // -----------------------------------------------------------------------

    #[test]
    fn verify_chain_detects_tampered_record() {
        let genesis = genesis_hash();

        // Build a mini 2-record chain by hand
        let mut r1 = sample_record(0);
        r1.prev_hash = genesis;
        let j1 = serde_json::to_string(&r1).unwrap();

        let mut r2 = sample_record(1);
        r2.prev_hash = hash_record(&j1);
        let j2 = serde_json::to_string(&r2).unwrap();

        // Valid chain
        let lines = vec![j1.as_str(), j2.as_str()];
        assert!(verify_chain(&lines).is_ok());

        // Tamper with r1 (change latency)
        let mut r1_tampered: AuditRecord = serde_json::from_str(&j1).unwrap();
        r1_tampered.latency_us = 99999;
        let j1_tampered = serde_json::to_string(&r1_tampered).unwrap();

        let tampered_lines = vec![j1_tampered.as_str(), j2.as_str()];
        assert!(verify_chain(&tampered_lines).is_err());
    }

    // -----------------------------------------------------------------------
    // 14. log rotation renames active file
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn log_rotation_renames_active_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let config = AuditWriterConfig {
            dir: dir.path().to_path_buf(),
            // Rotate after 1 byte
            max_size_bytes: 1,
            retention_days: 30,
            channel_capacity: 64,
        };
        let handle = spawn_audit_writer(config).await.unwrap();

        // Write one record — the 1-second tick will detect size > 1 byte
        handle.append(sample_record(0)).await.unwrap();
        // Wait a bit more than 1 second for the rotation timer to fire
        tokio::time::sleep(Duration::from_millis(1_200)).await;
        // Write one more record to the new active file
        handle.append(sample_record(1)).await.unwrap();
        handle.shutdown().await;

        // There should be at least one rotated file
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                let name = e.file_name();
                let n = name.to_string_lossy();
                n.starts_with("audit.") && n.ends_with(".jsonl") && n != "audit.jsonl"
            })
            .collect();
        assert!(!entries.is_empty(), "at least one rotated file should exist");
    }

    // -----------------------------------------------------------------------
    // 15. High-throughput: 10,000 records — no loss, valid chain
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn ten_thousand_records_no_loss_valid_chain() {
        const N: u64 = 10_000;

        let dir = tempfile::TempDir::new().unwrap();
        let config = AuditWriterConfig {
            dir: dir.path().to_path_buf(),
            max_size_bytes: DEFAULT_MAX_SIZE_BYTES,
            retention_days: 30,
            channel_capacity: N as usize * 2,
        };
        let handle = spawn_audit_writer(config).await.unwrap();

        for i in 0..N {
            handle.append(sample_record(i)).await.unwrap();
        }
        handle.shutdown().await;

        let content = std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap();
        let lines: Vec<&str> = content.lines().collect();

        // No records lost
        assert_eq!(
            lines.len(),
            N as usize,
            "expected {N} records, found {}",
            lines.len()
        );

        // All records deserialise
        for (i, line) in lines.iter().enumerate() {
            serde_json::from_str::<AuditRecord>(line)
                .unwrap_or_else(|e| panic!("record {i} failed to parse: {e}\nline: {line}"));
        }

        // Hash chain is intact
        verify_chain(&lines)
            .unwrap_or_else(|broken_at| panic!("hash chain broken at record {broken_at}"));
    }
}
