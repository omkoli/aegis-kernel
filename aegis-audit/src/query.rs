//! Query types for the audit log.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use aegis_core::{AuditEntry, Decision};

/// Filter and pagination parameters for audit queries.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditQuery {
    /// Filter: entries at or after this time.
    #[serde(default)]
    pub time_start: Option<DateTime<Utc>>,
    /// Filter: entries at or before this time.
    #[serde(default)]
    pub time_end: Option<DateTime<Utc>>,
    /// Filter: match agent ID exactly.
    #[serde(default)]
    pub agent_id: Option<String>,
    /// Filter: match tool name exactly.
    #[serde(default)]
    pub tool_name: Option<String>,
    /// Filter: match decision (Allow/Deny).
    #[serde(default)]
    pub decision: Option<Decision>,
    /// Filter: match token ID.
    #[serde(default)]
    pub token_id: Option<Uuid>,
    /// Filter: match resource path.
    #[serde(default)]
    pub resource_path: Option<String>,
    /// Sort order (default: newest first).
    #[serde(default)]
    pub sort: SortOrder,
    /// Pagination offset (default: 0).
    #[serde(default)]
    pub offset: Option<usize>,
    /// Page size (default: 100).
    #[serde(default)]
    pub limit: Option<usize>,
}

impl AuditQuery {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn agent(mut self, agent_id: impl Into<String>) -> Self {
        self.agent_id = Some(agent_id.into());
        self
    }

    pub fn tool(mut self, tool_name: impl Into<String>) -> Self {
        self.tool_name = Some(tool_name.into());
        self
    }

    pub fn decision(mut self, decision: Decision) -> Self {
        self.decision = Some(decision);
        self
    }

    pub fn token(mut self, token_id: Uuid) -> Self {
        self.token_id = Some(token_id);
        self
    }

    pub fn resource(mut self, path: impl Into<String>) -> Self {
        self.resource_path = Some(path.into());
        self
    }

    pub fn time_range(mut self, start: DateTime<Utc>, end: DateTime<Utc>) -> Self {
        self.time_start = Some(start);
        self.time_end = Some(end);
        self
    }

    pub fn since(mut self, start: DateTime<Utc>) -> Self {
        self.time_start = Some(start);
        self
    }

    pub fn until(mut self, end: DateTime<Utc>) -> Self {
        self.time_end = Some(end);
        self
    }

    pub fn sort(mut self, order: SortOrder) -> Self {
        self.sort = order;
        self
    }

    pub fn page(mut self, offset: usize, limit: usize) -> Self {
        self.offset = Some(offset);
        self.limit = Some(limit);
        self
    }
}

/// Sort order for query results.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub enum SortOrder {
    #[default]
    NewestFirst,
    OldestFirst,
}

/// A page of audit query results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Page {
    pub entries: Vec<AuditEntry>,
    pub total: usize,
    pub offset: usize,
    pub limit: usize,
    pub has_more: bool,
}
