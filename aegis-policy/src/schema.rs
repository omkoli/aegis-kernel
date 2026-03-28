//! YAML policy DSL schema.
//!
//! Example:
//! ```yaml
//! policies:
//!   - name: finance-agent-db-read
//!     agent: finance-agent
//!     resource: "db://finance/transactions"
//!     actions: [read]
//!     constraints:
//!       max_amount: 1000
//!     ttl: 60s
//!     delegatable: false
//!     max_uses: 100
//! ```

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Top-level document loaded from a YAML policy file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDocument {
    pub policies: Vec<PolicyRule>,
}

/// A single policy rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Unique policy name used for identification and dedup.
    pub name: String,
    /// The agent (subject) this policy applies to.
    pub agent: String,
    /// Resource specification — either a plain string or structured.
    pub resource: PolicyResource,
    /// Permitted actions (e.g. ["read", "write"]).
    pub actions: Vec<String>,
    /// Parameter constraints (optional).
    #[serde(default)]
    pub constraints: HashMap<String, PolicyConstraintValue>,
    /// Time-to-live as a human-readable string (e.g. "60s", "5m", "1h", "1d").
    #[serde(default)]
    pub ttl: Option<String>,
    /// Whether the resulting token can be delegated.
    #[serde(default)]
    pub delegatable: bool,
    /// Maximum number of times the token can be used.
    #[serde(default)]
    pub max_uses: Option<u64>,
}

/// Resource can be a plain string or a structured object with tool/provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PolicyResource {
    /// Simple path string like "db://finance/transactions".
    Simple(String),
    /// Structured resource with tool and provider fields.
    Structured {
        tool: String,
        #[serde(default)]
        provider: Option<String>,
    },
}

impl PolicyResource {
    /// Converts to a resource path string.
    pub fn to_path(&self) -> String {
        match self {
            PolicyResource::Simple(s) => s.clone(),
            PolicyResource::Structured { tool, provider } => match provider {
                Some(p) => format!("{p}://{tool}"),
                None => tool.clone(),
            },
        }
    }
}

/// Constraint values in the YAML DSL.
///
/// Supports several forms:
/// - Scalar number: interpreted as Range { min: 0, max: value }
/// - Scalar string: interpreted as Exact match
/// - Object with `type` key for explicit constraint types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PolicyConstraintValue {
    /// Numeric value → Range(0, value)
    Number(f64),
    /// String value → Exact match
    String(String),
    /// Boolean value → Exact("true"/"false")
    Bool(bool),
    /// Explicit constraint specification
    Explicit(ExplicitConstraint),
}

/// Explicitly typed constraint in YAML.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ExplicitConstraint {
    Exact { value: String },
    OneOf { values: Vec<String> },
    Regex { pattern: String },
    Range { min: f64, max: f64 },
}
