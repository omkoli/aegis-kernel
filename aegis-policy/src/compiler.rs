//! Policy compiler: YAML → validate → TokenRequest objects.

use std::collections::HashSet;
use std::path::Path;
use std::time::Duration;

use aegis_core::{Action, Constraints, ParamConstraint, Resource, TokenRequest};

use crate::error::PolicyError;
use crate::schema::{ExplicitConstraint, PolicyConstraintValue, PolicyDocument, PolicyRule};

/// Compiles policy YAML documents into validated `TokenRequest` objects.
#[derive(Debug, Default)]
pub struct PolicyCompiler;

impl PolicyCompiler {
    pub fn new() -> Self {
        Self
    }

    /// Loads and compiles a YAML file into a list of `TokenRequest`s.
    pub fn compile_file(&self, path: &Path) -> Result<Vec<TokenRequest>, PolicyError> {
        let content = std::fs::read_to_string(path)?;
        self.compile_str(&content)
    }

    /// Compiles a YAML string into a list of `TokenRequest`s.
    pub fn compile_str(&self, yaml: &str) -> Result<Vec<TokenRequest>, PolicyError> {
        let doc: PolicyDocument = serde_yaml::from_str(yaml)?;
        self.compile_document(&doc)
    }

    /// Compiles a parsed `PolicyDocument` into `TokenRequest`s.
    pub fn compile_document(&self, doc: &PolicyDocument) -> Result<Vec<TokenRequest>, PolicyError> {
        // Check for duplicate names
        let mut seen = HashSet::new();
        for rule in &doc.policies {
            if !seen.insert(&rule.name) {
                return Err(PolicyError::DuplicateName(rule.name.clone()));
            }
        }

        doc.policies
            .iter()
            .map(|rule| self.compile_rule(rule))
            .collect()
    }

    /// Compiles a single policy rule into a `TokenRequest`.
    pub fn compile_rule(&self, rule: &PolicyRule) -> Result<TokenRequest, PolicyError> {
        // Validate name
        if rule.name.is_empty() {
            return Err(PolicyError::Validation {
                name: "(unnamed)".into(),
                reason: "policy name must not be empty".into(),
            });
        }

        // Validate agent
        if rule.agent.is_empty() {
            return Err(PolicyError::Validation {
                name: rule.name.clone(),
                reason: "agent must not be empty".into(),
            });
        }

        // Parse resource
        let resource_path = rule.resource.to_path();
        let resource = Resource::new(&resource_path).map_err(|e| PolicyError::Validation {
            name: rule.name.clone(),
            reason: format!("invalid resource: {e}"),
        })?;

        // Parse actions
        if rule.actions.is_empty() {
            return Err(PolicyError::Validation {
                name: rule.name.clone(),
                reason: "actions must not be empty".into(),
            });
        }
        let actions: Vec<Action> = rule.actions.iter().map(|a| parse_action(a)).collect();

        // Parse constraints
        let mut constraints = Constraints::new();
        for (key, value) in &rule.constraints {
            let pc = compile_constraint(value).map_err(|reason| PolicyError::Validation {
                name: rule.name.clone(),
                reason: format!("constraint '{key}': {reason}"),
            })?;
            constraints = constraints.add(key.clone(), pc)?;
        }

        // Parse TTL
        let ttl = rule
            .ttl
            .as_ref()
            .map(|s| parse_duration(s))
            .transpose()
            .map_err(|reason| PolicyError::Validation {
                name: rule.name.clone(),
                reason: format!("invalid ttl: {reason}"),
            })?;

        // Validate max_uses
        if rule.max_uses == Some(0) {
            return Err(PolicyError::Validation {
                name: rule.name.clone(),
                reason: "max_uses must be at least 1".into(),
            });
        }

        Ok(TokenRequest {
            subject: rule.agent.clone(),
            resource,
            actions,
            constraints,
            ttl,
            delegatable: rule.delegatable,
            max_uses: rule.max_uses,
        })
    }
}

fn parse_action(s: &str) -> Action {
    match s.to_lowercase().as_str() {
        "read" => Action::Read,
        "write" => Action::Write,
        "execute" => Action::Execute,
        "delete" => Action::Delete,
        other => Action::Custom(other.into()),
    }
}

fn compile_constraint(value: &PolicyConstraintValue) -> Result<ParamConstraint, String> {
    match value {
        PolicyConstraintValue::Number(n) => Ok(ParamConstraint::Range { min: 0.0, max: *n }),
        PolicyConstraintValue::String(s) => Ok(ParamConstraint::Exact(s.clone())),
        PolicyConstraintValue::Bool(b) => Ok(ParamConstraint::Exact(b.to_string())),
        PolicyConstraintValue::Explicit(explicit) => match explicit {
            ExplicitConstraint::Exact { value } => Ok(ParamConstraint::Exact(value.clone())),
            ExplicitConstraint::OneOf { values } => Ok(ParamConstraint::OneOf(values.clone())),
            ExplicitConstraint::Regex { pattern } => Ok(ParamConstraint::Regex(pattern.clone())),
            ExplicitConstraint::Range { min, max } => {
                if min > max {
                    return Err(format!("invalid range: min ({min}) > max ({max})"));
                }
                Ok(ParamConstraint::Range {
                    min: *min,
                    max: *max,
                })
            }
        },
    }
}

/// Parses a human-readable duration string like "60s", "5m", "1h", "1d", "30".
fn parse_duration(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty duration string".into());
    }

    // Try pure numeric (seconds)
    if let Ok(secs) = s.parse::<u64>() {
        return Ok(Duration::from_secs(secs));
    }

    let (num_str, suffix) = s.split_at(s.len() - 1);
    let num: u64 = num_str
        .trim()
        .parse()
        .map_err(|_| format!("invalid number in duration: '{num_str}'"))?;

    match suffix {
        "s" => Ok(Duration::from_secs(num)),
        "m" => Ok(Duration::from_secs(num * 60)),
        "h" => Ok(Duration::from_secs(num * 3600)),
        "d" => Ok(Duration::from_secs(num * 86400)),
        _ => Err(format!("unknown duration suffix: '{suffix}' (use s/m/h/d)")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_duration_variants() {
        assert_eq!(parse_duration("60s").unwrap(), Duration::from_secs(60));
        assert_eq!(parse_duration("5m").unwrap(), Duration::from_secs(300));
        assert_eq!(parse_duration("1h").unwrap(), Duration::from_secs(3600));
        assert_eq!(parse_duration("1d").unwrap(), Duration::from_secs(86400));
        assert_eq!(parse_duration("120").unwrap(), Duration::from_secs(120));
        assert!(parse_duration("").is_err());
        assert!(parse_duration("abc").is_err());
        assert!(parse_duration("5x").is_err());
    }
}
