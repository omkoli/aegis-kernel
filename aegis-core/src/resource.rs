use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A named resource that capabilities can be granted over.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Resource {
    /// Hierarchical resource path, e.g. "file:///etc/config" or "net://api.example.com/v1".
    path: String,
}

impl Resource {
    /// Creates a new `Resource` from a non-empty path.
    ///
    /// # Errors
    /// Returns `AegisError::EmptyResourcePath` if `path` is empty.
    pub fn new(path: impl Into<String>) -> Result<Self, crate::AegisError> {
        let path = path.into();
        if path.is_empty() {
            return Err(crate::AegisError::EmptyResourcePath);
        }
        Ok(Self { path })
    }

    pub fn path(&self) -> &str {
        &self.path
    }
}

/// An action that can be performed on a resource.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Action {
    Read,
    Write,
    Execute,
    Delete,
    /// Application-defined custom action.
    Custom(String),
}

impl Action {
    /// Creates a custom action from a non-empty name.
    ///
    /// # Errors
    /// Returns `AegisError::EmptyActionName` if `name` is empty.
    pub fn custom(name: impl Into<String>) -> Result<Self, crate::AegisError> {
        let name = name.into();
        if name.is_empty() {
            return Err(crate::AegisError::EmptyActionName);
        }
        Ok(Self::Custom(name))
    }
}

/// A constraint on a single parameter value.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ParamConstraint {
    /// Exact string match.
    Exact(String),
    /// Value must be one of the listed options.
    OneOf(Vec<String>),
    /// Value must match the given regex pattern.
    Regex(String),
    /// Numeric range (inclusive on both ends).
    Range { min: f64, max: f64 },
}

impl ParamConstraint {
    /// Creates a `Range` constraint, ensuring `min <= max`.
    ///
    /// # Errors
    /// Returns `AegisError::InvalidRange` if `min > max`.
    pub fn range(min: f64, max: f64) -> Result<Self, crate::AegisError> {
        if min > max {
            return Err(crate::AegisError::InvalidRange { min, max });
        }
        Ok(Self::Range { min, max })
    }
}

/// A set of named parameter constraints that further limit a capability.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct Constraints {
    params: HashMap<String, ParamConstraint>,
}

impl Constraints {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a constraint for the given parameter name.
    ///
    /// # Errors
    /// Returns `AegisError::EmptyConstraintKey` if `key` is empty.
    pub fn add(
        mut self,
        key: impl Into<String>,
        constraint: ParamConstraint,
    ) -> Result<Self, crate::AegisError> {
        let key = key.into();
        if key.is_empty() {
            return Err(crate::AegisError::EmptyConstraintKey);
        }
        self.params.insert(key, constraint);
        Ok(self)
    }

    pub fn get(&self, key: &str) -> Option<&ParamConstraint> {
        self.params.get(key)
    }

    pub fn is_empty(&self) -> bool {
        self.params.is_empty()
    }

    pub fn len(&self) -> usize {
        self.params.len()
    }
}
