use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::resource::{Action, Constraints, Resource};

/// A request to issue a new capability token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenRequest {
    /// The principal (user, service, etc.) the token is issued to.
    pub subject: String,
    /// The resource the token grants access to.
    pub resource: Resource,
    /// Actions the token permits.
    pub actions: Vec<Action>,
    /// Optional parameter constraints.
    #[serde(default)]
    pub constraints: Constraints,
    /// Time-to-live. `None` means no expiry.
    #[serde(default, with = "optional_duration_secs")]
    pub ttl: Option<Duration>,
    /// Whether the token can be delegated to others.
    #[serde(default)]
    pub delegatable: bool,
    /// Maximum number of times the token can be used.
    #[serde(default)]
    pub max_uses: Option<u64>,
}

/// Serde helper for `Option<Duration>` as seconds.
mod optional_duration_secs {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::Duration;

    pub fn serialize<S: Serializer>(val: &Option<Duration>, s: S) -> Result<S::Ok, S::Error> {
        val.map(|d| d.as_secs()).serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Duration>, D::Error> {
        let opt: Option<u64> = Option::deserialize(d)?;
        Ok(opt.map(Duration::from_secs))
    }
}
