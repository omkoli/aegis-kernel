use serde::Serialize;

/// Produces a canonical JSON representation of a serializable value.
///
/// Keys are sorted lexicographically at every nesting level, ensuring the same
/// logical value always produces identical bytes regardless of HashMap iteration
/// order or insertion sequence.
pub fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, crate::AegisError> {
    let json_value =
        serde_json::to_value(value).map_err(|e| crate::AegisError::Serialization(e.to_string()))?;
    let sorted = sort_value(&json_value);
    serde_json::to_vec(&sorted).map_err(|e| crate::AegisError::Serialization(e.to_string()))
}

/// Recursively sorts all object keys in a JSON value.
fn sort_value(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut sorted: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for key in keys {
                sorted.insert(key.clone(), sort_value(&map[key]));
            }
            serde_json::Value::Object(sorted)
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(sort_value).collect())
        }
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn canonical_json_sorts_keys() {
        let mut map = HashMap::new();
        map.insert("z", 1);
        map.insert("a", 2);
        map.insert("m", 3);
        let bytes = canonical_json(&map).unwrap();
        let s = String::from_utf8(bytes).unwrap();
        assert_eq!(s, r#"{"a":2,"m":3,"z":1}"#);
    }

    #[test]
    fn canonical_json_nested_objects_sorted() {
        let mut inner = HashMap::new();
        inner.insert("beta", 1);
        inner.insert("alpha", 2);
        let mut outer = HashMap::new();
        outer.insert("z_inner", serde_json::to_value(&inner).unwrap());
        outer.insert("a_top", serde_json::Value::from(99));
        let bytes = canonical_json(&outer).unwrap();
        let s = String::from_utf8(bytes).unwrap();
        assert_eq!(s, r#"{"a_top":99,"z_inner":{"alpha":2,"beta":1}}"#);
    }

    #[test]
    fn canonical_json_deterministic() {
        let mut map = HashMap::new();
        map.insert("c", 3);
        map.insert("a", 1);
        map.insert("b", 2);
        let b1 = canonical_json(&map).unwrap();
        let b2 = canonical_json(&map).unwrap();
        assert_eq!(b1, b2);
    }
}
