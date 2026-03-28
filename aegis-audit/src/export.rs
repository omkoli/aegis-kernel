//! JSON Lines export for SIEM integration.

use std::io::Write;

use aegis_core::AuditEntry;

use crate::store::AuditStore;

/// Exports audit entries as JSON Lines (one JSON object per line).
pub struct JsonLinesExporter;

impl JsonLinesExporter {
    /// Exports all entries from the store to a writer in JSON Lines format.
    pub fn export_all<W: Write>(store: &dyn AuditStore, writer: &mut W) -> std::io::Result<usize> {
        let entries = store.all();
        Self::export_entries(&entries, writer)
    }

    /// Exports a slice of entries to a writer in JSON Lines format.
    pub fn export_entries<W: Write>(
        entries: &[AuditEntry],
        writer: &mut W,
    ) -> std::io::Result<usize> {
        let mut count = 0;
        for entry in entries {
            let line = serde_json::to_string(entry)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
            writer.write_all(line.as_bytes())?;
            writer.write_all(b"\n")?;
            count += 1;
        }
        writer.flush()?;
        Ok(count)
    }

    /// Exports all entries to a String in JSON Lines format.
    pub fn export_to_string(store: &dyn AuditStore) -> std::io::Result<String> {
        let mut buf = Vec::new();
        Self::export_all(store, &mut buf)?;
        String::from_utf8(buf)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
    }

    /// Exports all entries to a file.
    pub fn export_to_file(
        store: &dyn AuditStore,
        path: impl AsRef<std::path::Path>,
    ) -> std::io::Result<usize> {
        let mut file = std::fs::File::create(path)?;
        Self::export_all(store, &mut file)
    }
}
