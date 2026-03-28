//! Append-only ring buffer audit store.

use parking_lot::RwLock;

use aegis_core::AuditEntry;

use crate::query::{AuditQuery, Page, SortOrder};

/// Default capacity: 1 million entries.
pub const DEFAULT_CAPACITY: usize = 1_000_000;

/// Trait abstracting audit log storage.
pub trait AuditStore: Send + Sync {
    /// Appends an entry. If the buffer is full, the oldest entry is overwritten.
    fn append(&self, entry: AuditEntry);

    /// Queries entries matching the filter, with pagination.
    fn query(&self, query: &AuditQuery) -> Page;

    /// Returns the total number of stored entries (may be less than total appended
    /// if the ring buffer has wrapped).
    fn len(&self) -> usize;

    /// Whether the store is empty.
    fn is_empty(&self) -> bool;

    /// Returns all entries in insertion order (oldest first). Primarily for export.
    fn all(&self) -> Vec<AuditEntry>;

    /// Clears all entries.
    fn clear(&self);
}

/// Thread-safe audit log backed by a fixed-capacity ring buffer.
///
/// Uses a `RwLock` around the inner buffer. Writes take an exclusive lock
/// only briefly (one slot write + index bump). Reads snapshot the relevant
/// slice under a shared lock.
pub struct InMemoryAuditStore {
    inner: RwLock<RingBuffer>,
}

impl InMemoryAuditStore {
    /// Creates a store with the default capacity (1M entries).
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }

    /// Creates a store with a custom capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: RwLock::new(RingBuffer::new(capacity)),
        }
    }
}

impl Default for InMemoryAuditStore {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditStore for InMemoryAuditStore {
    fn append(&self, entry: AuditEntry) {
        self.inner.write().push(entry);
    }

    fn query(&self, query: &AuditQuery) -> Page {
        let inner = self.inner.read();
        let entries = inner.as_slice();

        // Filter
        let filtered: Vec<&AuditEntry> =
            entries.iter().filter(|e| matches_query(e, query)).collect();

        let total = filtered.len();

        // Sort
        let mut sorted: Vec<AuditEntry> = filtered.into_iter().cloned().collect();
        match query.sort {
            SortOrder::NewestFirst => sorted.sort_by(|a, b| b.timestamp.cmp(&a.timestamp)),
            SortOrder::OldestFirst => sorted.sort_by(|a, b| a.timestamp.cmp(&b.timestamp)),
        }

        // Paginate
        let offset = query.offset.unwrap_or(0);
        let limit = query.limit.unwrap_or(100);
        let page_entries: Vec<AuditEntry> = sorted.into_iter().skip(offset).take(limit).collect();
        let has_more = offset + limit < total;

        Page {
            entries: page_entries,
            total,
            offset,
            limit,
            has_more,
        }
    }

    fn len(&self) -> usize {
        self.inner.read().len()
    }

    fn is_empty(&self) -> bool {
        self.inner.read().is_empty()
    }

    fn all(&self) -> Vec<AuditEntry> {
        self.inner.read().as_slice().to_vec()
    }

    fn clear(&self) {
        self.inner.write().clear();
    }
}

/// Convenience wrapper that owns an `Arc<dyn AuditStore>`.
#[derive(Clone)]
pub struct AuditLog {
    store: std::sync::Arc<dyn AuditStore>,
}

impl AuditLog {
    pub fn new(store: std::sync::Arc<dyn AuditStore>) -> Self {
        Self { store }
    }

    pub fn append(&self, entry: AuditEntry) {
        self.store.append(entry);
    }

    pub fn query(&self, query: &AuditQuery) -> Page {
        self.store.query(query)
    }

    pub fn len(&self) -> usize {
        self.store.len()
    }

    pub fn is_empty(&self) -> bool {
        self.store.is_empty()
    }

    pub fn all(&self) -> Vec<AuditEntry> {
        self.store.all()
    }

    pub fn clear(&self) {
        self.store.clear();
    }

    pub fn store(&self) -> &dyn AuditStore {
        &*self.store
    }
}

// ── Ring buffer implementation ─────────────────────────────────────────

struct RingBuffer {
    buf: Vec<Option<AuditEntry>>,
    capacity: usize,
    /// Next write position.
    head: usize,
    /// Number of entries currently stored.
    count: usize,
}

impl RingBuffer {
    fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            buf: (0..capacity).map(|_| None).collect(),
            capacity,
            head: 0,
            count: 0,
        }
    }

    fn push(&mut self, entry: AuditEntry) {
        self.buf[self.head] = Some(entry);
        self.head = (self.head + 1) % self.capacity;
        if self.count < self.capacity {
            self.count += 1;
        }
    }

    fn len(&self) -> usize {
        self.count
    }

    fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns entries in insertion order (oldest first).
    fn as_slice(&self) -> Vec<AuditEntry> {
        if self.count == 0 {
            return Vec::new();
        }
        let start = if self.count < self.capacity {
            0
        } else {
            self.head
        };
        let mut result = Vec::with_capacity(self.count);
        for i in 0..self.count {
            let idx = (start + i) % self.capacity;
            if let Some(entry) = &self.buf[idx] {
                result.push(entry.clone());
            }
        }
        result
    }

    fn clear(&mut self) {
        for slot in &mut self.buf {
            *slot = None;
        }
        self.head = 0;
        self.count = 0;
    }
}

// ── Filter matching ────────────────────────────────────────────────────

fn matches_query(entry: &AuditEntry, query: &AuditQuery) -> bool {
    if let Some(ref start) = query.time_start {
        if entry.timestamp < *start {
            return false;
        }
    }
    if let Some(ref end) = query.time_end {
        if entry.timestamp > *end {
            return false;
        }
    }
    if let Some(ref agent) = query.agent_id {
        if entry.agent_id != *agent {
            return false;
        }
    }
    if let Some(ref tool) = query.tool_name {
        if entry.tool_name != *tool {
            return false;
        }
    }
    if let Some(ref decision) = query.decision {
        if entry.decision != *decision {
            return false;
        }
    }
    if let Some(ref token_id) = query.token_id {
        if entry.token_id != *token_id {
            return false;
        }
    }
    if let Some(ref resource) = query.resource_path {
        if entry.resource_path != *resource {
            return false;
        }
    }
    true
}
