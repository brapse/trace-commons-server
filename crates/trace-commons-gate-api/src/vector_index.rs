// Copyright (C) 2026 K&Z Partners LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// A nearest-neighbor result. `entry_id` is the `(tenant, entry_id)` UUID;
/// `similarity` is cosine similarity in `[-1.0, 1.0]`.
#[derive(Debug, Clone, PartialEq)]
pub struct NearestNeighbor {
    pub entry_id: Uuid,
    pub similarity: f32,
}

/// Instrumentation-only description of one tenant's index shard at the moment
/// a novelty score was computed against it (#199).
///
/// Novelty is `1 - max cosine similarity` against whatever the shard held at
/// scoring time, so the score is not reproducible — and not comparable across
/// time — without this. Recomputing it later scores against a fuller shard and
/// produces a number production never used, which is why it is recorded when
/// the decision is made rather than derived afterwards.
///
/// Hash-only/label-only safe by construction: an opaque generation UUID and a
/// count. No entry ids, no embeddings, no tenant identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VectorIndexSnapshot {
    /// Identifies the SHARD, not the write: two decisions carrying the same id
    /// were scored against the same corpus lineage — the same tenant's index
    /// under the same index root — and `cardinality` distinguishes states
    /// within it. A different id is a different corpus, which is the
    /// discontinuity an analyst must not average across. It is deliberately
    /// not a content hash: computing one would mean reading every vector on
    /// every decision.
    pub snapshot_id: Uuid,
    /// How many entries the shard held. Monotone within a generation (novelty
    /// drifts downward as it fills), so this is the covariate a chronological
    /// estimate conditions on. `0` is a real observation — the first trace of
    /// a tenant scores against an empty shard.
    pub cardinality: u64,
}

/// Pluggable vector index used by the gate orchestrator.
pub trait VectorIndex: Send + Sync {
    /// Describe the shard for `tenant_storage_ref` as it stands right now,
    /// for the instrumentation on the gate decision row.
    ///
    /// `None` means "this index cannot describe its own state", which is
    /// recorded as not-instrumented rather than as a zero-cardinality shard.
    /// The default is `None` so a substituted backend that has no shard
    /// generation to report says so instead of fabricating one; every index
    /// that gates real traffic should override it.
    ///
    /// Implementations MUST NOT mutate index contents here, and MUST be cheap:
    /// the orchestrator calls this on the scoring path of every trace.
    fn snapshot(&self, tenant_storage_ref: &str) -> Option<VectorIndexSnapshot> {
        let _ = tenant_storage_ref;
        None
    }

    /// Insert (or upsert) a vector for `entry_id` under `tenant_storage_ref`.
    fn insert(
        &self,
        entry_id: Uuid,
        tenant_storage_ref: &str,
        embedding: &[f32],
    ) -> anyhow::Result<()>;

    /// Return up to `k` nearest neighbors for `embedding` within
    /// `tenant_storage_ref`. Results are sorted by descending similarity.
    fn nearest(
        &self,
        tenant_storage_ref: &str,
        embedding: &[f32],
        k: usize,
    ) -> anyhow::Result<Vec<NearestNeighbor>>;

    /// Remove an entry from the index. Returns `Ok(true)` if removed,
    /// `Ok(false)` if no such entry existed.
    ///
    /// `tenant_storage_ref` is required so per-tenant implementations (e.g.
    /// `UsearchVectorIndex`, which keeps one file per tenant) can route the
    /// deletion to the right shard without doing a global scan.
    fn delete(&self, tenant_storage_ref: &str, entry_id: Uuid) -> anyhow::Result<bool>;

    /// Persist every pending write to whatever durable medium the
    /// implementation owns.
    ///
    /// Purely in-memory implementations (the mocks, the reference index) have
    /// nothing to persist and keep the no-op default. Implementations that own
    /// a durable corpus (`UsearchVectorIndex` and its per-tenant files) MUST
    /// override this: the corpus is what "duplicate" means, so a process that
    /// exits without flushing silently redefines the novelty gate.
    fn flush(&self) -> anyhow::Result<()> {
        Ok(())
    }
}

/// Deterministic identity for one index entry written during Settle.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct IndexEntryKey {
    pub tenant_id: String,
    pub index_id: String,
    pub revision_id: Uuid,
    pub projection_id: String,
    pub model_id: String,
    pub chunk: u32,
}

impl IndexEntryKey {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = b"trace-commons-index-entry-key\0".to_vec();
        encode_len_prefixed(&mut bytes, self.tenant_id.as_bytes());
        encode_len_prefixed(&mut bytes, self.index_id.as_bytes());
        bytes.extend_from_slice(self.revision_id.as_bytes());
        encode_len_prefixed(&mut bytes, self.projection_id.as_bytes());
        encode_len_prefixed(&mut bytes, self.model_id.as_bytes());
        bytes.extend_from_slice(&self.chunk.to_be_bytes());
        bytes
    }

    pub fn entry_id(&self) -> Uuid {
        Uuid::new_v5(&Uuid::NAMESPACE_URL, &self.canonical_bytes())
    }

    pub fn content_digest(embedding: &[f32], content_hash: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(content_hash.as_bytes());
        hasher.update(b"\0");
        for value in embedding {
            hasher.update(value.to_le_bytes());
        }
        format!("sha256:{:x}", hasher.finalize())
    }
}

fn encode_len_prefixed(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u32).to_be_bytes());
    output.extend_from_slice(value);
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexSnapshot {
    pub snapshot_id: String,
    pub snapshot_hash: String,
    pub cardinality: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexUpsertResult {
    Inserted,
    Unchanged,
}

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum IndexWriteError {
    #[error("index key already exists with different content")]
    ContentConflict,
    #[error("index write did not complete")]
    Uncertain,
    #[error("index write failed")]
    Failed,
}

/// Read-only index capability used while Score computes evidence.
pub trait VectorIndexReader: Send + Sync {
    fn snapshot(&self, tenant_id: &str, index_id: &str) -> anyhow::Result<IndexSnapshot>;

    fn nearest(
        &self,
        tenant_id: &str,
        index_id: &str,
        embedding: &[f32],
        k: usize,
        exclude_revision: Option<Uuid>,
    ) -> anyhow::Result<Vec<NearestNeighbor>>;
}

/// Write-only index capability used after Settle has sealed a command.
pub trait VectorIndexWriter: Send + Sync {
    fn upsert(
        &self,
        key: &IndexEntryKey,
        embedding: &[f32],
        content_hash: &str,
    ) -> Result<IndexUpsertResult, IndexWriteError>;
}

#[cfg(test)]
mod pipeline_tests {
    use super::*;

    fn key() -> IndexEntryKey {
        IndexEntryKey {
            tenant_id: "tenant-a".to_string(),
            index_id: "index-v1".to_string(),
            revision_id: Uuid::nil(),
            projection_id: "projection-v1".to_string(),
            model_id: "model-v1".to_string(),
            chunk: 0,
        }
    }

    #[test]
    fn each_index_key_field_changes_entry_identity() {
        let base = key().entry_id();
        let changes = [
            {
                let mut value = key();
                value.tenant_id = "tenant-b".to_string();
                value
            },
            {
                let mut value = key();
                value.index_id = "index-v2".to_string();
                value
            },
            {
                let mut value = key();
                value.revision_id = Uuid::from_u128(1);
                value
            },
            {
                let mut value = key();
                value.projection_id = "projection-v2".to_string();
                value
            },
            {
                let mut value = key();
                value.model_id = "model-v2".to_string();
                value
            },
            {
                let mut value = key();
                value.chunk = 1;
                value
            },
        ];
        assert!(changes.iter().all(|changed| changed.entry_id() != base));
    }
}
