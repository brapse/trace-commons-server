// Copyright (C) 2026 K&Z Partners LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Internal credit settlement helpers for the versioned pipeline.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};
use trace_commons_gate_api::pipeline::{AtomicUnits, InstrumentId, Microcredits};
use uuid::Uuid;

use crate::near_credit::{NearCreditReceipt, NearCreditReceiptCall};
use crate::trace_corpus_storage::TraceCreditSettlementNearStatus;

pub const PIPELINE_SETTLEMENT_POLICY_VERSION: &str = "pipeline-internal-v1";
pub const PIPELINE_CREDIT_REASON: &str = "pipeline_score";
pub const PIPELINE_TEST_CREDIT_CAP_MICROCREDITS: u64 = 10_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettlementRequest {
    pub tenant_id: String,
    pub run_id: Uuid,
    pub instrument_id: InstrumentId,
    pub atomic_units: AtomicUnits,
    pub operation_ref_hash: String,
    pub expected_result_ref_hash: String,
}

pub trait SettlementAdapter: Send + Sync {
    fn instrument_id(&self) -> &InstrumentId;
    fn adapter_identity(&self) -> &str;
    fn production_qualified(&self) -> bool {
        false
    }
    fn payout_rail(&self) -> &str;
    fn settle(&self, request: &SettlementRequest) -> anyhow::Result<String>;
}

#[derive(Default)]
pub struct SettlementAdapterRegistry {
    adapters: BTreeMap<String, Arc<dyn SettlementAdapter>>,
}

impl SettlementAdapterRegistry {
    pub fn new(adapters: Vec<Arc<dyn SettlementAdapter>>) -> anyhow::Result<Self> {
        let mut registry = Self::default();
        for adapter in adapters {
            let instrument_id = adapter.instrument_id().as_str().to_string();
            anyhow::ensure!(
                !adapter.adapter_identity().trim().is_empty(),
                "settlement adapter identity is empty"
            );
            anyhow::ensure!(
                !adapter.payout_rail().trim().is_empty(),
                "settlement adapter payout rail is empty"
            );
            anyhow::ensure!(
                registry
                    .adapters
                    .insert(instrument_id.clone(), adapter)
                    .is_none(),
                "duplicate settlement adapter for {instrument_id}"
            );
        }
        Ok(registry)
    }

    pub fn get(&self, instrument_id: &InstrumentId) -> Option<&Arc<dyn SettlementAdapter>> {
        self.adapters.get(instrument_id.as_str())
    }

    pub fn payout_rails(&self) -> BTreeMap<String, String> {
        self.adapters
            .iter()
            .map(|(instrument, adapter)| (instrument.clone(), adapter.payout_rail().to_string()))
            .collect()
    }

    pub fn identities(&self) -> BTreeMap<String, String> {
        self.adapters
            .iter()
            .map(|(instrument, adapter)| {
                (instrument.clone(), adapter.adapter_identity().to_string())
            })
            .collect()
    }

    pub fn production_qualifications(&self) -> BTreeMap<String, bool> {
        self.adapters
            .iter()
            .map(|(instrument, adapter)| (instrument.clone(), adapter.production_qualified()))
            .collect()
    }
}

#[derive(Debug)]
pub struct RecordingSettlementAdapter {
    instrument_id: InstrumentId,
    identity: String,
    payout_rail: String,
    requests: Mutex<Vec<SettlementRequest>>,
    fail_next: AtomicBool,
}

impl RecordingSettlementAdapter {
    pub fn new(
        instrument_id: InstrumentId,
        identity: impl Into<String>,
        payout_rail: impl Into<String>,
    ) -> Arc<Self> {
        Arc::new(Self {
            instrument_id,
            identity: identity.into(),
            payout_rail: payout_rail.into(),
            requests: Mutex::new(Vec::new()),
            fail_next: AtomicBool::new(false),
        })
    }

    pub fn fail_next(&self) {
        self.fail_next.store(true, Ordering::SeqCst);
    }

    pub fn requests(&self) -> Vec<SettlementRequest> {
        self.requests
            .lock()
            .expect("settlement adapter mutex")
            .clone()
    }
}

impl SettlementAdapter for RecordingSettlementAdapter {
    fn instrument_id(&self) -> &InstrumentId {
        &self.instrument_id
    }

    fn adapter_identity(&self) -> &str {
        &self.identity
    }

    fn payout_rail(&self) -> &str {
        &self.payout_rail
    }

    fn settle(&self, request: &SettlementRequest) -> anyhow::Result<String> {
        anyhow::ensure!(
            request.instrument_id == self.instrument_id,
            "settlement adapter instrument mismatch"
        );
        if self.fail_next.swap(false, Ordering::SeqCst) {
            anyhow::bail!("settlement_adapter_unavailable");
        }
        let mut requests = self.requests.lock().expect("settlement adapter mutex");
        if let Some(existing) = requests
            .iter()
            .find(|existing| existing.operation_ref_hash == request.operation_ref_hash)
        {
            anyhow::ensure!(
                existing == request,
                "settlement operation reference reused with different content"
            );
            return Ok(existing.expected_result_ref_hash.clone());
        }
        requests.push(request.clone());
        Ok(request.expected_result_ref_hash.clone())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NearLogicalRequest {
    pub idempotency_key: String,
    pub method_name: String,
}

#[derive(Debug, Default)]
pub struct RecordingNearAdapter {
    requests: Mutex<Vec<NearLogicalRequest>>,
    confirmations: Mutex<BTreeMap<String, NearConfirmationEvidence>>,
    fail_next: AtomicBool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NearConfirmationEvidence {
    pub transaction_hash_hash: String,
    pub receipt_hash: String,
}

pub trait NearPayoutAdapter: Send + Sync {
    fn adapter_identity(&self) -> &str;
    fn production_qualified(&self) -> bool {
        false
    }
    fn submit(&self, call: &NearCreditReceiptCall) -> anyhow::Result<String>;
    fn confirmation(&self, idempotency_key: &str) -> Option<NearConfirmationEvidence>;
}

impl RecordingNearAdapter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn fail_next(&self) {
        self.fail_next.store(true, Ordering::SeqCst);
    }

    pub fn submit(&self, call: &NearCreditReceiptCall) -> anyhow::Result<String> {
        call.validate()?;
        if self.fail_next.swap(false, Ordering::SeqCst) {
            anyhow::bail!("near_adapter_unavailable");
        }
        let mut requests = self.requests.lock().expect("near adapter mutex");
        if let Some(existing) = requests
            .iter()
            .find(|request| request.idempotency_key == call.idempotency_key)
        {
            anyhow::ensure!(
                existing.method_name == call.method_name,
                "NEAR idempotency key reused with a different method"
            );
            return Ok(call.idempotency_key.clone());
        }
        requests.push(NearLogicalRequest {
            idempotency_key: call.idempotency_key.clone(),
            method_name: call.method_name.clone(),
        });
        Ok(call.idempotency_key.clone())
    }

    pub fn requests(&self) -> Vec<NearLogicalRequest> {
        self.requests.lock().expect("near adapter mutex").clone()
    }

    pub fn record_confirmation(
        &self,
        idempotency_key: &str,
        transaction_hash_hash: impl Into<String>,
        receipt_hash: impl Into<String>,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.requests
                .lock()
                .expect("near adapter mutex")
                .iter()
                .any(|request| request.idempotency_key == idempotency_key),
            "cannot confirm an unsubmitted NEAR request"
        );
        let evidence = NearConfirmationEvidence {
            transaction_hash_hash: transaction_hash_hash.into(),
            receipt_hash: receipt_hash.into(),
        };
        anyhow::ensure!(
            evidence.transaction_hash_hash.starts_with("sha256:")
                && evidence.receipt_hash.starts_with("sha256:"),
            "NEAR confirmation evidence must be hash-only"
        );
        self.confirmations
            .lock()
            .expect("near confirmation mutex")
            .insert(idempotency_key.to_string(), evidence);
        Ok(())
    }

    pub fn confirmation(&self, idempotency_key: &str) -> Option<NearConfirmationEvidence> {
        self.confirmations
            .lock()
            .expect("near confirmation mutex")
            .get(idempotency_key)
            .cloned()
    }
}

impl NearPayoutAdapter for RecordingNearAdapter {
    fn adapter_identity(&self) -> &str {
        "recording_near_test_only"
    }

    fn submit(&self, call: &NearCreditReceiptCall) -> anyhow::Result<String> {
        Self::submit(self, call)
    }

    fn confirmation(&self, idempotency_key: &str) -> Option<NearConfirmationEvidence> {
        Self::confirmation(self, idempotency_key)
    }
}

pub fn pipeline_credit_event_id(tenant_id: &str, run_id: Uuid, score_outcome_id: Uuid) -> Uuid {
    Uuid::new_v5(
        &Uuid::NAMESPACE_URL,
        format!("tracecommons:pipeline-credit:{tenant_id}:{run_id}:{score_outcome_id}").as_bytes(),
    )
}

pub fn pipeline_ledger_source_key(tenant_id: &str, request_idempotency_key: &str) -> String {
    format!(
        "sha256:{:x}",
        Sha256::digest(
            format!("tracecommons:ledger-source:{tenant_id}:{request_idempotency_key}").as_bytes()
        )
    )
}

pub fn pipeline_settlement_batch_id(tenant_id: &str, source_list_hash: &str) -> Uuid {
    Uuid::new_v5(
        &Uuid::NAMESPACE_URL,
        format!("tracecommons:pipeline-batch:{tenant_id}:{source_list_hash}").as_bytes(),
    )
}

pub fn pipeline_near_outbox_id(tenant_id: &str, settlement_batch_id: Uuid) -> Uuid {
    Uuid::new_v5(
        &Uuid::NAMESPACE_URL,
        format!("tracecommons:pipeline-near:{tenant_id}:{settlement_batch_id}").as_bytes(),
    )
}

pub fn pipeline_near_outbox_line_id(
    tenant_id: &str,
    settlement_batch_id: Uuid,
    credit_account_hash: &str,
) -> Uuid {
    Uuid::new_v5(
        &Uuid::NAMESPACE_URL,
        format!(
            "tracecommons:pipeline-near:{tenant_id}:{settlement_batch_id}:{credit_account_hash}"
        )
        .as_bytes(),
    )
}

pub fn credit_account_hash(principal_ref: &str) -> String {
    format!("sha256:{:x}", Sha256::digest(principal_ref.as_bytes()))
}

pub fn source_list_hash(event_ids: &[Uuid]) -> String {
    let mut ids = event_ids.to_vec();
    ids.sort_unstable();
    let canonical = ids
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    format!("sha256:{:x}", Sha256::digest(canonical.as_bytes()))
}

pub fn issuer_approval_hash(source_list_hash: &str) -> String {
    format!(
        "sha256:{:x}",
        Sha256::digest(format!("pipeline-issuer:{source_list_hash}").as_bytes())
    )
}

pub fn settlement_batch_ref_hash(settlement_batch_id: Uuid, source_list_hash: &str) -> String {
    format!(
        "sha256:{:x}",
        Sha256::digest(format!("{settlement_batch_id}\n{source_list_hash}").as_bytes())
    )
}

pub fn microcredits_to_settled_i64(amount: Microcredits) -> anyhow::Result<i64> {
    i64::try_from(amount.get()).map_err(|_| anyhow::anyhow!("credit_amount_overflow"))
}

pub fn disabled_near_call(
    settlement_batch_id: Uuid,
    credit_account_hash: &str,
    source_list_hash: &str,
    amount_micros: i64,
) -> anyhow::Result<NearCreditReceiptCall> {
    NearCreditReceiptCall::settle(
        "pipeline.test.near",
        NearCreditReceipt {
            settlement_batch_id,
            credit_account_hash: credit_account_hash.to_string(),
            policy_version: PIPELINE_SETTLEMENT_POLICY_VERSION.to_string(),
            source_list_hash: source_list_hash.to_string(),
            attestation_hash: issuer_approval_hash(source_list_hash),
            amount_micros,
            issuer_signature_hash: issuer_approval_hash(source_list_hash),
        },
    )
}

pub fn payout_state_label(status: TraceCreditSettlementNearStatus) -> &'static str {
    match status {
        TraceCreditSettlementNearStatus::Disabled => "disabled",
        TraceCreditSettlementNearStatus::Pending => "pending",
        TraceCreditSettlementNearStatus::Submitted => "submitted",
        TraceCreditSettlementNearStatus::Confirmed => "confirmed",
        TraceCreditSettlementNearStatus::Failed => "failed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_list_hash_is_order_independent() {
        let left = Uuid::from_u128(1);
        let right = Uuid::from_u128(2);
        assert_eq!(
            source_list_hash(&[left, right]),
            source_list_hash(&[right, left])
        );
        assert_ne!(source_list_hash(&[left]), source_list_hash(&[right]));
    }

    #[test]
    fn microcredit_storage_conversion_rejects_overflow() {
        assert!(microcredits_to_settled_i64(Microcredits::from_raw(i64::MAX as u64)).is_ok());
        assert!(
            microcredits_to_settled_i64(Microcredits::from_raw(u64::MAX))
                .unwrap_err()
                .to_string()
                .contains("credit_amount_overflow")
        );
    }
}
