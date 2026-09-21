// Copyright (C) 2026 K&Z Partners LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const MANIFEST: &str =
    "docs/superpowers/specs/2026-09-11-versioned-pipeline-contract-test-manifest.json";
const CONTRACTS: &str =
    "docs/superpowers/specs/2026-09-11-versioned-pipeline-behavioral-contracts.md";

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn declared_ids(source: &str, prefix: &str) -> BTreeSet<String> {
    source
        .lines()
        .filter_map(|line| {
            let heading = line.trim_start_matches('#').trim_start();
            let id = heading.split(':').next()?;
            (id.starts_with(prefix)
                && id
                    .strip_prefix(prefix)?
                    .bytes()
                    .all(|byte| byte.is_ascii_digit()))
            .then(|| id.to_string())
        })
        .collect()
}

fn source_for_module(module: &str) -> Option<&'static str> {
    match module {
        "pipeline" => Some("crates/trace-commons-gate-api/src/pipeline.rs"),
        "versioned_pipeline" => Some("crates/trace-commons-server/src/versioned_pipeline.rs"),
        "versioned_pipeline_activation" => {
            Some("crates/trace-commons-server/src/versioned_pipeline_activation.rs")
        }
        "versioned_pipeline_compat" => {
            Some("crates/trace-commons-server/src/versioned_pipeline_compat.rs")
        }
        "versioned_pipeline_index" => {
            Some("crates/trace-commons-server/src/versioned_pipeline_index.rs")
        }
        "versioned_pipeline_qualification" => {
            Some("crates/trace-commons-server/src/versioned_pipeline_qualification.rs")
        }
        "versioned_pipeline_runtime_pg" => {
            Some("crates/trace-commons-server/tests/versioned_pipeline_runtime_pg.rs")
        }
        "trace_commons_ingest_internal" => {
            Some("crates/trace-commons-server/src/bin/trace_commons_ingest_internal/tests.rs")
        }
        "trace_score_attestation" => {
            Some("crates/trace-commons-server/src/trace_score_attestation.rs")
        }
        _ => None,
    }
}

fn test_function_exists(source: &str, name: &str) -> bool {
    source.lines().any(|line| {
        let line = line.trim_start();
        line.strip_prefix("fn ")
            .or_else(|| line.strip_prefix("async fn "))
            .and_then(|declaration| declaration.split('(').next())
            == Some(name)
    })
}

fn resolve_evidence(root: &Path, evidence_id: &str) {
    if let Some((module, test_name)) = evidence_id.split_once("::") {
        let source_path =
            source_for_module(module).unwrap_or_else(|| panic!("unknown module: {evidence_id}"));
        let source = std::fs::read_to_string(root.join(source_path))
            .unwrap_or_else(|_| panic!("source exists: {source_path}"));
        assert!(
            test_function_exists(&source, test_name),
            "missing Rust test: {evidence_id}"
        );
        return;
    }

    let explicit_paths: &[&str] = match evidence_id {
        "pipeline-deployment-inventory" => &["scripts/operator/pipeline-deployment-inventory.py"],
        "pipeline-backup-restore-smoke" => &["scripts/operator/pipeline-backup-restore-smoke.sh"],
        "pipeline_hf_qualification" => &[
            "scripts/operator/run-pipeline-hf-qualification.sh",
            "docs/superpowers/specs/versioned-pipeline-hf-corpus-v1.json",
        ],
        "minimal_pipeline_corpus" => &[
            "scripts/operator/run-minimal-pipeline-corpus.sh",
            "docs/superpowers/specs/fixtures/versioned-pipeline-minimal-corpus-v1.json",
        ],
        "compatibility_pipeline_corpus" => &[
            "scripts/operator/run-compatibility-pipeline-corpus.sh",
            "docs/superpowers/specs/versioned-pipeline-compatibility-baseline-v1.json",
        ],
        _ => &[],
    };
    if !explicit_paths.is_empty() {
        for path in explicit_paths {
            assert!(root.join(path).is_file(), "missing evidence file: {path}");
        }
        return;
    }

    let binary_name = if let Some(suffix) = evidence_id.strip_prefix("trace_") {
        format!("trace-commons-{}", suffix.replace('_', "-"))
    } else {
        evidence_id.replace('_', "-")
    };
    let candidates = [
        root.join(format!(
            "crates/trace-commons-server/tests/{evidence_id}.rs"
        )),
        root.join(format!(
            "crates/trace-commons-server/src/bin/{binary_name}.rs"
        )),
        root.join(format!("crates/trace-commons-server/src/{evidence_id}.rs")),
        root.join(format!(
            "crates/trace-commons-contributor/tests/{evidence_id}.rs"
        )),
    ];
    assert!(
        candidates.iter().any(|candidate| candidate.is_file()),
        "missing evidence target: {evidence_id}"
    );
}

#[test]
fn contract_manifest_enumerates_the_authoritative_contracts_and_real_evidence() {
    let root = root();
    let contract_source = std::fs::read_to_string(root.join(CONTRACTS)).expect("contracts exist");
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join(MANIFEST)).expect("manifest exists"))
            .expect("manifest is valid JSON");
    assert_eq!(
        manifest["schema"],
        "trace_commons.contract_test_manifest.v1"
    );

    let declared_contracts = contract_source
        .lines()
        .filter_map(|line| {
            let heading = line.trim_start_matches('#').trim_start();
            let id = heading.split(':').next()?;
            let (prefix, number) = id.split_once('-')?;
            ((3..=4).contains(&prefix.len())
                && prefix.bytes().all(|byte| byte.is_ascii_uppercase())
                && number.len() == 3
                && number.bytes().all(|byte| byte.is_ascii_digit())
                && prefix != "SCN")
                .then(|| id.to_string())
        })
        .collect::<BTreeSet<_>>();
    let manifest_contracts = manifest["contract_groups"]
        .as_array()
        .expect("contract_groups is an array")
        .iter()
        .flat_map(|group| {
            group["contract_ids"]
                .as_array()
                .expect("contract_ids is an array")
        })
        .map(|id| id.as_str().expect("contract ID is a string").to_string())
        .collect::<BTreeSet<_>>();
    assert_eq!(manifest_contracts, declared_contracts);

    let manifest_scenarios = manifest["scenarios"]
        .as_array()
        .expect("scenarios is an array")
        .iter()
        .map(|scenario| {
            scenario["scenario_id"]
                .as_str()
                .expect("scenario ID is a string")
                .to_string()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(manifest_scenarios, declared_ids(&contract_source, "SCN-"));

    for item in manifest["contract_groups"]
        .as_array()
        .expect("contract_groups is an array")
        .iter()
        .chain(
            manifest["scenarios"]
                .as_array()
                .expect("scenarios is an array"),
        )
    {
        for evidence_id in item["test_ids"].as_array().expect("test_ids is an array") {
            resolve_evidence(
                &root,
                evidence_id.as_str().expect("evidence ID is a string"),
            );
        }
    }
}
