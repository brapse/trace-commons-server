"""Lab safety and persistence tests; no Docker or network needed."""

import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import lab


def report_fixture():
    policy = {"policy_id": "policy.v1", "implementation_id": "implementation.v1",
              "code_artifact_hash": lab.digest(b"code"), "configuration_hash": lab.digest(b"configuration"),
              "data_artifact_hashes": [], "projection_ids": []}
    manifest = {"format_version": 1, **{phase: policy.copy() for phase in lab.PHASES}}
    fixture = {
        "label": "clean", "state": "complete", "admission_decision": "admit",
        "expected_admission_decision": "admit", "phase_count": 4, "expected_outcome_count": 4,
        "replay_same_run": True, "changed_content_refused": True, "public_processing_state": "complete",
        "consent_state": "allowed", "expected_consent_state": "allowed",
        "privacy_state": "low", "expected_privacy_state": "low",
        "scoring_state": "complete", "expected_scoring_state": "complete",
        "settlement_state": "complete", "expected_settlement_state": "complete",
        "instrument_count": 1, "expected_instrument_count": 1,
        "phases": [{"phase": phase, "outcome_id": "11111111-1111-4111-8111-111111111111",
                    "decision": {"status": "ok"}, "evidence": {"input_hash": lab.digest(b"input")},
                    "evaluation": {"rule_id": "test_rule_v1"}} for phase in lab.PHASES],
    }
    raw = {
        "schema": "trace_commons.pipeline_corpus_report.v4", "bundle_id": lab.digest(b"bundle"),
        "package_hash": lab.digest(b"package"), "corpus_digest": lab.digest(b"corpus"),
        "configuration_digest": lab.digest(lab.canonical({phase: policy["configuration_hash"] for phase in lab.PHASES})),
        "configuration_identities": {"external_payout": "disabled"}, "policy_manifest": manifest,
        "expected_fixture_count": 1, "completed_fixture_count": 1, "failure_count": 0,
        "duration_ms": 123, "fixtures": [fixture],
    }
    signed = {"package": {"bundle_id": raw["bundle_id"], "manifest": manifest},
              "signature": {"package_hash": raw["package_hash"]}}
    return lab.normalize_report(raw, signed, raw["corpus_digest"], lab.digest(b"binary"))


def reseal(report):
    report["result_digest"] = lab.report_result_digest(report)
    report["report_digest"] = lab.digest(lab.canonical({key: value for key, value in report.items() if key != "report_digest"}))


class LabTests(unittest.TestCase):
    def test_git_corpus_has_fixed_order_digest_and_rejects_report_input(self):
        corpus, digest = lab.validate_corpus(lab.DEFAULT_CORPUS)
        self.assertEqual(len(corpus["fixtures"]), 5)
        self.assertEqual(corpus["fixtures"][0]["label"], "clean_tool_plan")
        self.assertEqual(lab.validate_corpus(lab.DEFAULT_CORPUS, digest)[1], digest)
        with self.assertRaises(lab.LabError):
            lab.validate_corpus(lab.DEFAULT_CORPUS, lab.digest(b"different"))
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "pipeline-restore-corpus.json"
            lab.write_json(candidate, {"schema": "trace_commons.pipeline_corpus_report.v4", "fixtures": []})
            with self.assertRaises(lab.LabError):
                lab.validate_corpus(candidate)
            corpus["fixtures"][0]["label"] = "raw@example.com"
            lab.write_json(candidate, corpus)
            with self.assertRaises(lab.LabError):
                lab.validate_corpus(candidate)

    def test_private_values_never_enter_a_report(self):
        for value in ({"input": "singleword"}, {"account_id": "person"},
                      {"label": "someone@example.com"}, {"label": "ghp_abcdef"},
                      {"label": "this contains trace text"}):
            with self.assertRaises(lab.LabError):
                lab.safe_report_value(value)
        report = report_fixture()
        self.assertNotIn("11111111-1111-4111-8111-111111111111", json.dumps(report))
        self.assertNotIn("duration_ms", report)
        self.assertTrue(report["fixtures"][0]["phases"][0]["outcome_id"].startswith("sha256:"))

    def test_report_validation_rejects_tampering_payout_and_configuration_mismatch(self):
        report = report_fixture()
        lab.validate_report(report)
        report["failure_count"] = 1
        with self.assertRaises(lab.LabError):
            lab.validate_report(report)
        for field, value in (("external_payout_enabled", True), ("production_ready", True),
                             ("configuration_digest", lab.digest(b"wrong")), ("fixture_order", [])):
            report = report_fixture()
            report[field] = value
            reseal(report)
            with self.assertRaises(lab.LabError):
                lab.validate_report(report)

    def test_catalog_preserves_history_and_repeated_updates_are_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report_path, catalog_path = root / "report.json", root / "catalog.json"
            first = report_fixture()
            lab.write_json(report_path, first)
            lab.update_catalog(catalog_path, report_path)
            original = catalog_path.read_bytes()
            lab.update_catalog(catalog_path, report_path)
            self.assertEqual(original, catalog_path.read_bytes())
            second = copy.deepcopy(first)
            second["bundle_id"] = lab.digest(b"another-bundle")
            reseal(second)
            lab.write_json(report_path, second)
            lab.update_catalog(catalog_path, report_path)
            third = copy.deepcopy(first)
            third["corpus_digest"] = lab.digest(b"holdout")
            reseal(third)
            lab.write_json(report_path, third)
            catalog = lab.update_catalog(catalog_path, report_path)
            self.assertEqual(len(catalog["bundles"]), 2)
            original_entry = next(item for item in catalog["bundles"] if item["bundle_id"] == first["bundle_id"])
            self.assertEqual(len(original_entry["reports"]), 2)
            for entry in catalog["bundles"]:
                for record in entry["reports"]:
                    stored = lab.read_json(root / record["report"])
                    lab.validate_report(stored)
                    self.assertEqual(stored["report_digest"], record["report_digest"])

    def test_result_digest_ignores_provenance_but_detects_decision_changes(self):
        first = report_fixture()
        changed = copy.deepcopy(first)
        phase = changed["fixtures"][0]["phases"][0]
        phase["outcome_id"] = lab.digest(b"another-outcome")
        phase["evidence"]["input_hash"] = lab.digest(b"another-input-hash")
        reseal(changed)
        self.assertEqual(changed["result_digest"], first["result_digest"])
        self.assertNotEqual(changed["report_digest"], first["report_digest"])
        phase["decision"]["status"] = "rejected"
        reseal(changed)
        self.assertNotEqual(changed["result_digest"], first["result_digest"])

    def test_concurrent_catalog_updates_do_not_lose_reports(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            processes = []
            for number in range(4):
                report = report_fixture()
                report["corpus_digest"] = lab.digest(str(number).encode())
                reseal(report)
                report_path = root / f"report-{number}.json"
                lab.write_json(report_path, report)
                processes.append(subprocess.Popen([sys.executable, str(Path(lab.__file__)), "catalog",
                    "--report", str(report_path), "--catalog", str(root / "catalog.json")], stdout=subprocess.DEVNULL))
            self.assertTrue(all(process.wait(timeout=10) == 0 for process in processes))
            self.assertEqual(len(lab.read_json(root / "catalog.json")["bundles"][0]["reports"]), 4)

    def test_inherited_ingest_configuration_does_not_reach_the_instance(self):
        with patch.dict(lab.os.environ, {"DATABASE_URL": "shared", "TRACE_COMMONS_DATABASE_URL": "shared",
                                       "TRACE_COMMONS_PIPELINE_PAYOUT_ENABLED": "true", "RUST_LOG": "debug",
                                       "TRACE_COMMONS_PIPELINE_TOKENS": "raw-account-token"}):
            env = lab.child_environment()
        self.assertNotIn("DATABASE_URL", env)
        self.assertNotIn("TRACE_COMMONS_DATABASE_URL", env)
        self.assertNotIn("TRACE_COMMONS_PIPELINE_PAYOUT_ENABLED", env)
        self.assertEqual(env["RUST_LOG"], "off")
        self.assertNotIn("raw-account-token", env["TRACE_COMMONS_PIPELINE_TOKENS"])

    def test_server_process_is_stopped_on_failure(self):
        process = unittest.mock.Mock()
        process.poll.return_value = None
        with patch.object(lab.subprocess, "Popen", return_value=process), patch.object(lab, "http", return_value=b"ok"):
            with self.assertRaises(RuntimeError):
                with lab.server(["server"], {}, "http://127.0.0.1:1"):
                    raise RuntimeError("fixture")
        process.terminate.assert_called_once()
        process.wait.assert_called_once_with(timeout=10)

    def test_wrong_qualification_cannot_be_attached_to_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = report_fixture()
            lab.write_json(root / "report.json", report)
            lab.write_json(root / "qualification.json", {
                "schema": "trace_commons.pipeline_qualification_report.v1",
                "inputs": {"bundle_id": lab.digest(b"other")},
            })
            with self.assertRaises(lab.LabError):
                lab.update_catalog(root / "catalog.json", root / "report.json", records=[root / "qualification.json"])
            self.assertFalse((root / "catalog.json").exists())


if __name__ == "__main__":
    unittest.main()
