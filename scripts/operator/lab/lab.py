#!/usr/bin/env python3
"""Local pipeline lab. Files only; the runner owns the isolated pipeline instance."""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[3]
DEFAULT_CORPUS = (
    ROOT
    / "docs/superpowers/specs/fixtures/versioned-pipeline-minimal-corpus-v1.json"
)
DEFAULT_OUTPUT = ROOT / ".local/lab"
DEFAULT_CATALOG = ROOT / ".local/pipeline-lab-catalog.json"
CATALOG_SCHEMA = "trace_commons.pipeline_lab_catalog.v1"
REPORT_SCHEMA = "trace_commons.pipeline_corpus_report.v5"
PHASES = ("admission", "review", "score", "settle")
BLOCKERS = [
    "local_test_only", "local_reference_scorer", "local_reference_embedder",
    "synthetic_index", "synthetic_settlement", "static_bearer_authentication",
]
HASH = re.compile(r"sha256:[a-f0-9]{64}\Z")
LABEL = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")
UUID = re.compile(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}\Z")
VOLATILE = {"duration_ms", "time_in_phase_ms", "next_attempt_at"}
PRIVATE_FIELDS = {"input", "text", "trace_text", "secret", "secret_probe", "token", "account_id", "email"}


class LabError(Exception):
    """A label which is safe to print. Never include source values."""


def require(condition, label):
    if not condition:
        raise LabError(label)


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def read_json(path):
    return json.loads(Path(path).read_bytes())


def atomic_write(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as output:
        temporary = Path(output.name)
        output.write(data)
        output.flush()
        os.fsync(output.fileno())
    try:
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def write_json(path, value):
    atomic_write(path, json.dumps(value, indent=2, sort_keys=True, allow_nan=False).encode() + b"\n")


def validate_corpus(path, expected_digest=None):
    data = Path(path).read_bytes()
    corpus = json.loads(data)
    require(corpus.get("schema") == "trace_commons.pipeline_corpus.v1", "unsupported_corpus_schema")
    require(bool(corpus.get("fixtures")), "empty_corpus")
    seen = {field: set() for field in ("label", "trace_id", "submission_id")}
    for fixture in corpus["fixtures"]:
        require(re.fullmatch(r"[a-z0-9_]{1,64}", fixture["label"]), "unsafe_fixture_label")
        for field, values in seen.items():
            value = fixture[field]
            require(value not in values, "duplicate_corpus_identity")
            values.add(value)
        uuid.UUID(fixture["trace_id"])
        uuid.UUID(fixture["submission_id"])
        require(bool(fixture["secret_probe"]), "empty_secret_probe")
    actual = digest(data)
    require(expected_digest is None or actual == expected_digest, "corpus_digest_mismatch")
    return corpus, actual


def safe_report_value(value):
    """Only structured values, hashes and labels leave the temporary runner directory."""
    if isinstance(value, dict):
        require(all(LABEL.fullmatch(key) for key in value), "unsafe_report_field")
        require(not PRIVATE_FIELDS.intersection(value), "private_report_field")
        return {key: safe_report_value(item) for key, item in value.items() if key not in VOLATILE}
    if isinstance(value, list):
        return [safe_report_value(item) for item in value]
    if isinstance(value, str):
        if UUID.fullmatch(value):
            return digest(value.encode())
        require(LABEL.fullmatch(value) is not None, "unsafe_report_value")
        require(not value.startswith(("ghp_", "github_pat_", "sk-")), "unsafe_report_value")
    require(value is None or isinstance(value, (str, int, float, bool)), "unsafe_report_value")
    return value


def result_values(value):
    # Keep numeric results and labels. Content/provenance hashes remain in the full report.
    if isinstance(value, dict):
        return {key: result_values(item) for key, item in value.items() if key != "outcome_id"}
    if isinstance(value, list):
        return [result_values(item) for item in value]
    return "hash" if isinstance(value, str) and HASH.fullmatch(value) else value


def report_result_digest(report):
    results = [{key: fixture[key] for key in (
        "label", "state", "admission_decision", "expected_admission_decision",
        "phase_count", "expected_outcome_count", "phases", "replay_same_run",
        "changed_content_refused", "public_processing_state", "consent_state",
        "expected_consent_state", "privacy_state", "expected_privacy_state",
        "scoring_state", "expected_scoring_state", "settlement_state",
        "expected_settlement_state", "instrument_count",
        "expected_instrument_count",
    )} for fixture in report["fixtures"]]
    return digest(canonical({
        "bundle_id": report["bundle_id"], "corpus_digest": report["corpus_digest"],
        "fixtures": result_values(results),
    }))


def normalize_report(raw, signed, corpus_digest, binary_hash):
    package = signed["package"]
    require(raw["corpus_digest"] == corpus_digest, "corpus_digest_mismatch")
    require(raw["bundle_id"] == package["bundle_id"], "bundle_mismatch")
    require(raw["policy_manifest"] == package["manifest"], "manifest_mismatch")
    require(raw["package_hash"] == signed["signature"]["package_hash"], "package_hash_mismatch")
    require(raw["configuration_identities"]["external_payout"] == "disabled", "payout_enabled")
    report = safe_report_value(raw)
    report.update(
        schema=REPORT_SCHEMA, scope="local_test", external_payout_enabled=False,
        production_ready=False, safe_blockers=BLOCKERS,
        runner_artifact_hash=binary_hash,
        fixture_order=[fixture["label"] for fixture in report["fixtures"]],
    )
    report["result_digest"] = report_result_digest(report)
    report["report_digest"] = digest(canonical(report))
    validate_report(report)
    return report


def validate_report(report):
    require(report.get("schema") == REPORT_SCHEMA, "unsupported_report_schema")
    require(report.get("scope") == "local_test" and report.get("production_ready") is False,
            "invalid_report_scope")
    require(report.get("external_payout_enabled") is False, "payout_enabled")
    require(set(BLOCKERS).issubset(report["safe_blockers"]), "missing_local_blockers")
    require(safe_report_value(report) == report, "unsafe_report")
    for field in ("bundle_id", "corpus_digest", "configuration_digest", "package_hash",
                  "runner_artifact_hash", "result_digest", "report_digest"):
        require(HASH.fullmatch(report[field]), "invalid_report_hash")
    require(digest(canonical({key: value for key, value in report.items() if key != "report_digest"}))
            == report["report_digest"], "report_digest_mismatch")
    require(report_result_digest(report) == report["result_digest"], "result_digest_mismatch")
    manifest = report["policy_manifest"]
    configuration = {phase: manifest[phase]["configuration_hash"] for phase in PHASES}
    require(digest(canonical(configuration)) == report["configuration_digest"], "configuration_digest_mismatch")
    require(report["fixture_order"] == [item["label"] for item in report["fixtures"]], "fixture_order_mismatch")
    require(len(report["fixtures"]) == report["expected_fixture_count"] > 0, "fixture_count_mismatch")
    require(len(set(report["fixture_order"])) == len(report["fixtures"]), "duplicate_fixture_label")
    require(sum(item["state"] == "complete" for item in report["fixtures"])
            == report["completed_fixture_count"], "completion_count_mismatch")
    require(0 <= report["failure_count"] <= report["expected_fixture_count"], "failure_count_invalid")
    mismatches = sum(
        item["consent_state"] != item["expected_consent_state"]
        or item["privacy_state"] != item["expected_privacy_state"]
        or item["scoring_state"] != item["expected_scoring_state"]
        or item["settlement_state"] != item["expected_settlement_state"]
        or item["instrument_count"] != item["expected_instrument_count"]
        or not item["replay_same_run"]
        or not item["changed_content_refused"]
        for item in report["fixtures"]
    )
    require(mismatches <= report["failure_count"], "qualification_mismatch_not_failed")


def validate_evidence(value):
    """Allow labels, hashes, repository-relative paths and ISO observation times only."""
    if isinstance(value, dict):
        require(not PRIVATE_FIELDS.intersection(value), "private_evidence_field")
        for key, item in value.items():
            require(LABEL.fullmatch(key), "unsafe_evidence_field")
            validate_evidence(item)
    elif isinstance(value, list):
        for item in value:
            validate_evidence(item)
    elif isinstance(value, str):
        timestamp = re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+(?:Z|[+-][0-9:]+)", value)
        repository_path = re.fullmatch(r"[A-Za-z0-9_./{}:-]+", value)
        require(timestamp or repository_path or value == "", "unsafe_evidence_value")
        require(not value.startswith(("ghp_", "github_pat_", "sk-")), "unsafe_evidence_value")
    else:
        require(value is None or isinstance(value, (int, float, bool)), "unsafe_evidence_value")


def markdown(report):
    lines = ["# Pipeline corpus report", "", f"Bundle: `{report['bundle_id']}`", "",
             f"Corpus: `{report['corpus_digest']}`", "",
             f"Completed: {report['completed_fixture_count']}/{report['expected_fixture_count']}. "
             f"Failures: {report['failure_count']}.", "", "External payout: disabled.", "",
             "| Phase | Implementation | Configuration hash |", "| --- | --- | --- |"]
    for phase in PHASES:
        policy = report["policy_manifest"][phase]
        lines.append(f"| {phase} | `{policy['implementation_id']}` | `{policy['configuration_hash']}` |")
    lines += ["", "| Fixture | Admission | State | Outcomes |", "| --- | --- | --- | --- |"]
    for fixture in report["fixtures"]:
        lines.append(f"| {fixture['label']} | {fixture['admission_decision']} | {fixture['state']} | {fixture['phase_count']} |")
    lines += ["", "Production blockers: " + ", ".join(report["safe_blockers"]) + ".", ""]
    return "\n".join(lines)


def archive(catalog_path, data, kind):
    identity = digest(data)
    destination = catalog_path.parent / "lab-records" / f"{kind}-{identity[7:]}.json"
    if destination.exists():
        require(destination.read_bytes() == data, "immutable_record_conflict")
    else:
        atomic_write(destination, data)
    return destination.relative_to(catalog_path.parent).as_posix()


def update_catalog(catalog_path, report_path, package_path=None, key_path=None, records=()):
    catalog_path = Path(catalog_path)
    report = read_json(report_path)
    validate_report(report)
    require(bool(package_path) == bool(key_path), "package_and_key_required")
    # Validate before changing any files. Qualification records are evidence, never corpus inputs.
    extra = []
    allowed_schemas = {
        "trace_commons.pipeline_qualification_report.v1",
        "trace_commons.pipeline_restore_report.v1",
        "trace_commons.pipeline_deployment_inventory.v1",
        "trace_commons.pipeline_hf_qualification_report.v1",
    }
    for record in records:
        value = read_json(record)
        require(value.get("schema") in allowed_schemas, "unsupported_development_record")
        validate_evidence(value)
        if "inputs" in value:
            require(value["inputs"]["bundle_id"] == report["bundle_id"], "qualification_bundle_mismatch")
            require(value["inputs"]["corpus_digest"] == report["corpus_digest"], "qualification_corpus_mismatch")
            require(value["inputs"]["configuration_digest"] == report["configuration_digest"], "qualification_configuration_mismatch")
        extra.append(canonical(value) + b"\n")
    if package_path:
        signed = read_json(package_path)
        require(signed["package"]["bundle_id"] == report["bundle_id"], "catalog_package_mismatch")
        require(signed["package"]["manifest"] == report["policy_manifest"], "catalog_manifest_mismatch")
        require(signed["signature"]["package_hash"] == report["package_hash"], "catalog_package_hash_mismatch")
    catalog_path.parent.mkdir(parents=True, exist_ok=True)
    with catalog_path.with_suffix(".lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        catalog = read_json(catalog_path) if catalog_path.exists() else {"schema": CATALOG_SCHEMA, "bundles": []}
        require(catalog.get("schema") == CATALOG_SCHEMA, "unsupported_catalog_schema")
        # Older one-shot catalogs had a generation time. Content now defines identity.
        catalog.pop("generated_at", None)
        bundles = catalog["bundles"]
        entry = next((item for item in bundles if item["bundle_id"] == report["bundle_id"]), None)
        if entry is None:
            entry = {"bundle_id": report["bundle_id"], "development_records": []}
            bundles.append(entry)
        entry.update(corpus_digest=report["corpus_digest"], configuration_digest=report["configuration_digest"],
                     production_ready=False, safe_blockers=report["safe_blockers"])
        record = {key: report[key] for key in ("report_digest", "result_digest", "corpus_digest", "configuration_digest", "package_hash")}
        record["status"] = "pass" if report["failure_count"] == 0 else "fail"
        record["report"] = archive(catalog_path, canonical(report) + b"\n", "report")
        paths = [record["report"]]
        if package_path:
            record["package"] = archive(catalog_path, canonical(read_json(package_path)) + b"\n", "package")
            record["trusted_key"] = archive(catalog_path, canonical(read_json(key_path)) + b"\n", "key")
            paths += [record["package"], record["trusted_key"]]
        for data in extra:
            paths.append(archive(catalog_path, data, "evidence"))
        entry["development_records"] = sorted(set(entry["development_records"] + paths))
        previous = entry.setdefault("reports", [])
        # Preserve separately signed instances as well as reports for different corpora.
        if record not in previous:
            previous.append(record)
        previous.sort(key=lambda item: (item["report_digest"], item.get("package", "")))
        bundles.sort(key=lambda item: item["bundle_id"])
        write_json(catalog_path, catalog)
    return catalog


def build_runner():
    env = os.environ.copy()
    env["RUSTFLAGS"] = "-D warnings"
    subprocess.run(["cargo", "build", "-p", "trace-commons-server", "--bin", "trace-commons-pipeline-local"],
                   cwd=ROOT, env=env, check=True)
    target = Path(env.get("CARGO_TARGET_DIR", ROOT / "target"))
    if not target.is_absolute():
        target = ROOT / target
    return target / "debug/trace-commons-pipeline-local"


def child_environment():
    # Do not inherit payout, shared DB, telemetry, authentication or adapter configuration.
    env = {key: value for key, value in os.environ.items() if key in ("PATH", "HOME", "TMPDIR", "SystemRoot")}
    env["RUST_LOG"] = "off"
    env["TRACE_COMMONS_PIPELINE_MASTER_KEY"] = "lab-local-master-key-material-32-bytes"
    roles = [("contributor", "principal", "a"), ("reviewer", "reviewer", "e"),
             ("worker", "worker", "b"), ("operator", "operator", "c"),
             ("exporter", "exporter", "f"), ("lifecycle", "lifecycle_worker", "9")]
    env["TRACE_COMMONS_PIPELINE_TOKENS"] = ";".join(
        f"{token}-token,tenant-lab,{principal}_sha256:{char * 64},{principal if token == 'lifecycle' else token}"
        for token, principal, char in roles
    ) + ";other-operator-token,tenant-other,operator_sha256:" + "d" * 64 + ",operator"
    return env


def run_quiet(command, **kwargs):
    # Never replay subprocess errors containing a database URL, token or corpus input.
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, **kwargs)
    require(result.returncode == 0, "lab_subprocess_failed")
    return result.stdout.decode().strip()


def unused_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def http(base, endpoint, token=None):
    request = urllib.request.Request(base + endpoint)
    if token:
        request.add_header("Authorization", "Bearer " + token)
    with urllib.request.urlopen(request, timeout=1) as response:
        return response.read()


@contextlib.contextmanager
def server(command, env, base):
    debug_path = os.environ.get("TRACE_COMMONS_PIPELINE_LAB_DEBUG_LOG")
    debug = open(debug_path, "ab") if debug_path else None
    process = subprocess.Popen(
        command,
        env=env,
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=debug or subprocess.DEVNULL,
    )
    try:
        for _ in range(120):
            require(process.poll() is None, "lab_server_exited")
            try:
                http(base, "/healthz")
                break
            except (OSError, urllib.error.URLError):
                time.sleep(0.25)
        else:
            raise LabError("lab_server_start_timeout")
        require(process.poll() is None, "lab_server_exited")
        yield
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        if debug:
            debug.close()


def make_package(binary, output, key_output, policies, signing_key=None, key_id=None):
    command = [str(binary), "package", "--policies", policies, "--output", str(output),
               "--public-key-output", str(key_output)]
    if signing_key:
        command += ["--signing-key", str(signing_key), "--key-id", key_id]
    run_quiet(command, env=child_environment())


def corpus_run(args):
    corpus, corpus_digest = validate_corpus(args.corpus, args.corpus_digest)
    require(bool(args.package) == bool(args.trusted_key), "package_and_key_required")
    require(not args.package or args.policies is None, "package_and_policies_conflict")
    binary = build_runner()
    binary_hash = digest(binary.read_bytes())
    args.output_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="pipeline-lab-") as temporary:
        work = Path(temporary)
        # Snapshot selected input and package before starting the instance.
        corpus_path = work / "corpus.json"
        shutil.copyfile(args.corpus, corpus_path)
        validate_corpus(corpus_path, corpus_digest)
        package_path, key_path = work / "package.json", work / "key.json"
        if args.package:
            shutil.copyfile(args.package, package_path)
            shutil.copyfile(args.trusted_key, key_path)
        else:
            make_package(binary, package_path, key_path, args.policies or "minimal")
        signed = read_json(package_path)
        expected_instrument_count = (
            1
            if signed["package"]["manifest"]["score"]["implementation_id"]
            == "trace_commons.score.compatibility.v1"
            else 0
        )
        package_args = ["--package", str(package_path), "--trusted-key", str(key_path)]
        container = "trace-commons-lab-" + uuid.uuid4().hex
        port = int(os.environ.get("TRACE_COMMONS_PIPELINE_PORT", unused_port()))
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", port))
        pg_port = os.environ.get("TRACE_COMMONS_PIPELINE_PG_PORT", "")
        require(not pg_port or pg_port.isdigit(), "invalid_postgres_port")
        base = f"http://127.0.0.1:{port}"
        env = child_environment()
        try:
            run_quiet(["docker", "run", "--rm", "--detach", "--name", container,
                       "-e", "POSTGRES_PASSWORD=lab-admin", "-p", f"127.0.0.1:{pg_port}:5432", "postgres:17-alpine"])
            for _ in range(60):
                result = subprocess.run(["docker", "exec", container, "pg_isready", "-U", "postgres"],
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if result.returncode == 0:
                    break
                time.sleep(0.25)
            else:
                raise LabError("lab_postgres_start_timeout")
            time.sleep(0.5)
            published = run_quiet(["docker", "port", container, "5432/tcp"])
            require(published.startswith("127.0.0.1:") and published.count(":") == 1, "invalid_postgres_binding")
            database_address = published.split(":")[1]
            serve = [str(binary), "serve", "--bind", f"127.0.0.1:{port}",
                     "--artifact-root", str(work / "artifacts"), "--allow-minimal-policies"] + package_args
            with server(serve + ["--database-url", f"postgres://postgres:lab-admin@127.0.0.1:{database_address}/postgres"], env, base):
                pass
            run_quiet(["docker", "exec", container, "psql", "-U", "postgres", "-v", "ON_ERROR_STOP=1", "-c", """
                CREATE ROLE pipeline_runtime LOGIN PASSWORD 'lab-runtime' NOBYPASSRLS;
                GRANT pipeline_claimer TO pipeline_runtime;
                GRANT CONNECT ON DATABASE postgres TO pipeline_runtime;
                GRANT USAGE ON SCHEMA public TO pipeline_runtime;
                GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO pipeline_runtime;
                GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO pipeline_runtime;
                GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO pipeline_runtime;
            """])
            raw_path = work / "report.json"
            with server(serve + ["--database-url", f"postgres://pipeline_runtime:lab-runtime@127.0.0.1:{database_address}/postgres",
                                 "--skip-migrations"], env, base):
                debug_path = os.environ.get("TRACE_COMMONS_PIPELINE_LAB_DEBUG_LOG")
                with (
                    open(debug_path, "ab")
                    if debug_path
                    else contextlib.nullcontext(subprocess.DEVNULL)
                ) as debug:
                    completed = subprocess.run([str(binary), "corpus", "--base-url", base,
                        "--submit-token", "contributor-token", "--worker-token", "worker-token",
                        "--reviewer-token", "reviewer-token", "--inspect-token", "operator-token",
                        "--fixtures", str(corpus_path), "--json-report", str(raw_path),
                        "--markdown-report", str(work / "report.md"),
                        "--expected-instrument-count", str(expected_instrument_count)] + package_args,
                        env=env, cwd=ROOT, stdout=subprocess.DEVNULL, stderr=debug)
                require(raw_path.exists(), "corpus_failed_before_report")
                raw = read_json(raw_path)
                run_id = raw["fixtures"][0]["run_id"]
                try:
                    http(base, f"/v1/pipeline/runs/{run_id}", "other-operator-token")
                except urllib.error.HTTPError as error:
                    require(error.code == 404, "tenant_isolation_failed")
                else:
                    raise LabError("tenant_isolation_failed")
            for fixture in corpus["fixtures"]:
                require(fixture["secret_probe"].encode() not in raw_path.read_bytes(), "secret_in_report")
            report = normalize_report(raw, signed, corpus_digest, binary_hash)
            report_path = args.json_report or args.output_dir / "report.json"
            markdown_path = args.markdown_report or args.output_dir / "report.md"
            require(report_path.resolve() != markdown_path.resolve(), "report_outputs_must_differ")
            catalog_path = args.catalog
            outputs = [report_path.resolve(), markdown_path.resolve(), catalog_path.resolve()]
            inputs = [Path(item).resolve() for item in (args.corpus, args.package, args.trusted_key) if item]
            require(len(set(outputs)) == 3 and not set(outputs).intersection(inputs), "conflicting_lab_paths")
            normalized_path = work / "normalized-report.json"
            write_json(normalized_path, report)
            update_catalog(catalog_path, normalized_path, package_path, key_path)
            write_json(report_path, report)
            atomic_write(markdown_path, markdown(report).encode())
            print(f"Report: {report_path}\nCatalog: {catalog_path}\nBundle: {report['bundle_id']}")
            require(completed.returncode == 0 and report["failure_count"] == 0, "corpus_report_failed")
        finally:
            subprocess.run(["docker", "rm", "-f", container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("corpus-run", help="Run a fixed corpus in a throwaway Docker instance and index its report")
    run.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    run.add_argument("--corpus-digest", help="Require this exact sha256 digest before starting")
    run.add_argument("--policies", choices=("minimal", "compatibility"))
    run.add_argument("--package", type=Path)
    run.add_argument("--trusted-key", type=Path)
    run.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    run.add_argument("--json-report", type=Path)
    run.add_argument("--markdown-report", type=Path)
    run.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
    report = commands.add_parser("report", help="Validate and display a stored corpus report")
    report.add_argument("path", type=Path)
    catalog = commands.add_parser("catalog", help="Update the catalog without rerunning a corpus")
    catalog.add_argument("--report", type=Path, required=True)
    catalog.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
    catalog.add_argument("--package", type=Path)
    catalog.add_argument("--trusted-key", type=Path)
    catalog.add_argument("--record", type=Path, action="append", default=[])
    package = commands.add_parser("package", help="Build and sign a Rust policy profile with the ingest package format")
    package.add_argument("--policies", choices=("minimal", "compatibility"), default="minimal")
    package.add_argument("--output", type=Path, default=DEFAULT_OUTPUT / "package.json")
    package.add_argument("--public-key-output", type=Path, default=DEFAULT_OUTPUT / "trusted-key.json")
    package.add_argument("--signing-key", type=Path)
    package.add_argument("--key-id")
    commands.add_parser("qualify", help="Run pipeline qualification and PostgreSQL integration tests")
    args = parser.parse_args()
    if args.command == "corpus-run":
        corpus_run(args)
    elif args.command == "report":
        value = read_json(args.path)
        validate_report(value)
        print(markdown(value))
    elif args.command == "catalog":
        if args.package or args.trusted_key:
            require(args.package and args.trusted_key, "package_and_key_required")
            run_quiet([str(build_runner()), "verify-package", "--package", str(args.package.resolve()),
                       "--trusted-key", str(args.trusted_key.resolve())], env=child_environment())
        update_catalog(args.catalog, args.report, args.package, args.trusted_key, args.record)
        print(f"Catalog: {args.catalog}")
    elif args.command == "package":
        require(bool(args.signing_key) == bool(args.key_id), "signing_key_and_id_required")
        outputs = {args.output.resolve(), args.public_key_output.resolve()}
        require(len(outputs) == 2 and (not args.signing_key or args.signing_key.resolve() not in outputs),
                "conflicting_package_paths")
        make_package(build_runner(), args.output.resolve(), args.public_key_output.resolve(), args.policies,
                     args.signing_key.resolve() if args.signing_key else None, args.key_id)
        print(f"Package: {args.output}\nPublic key: {args.public_key_output}")
    elif args.command == "qualify":
        subprocess.run(
            ["bash", str(ROOT / "scripts/operator/run-pipeline-qualification.sh")],
            cwd=ROOT,
            check=True,
        )


if __name__ == "__main__":
    def interrupt(_signum, _frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupt)
    try:
        main()
    except LabError as error:
        print(f"Lab failed: {error}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("Lab interrupted; temporary resources removed.", file=sys.stderr)
        sys.exit(130)
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError):
        # Inputs and child-process commands may contain credentials or trace text.
        print("Lab failed. Check corpus, package, report and Docker prerequisites.", file=sys.stderr)
        sys.exit(1)
