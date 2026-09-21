# Pipeline qualification

Pipeline qualification adds package trust, operational evidence, and restore qualification.
It does not activate the new pipeline for production submissions.

The pipeline now has these properties:

- Ed25519 signatures bind canonical package bytes.
- A trust store rejects unknown package signing keys.
- Production qualification rejects unknown policy implementations.
- Production qualification rejects development and synthetic dependencies.
- Only a qualified package can use the production activation operation.
- Package and qualification records remain immutable.
- Readiness separates liveness from dependency and control state.
- Operational summaries show work age, errors, holds, outbox state, and
  blocked lifecycle work.
- Forensic traces link a run to outcomes, commands, credit, batches, and
  interventions.
- Promotion evidence has a maximum age.
- Missing, failed, or stale drill evidence blocks promotion.
- Index rebuild uses sealed commands and does not create outcomes or credit.
- PostgreSQL and encrypted object restore preserve operation identities.
- A machine-generated inventory classifies routes, operations, adapters,
  tables, object namespaces, telemetry destinations, and roles.

## Local qualification

Use the [local pipeline lab](pipeline-lab.md) for a single corpus run, signed package,
report, and catalog. To run all qualification drills through the same entrypoint:

```bash
bash scripts/operator/lab/run.sh qualify
```

The existing command remains supported:

```bash
bash scripts/operator/run-pipeline-qualification.sh
```

The command does these tests:

1. It validates the deployment inventory.
2. It tests package identity and package trust.
3. It runs the full PostgreSQL pipeline suite.
4. It runs the compatibility corpus through the HTTP and worker paths.
5. It restores PostgreSQL and encrypted objects.
6. It compares immutable identities before and after the restore.
7. It writes a qualification report and a lab catalog.

Catalog generation is a separate lab command. It preserves earlier bundle
entries and archives report and package records by digest. Configuration
digests come from the four policy configurations in the selected package.

The command writes these files:

- `.local/pipeline-qualification-report.json`
- `.local/pipeline-lab-catalog.json`
- `.local/pipeline-interface-inventory.json`
- `.local/pipeline-restore-report.json`
- `.local/pipeline-report.json`
- `.local/pipeline-report.md`

## PostgreSQL qualification

Set `TRACE_COMMONS_PG_TEST_DATABASE_URL` to a PostgreSQL test database.
Then run this command:

```bash
cargo test -p trace-commons-server --test versioned_pipeline_runtime_pg
```

CI supplies the database. Therefore, a skipped database test cannot qualify
the candidate in CI.

## Pinned Hugging Face qualification

Run:

```bash
bash scripts/operator/run-pipeline-hf-qualification.sh
```

The command reads the repository, revision, split, sample counts, and expected
digests from
[`versioned-pipeline-hf-corpus-v1.json`](../superpowers/specs/versioned-pipeline-hf-corpus-v1.json).
It downloads JSONL sessions only. It creates separate bootstrap and holdout
corpora under `.local/pipeline-hf/`, then runs both through the local HTTP and
worker path.

The workflow fails if the dataset or order changes, the sample is incomplete,
or replay, conflict, isolation, privacy, consent, scoring, settlement, or
instrument results differ. Reports contain hashes, labels, and counts. They do
not contain trace text or contributor identity.

The HF report expires after seven days. Missing, failed, or stale HF evidence
blocks production promotion. Ordinary CI runs the checked-in synthetic corpus
and does not require network access.

For an offline implementation check, set
`TRACE_COMMONS_PIPELINE_HF_LOCAL_JSONL_DIR` to the checked-in JSONL fixture
directory and supply its expected source and order digests. Offline evidence
is local test evidence and does not replace the pinned HF promotion report.

## Production package registration

Build the package in the policy lab. Sign its canonical package hash with an
approved Ed25519 release key.

Call `PipelineQualificationStore::qualify_bundle` with the signed package,
the trust store, the evidence digests, and the production dependency profile.

Pass the current promotion decision, deployed code revision, and dependency
profile to `activate_qualified_bundle`. The operation rejects stale evidence,
a revision mismatch, or a non-production dependency.

Pipeline activation owns tenant activation and production rollback observation. See
[pipeline-activation.md](pipeline-activation.md).

## Local runner limit

`trace-commons-pipeline-local` remains a local test process. Its readiness
response lists static authentication and synthetic adapters as blockers.

The local lab catalog also records these blockers. A local corpus report
cannot serve as production evidence.
