# Pipeline activation and migration

Pipeline activation routes the qualified pipeline for new submissions. Retained
legacy records stay readable. The switch assigns each receipt to one
implementation.

The pipeline now has these properties:

- A receipt ownership record selects the legacy executor or the pipeline.
- A retry of a pre-switch receipt returns the original operation.
- It does not start a new pipeline run.
- Unique ledger source keys prevent both paths from awarding the same receipt.
- Tenant routing is an explicit record. Timestamps do not select the bundle.
- Activation and expansion require current drills, readiness, corpus
  evidence, credit reconciliation, index checks, and invalidation checks.
- Rollback selects an earlier qualified bundle for later runs only.
- An unsafe bound policy must be suspended. The run keeps its package.
- First-rollout containment stops new pipeline receipts. Workers and
  packages remain available.
- Legacy writers disable only after their pending owned work completes.
- Destructive schema cleanup is not part of this change.
- Work-age readiness includes only `pending`, `retry`, and `leased` work.
- Completed work and terminal failed history do not block activation.

## Production receipt route

`POST /v1/traces` reads the tenant and actor from authenticated request data.
The envelope tenant field does not select the owner.

The handler records one owner before either writer continues. An exact retry
uses the stored owner. Reuse with different request bytes returns `409`.

The ingest process must have the production pipeline runtime before a tenant
uses pipeline routing. If the runtime is absent, the handler returns `503`.

Containment returns `503` for a new receipt. Existing runs keep their bound
package and remain available to workers.

## Rehearse the switch

Set `TRACE_COMMONS_PG_TEST_DATABASE_URL` to a PostgreSQL test database.
Then run this command:

```bash
cargo test -p trace-commons-server --test versioned_pipeline_runtime_pg pipeline_activation
```

The tests cover mixed legacy and pipeline records, exact replay of a
pre-switch receipt, unique ledger sources, tenant expansion gates,
rollback, containment, suspension instead of rebinding, and writer
retirement after pending work completes.

The ingest binary test covers concurrent first receipt, exact replay, changed
content, and one stored owner on the real `POST /v1/traces` handler.

The [local pipeline lab](pipeline-lab.md) `qualify` command runs this suite as part of pipeline qualification. Lab corpus and package evidence remains in local files;
these PostgreSQL integration tests remain separate schema and recovery checks.

## Local operator routes

`trace-commons-pipeline-local` adds these routes:

- `POST /v1/pipeline/switched-submissions`
- `GET /v1/admin/pipeline-routing`
- `POST /v1/admin/pipeline-contain`
- `POST /v1/admin/pipeline-retire-legacy-writer`

The local switched route is an operator rehearsal surface. Production clients
use `POST /v1/traces`.

## Current completion

The redesign is complete for the contracts that are not deferred.
`SCR-005` remains deferred until the external valuation protocol exists.
New valuation rules use a later bundle through the same qualification and
activation process.
