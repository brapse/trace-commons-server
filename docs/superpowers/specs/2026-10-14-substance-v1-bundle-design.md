# Substance v1 bundle: design

Status: design, 2026-10-14. Not implemented.

Owner decisions, 2026-10-14:

- **D1 Replace perplexity, do not patch it.** Perplexity is a bad metric. The
  new metric is called substance. It is one number per trace.
- **D2 Model-free v1.** Substance v1 is a pure function of the envelope. No
  scorer model, no GPU, no remote call. A model-backed term is a later version.
- **D3 `q` stays the economic seam.** Credit quality `q` keeps its four
  consumers. Its inputs change from (perplexity, peak, novelty) to (substance,
  novelty) under a new calibration era, label `cq4`.
- **D4 No database changes.** The bundle stores its values in the pipeline
  Score evidence. The substance family never writes the legacy
  `trace_gate_decisions` row.
- **D5 Novelty stays as it is.** The bundle replaces the quality half of the
  compatibility Score policy only.
- **D6 Offline evaluation on pinned datasets.** A generator writes a fixed,
  digest-checked benchmark dataset once. Evaluation reads that file. Shadow
  scoring in production is not the acceptance path.
- **D7 The substance floor comes from calibration**, not from a guess.
- **D8 Stages 1 and 2 are this effort.** Stage 3, the retirement of the
  perplexity path, waits until the substance bundle is active on every tenant.

## 1. Why

The docs define the substance gate as "is this real work rather than
template-shaped filler" (`docs/trace-commons.md:8`). The implementation is
model surprise: a `PerplexityScorer` returns aggregate and tail perplexity,
and a floor passes the trace when surprise is high enough. The tree holds the
evidence that surprise is not value:

- Twenty operator sessions, per-author shadow spec (2026-09-18): twelve fell
  below the floor, including the three a judge rated hardest. Short,
  low-substance sessions scored highest. Correlation with length was -0.49.
- Scaffold dilution: 8,516 of 10,533 `tool_result` events and all 2,017
  `tool_call` events in that sample carried no content. Each adds one
  predictable line, so real work dilutes its own score.
- The 27B re-score (2026-07-12) peaked at 1642M micros, forty times the p90,
  on encoded content. Random bytes earn the top score; routine correct work
  earns a low one.
- The red team (2026-07-12) showed perplexity and novelty fail in the same
  direction, and a monotone score hands an attacker a gradient. The concave
  transforms in `q` cap the damage; they do not remove the gradient.
- The envelope carries `task_success`, `human_correction`, per-event
  `success`, `failure_modes`, tool arguments and results, and replay fields.
  Issue #199 confirmed that nothing in the scoring path reads them.
- The classifier audit (2026-08-24) showed that no version binds the renderer,
  the floors, and the evidence, so a better metric was indistinguishable from
  a worse one.

The owner's notes add the product intent: award traces that represent work we
have not seen before. Novelty owns "not seen before". Substance owns "work".
The witness proves only that the last model call was real, so every other
turn can be fabricated, and a substance classifier is still required.

## 2. What economic value means here

A trace is worth money when a trainer can learn from it. Four properties of
the envelope say whether that is likely:

| Property | Question | Envelope source |
|---|---|---|
| Work | Did the agent act in a real environment? | `tool_call` arguments, `tool_result` content, tool diversity, side effects |
| Outcome | Does the trace say how it ended, and is a failure explained? | `outcome.task_success`, `outcome.human_correction`, `outcome.user_feedback` |
| Density | Is the agent's own text content, not filler and not noise? | compression ratio of `assistant_message` and `reasoning` content |
| Replay | Can a consumer rebuild the trajectory? | `replay_sufficiency` (protocol crate) |

Scarcity is the fifth property. Novelty owns it. Substance does not measure it.

## 3. The substance function

All arithmetic is in fixed-point micros, like `credit_quality`. Every constant
below lives in the bundle configuration and is hashed into the bundle id.
Every term saturates, so no term offers an unbounded gradient.

`sat(x, ceil) = ln(1 + x) / ln(1 + ceil)`, clamped to [0, 1]. This is the
`saturating_term` curve of `credit_quality.rs`, with the floor at 0.

`graded(v, m) = m + (1 - m) · v`. This is `graded_floor` from the same module.

### 3.1 Work

From the event list:

- `paired_calls`: `tool_call` events that carry arguments (the same detection
  as `replay_sufficiency`: an object under `arguments`, `args`, `parameters`,
  `params`, or `input`) and that have a matching `tool_result` with non-empty
  `redacted_content` or `structured_payload`. The match is by `tool_call_id`,
  else by the result's `parent_event_id`. Calls are counted distinct by
  (`tool_name`, canonical JSON of the arguments): the same call issued twice
  is one unit of work, so a repeated loop earns nothing extra.
- `distinct_tools`: distinct `tool_name` values over the paired calls.
- `write_actions`: events whose `side_effect` is `local_write` or
  `external_write`.

```
work = 0.5 · sat(paired_calls, work_calls_ceil)
     + 0.25 · sat(distinct_tools, work_tools_ceil)
     + 0.25 · sat(write_actions, work_writes_ceil)
work = graded(work, work_floor_mult)
```

Defaults before calibration: `work_calls_ceil = 20`, `work_tools_ceil = 5`,
`work_writes_ceil = 5`, `work_floor_mult = 0`. With the default, a trace with
no paired call has `work = 0`, and substance is 0. A pure conversation with
no tool use earns no substance in v1; the knob exists so calibration can give
such traces a small floor if the dataset shows they carry value.

### 3.2 Outcome

From `outcome`:

| `task_success` | `human_correction` present | outcome |
|---|---|---|
| `success` | any | `outcome_success` (default 1.0) |
| `partial` | any | `outcome_partial` (default 0.6) |
| `failure` | yes | `outcome_corrected_failure` (default 1.0) |
| `failure` | no | `outcome_failure` (default 0.3) |
| `unknown` | yes | `outcome_corrected_failure` |
| `unknown` | no | `outcome_unknown` (default 0.5) |

`user_feedback = thumbs_down` with no correction multiplies by
`outcome_thumbs_down_mult` (default 0.8). `correction` as feedback counts as a
correction present.

A corrected failure scores as high as a success on purpose. A failure that a
person explained is premium training data, not filler. Every outcome value is
above zero, so this term grades and never gates. All of its inputs are
client-asserted; section 7 explains why that is safe.

### 3.3 Density

Concatenate the `redacted_content` of every `assistant_message` and
`reasoning` event, in event order, as UTF-8 bytes. This is the agent-prose
split that the per-author attribution already defines; `tool_result` content
and `user_message` content are excluded, because the agent did not write
them.

`ratio = deflate_len / raw_len`, with DEFLATE at a fixed level through the
`flate2` crate. The compressor and its level are part of `substance_version`.

```
density = 1                                   if lo <= ratio <= hi
        = (ratio - (lo - ramp)) / ramp         if lo - ramp < ratio < lo
        = ((hi + ramp) - ratio) / ramp         if hi < ratio < hi + ramp
        = 0                                    otherwise
```

Defaults before calibration: `density_lo = 0.15`, `density_hi = 0.70`,
`density_ramp = 0.10`, `density_min_bytes = 256`. Under `density_min_bytes`
the term is 0: no agent prose means no measurable substance.

The band is two-sided on purpose. Template filler compresses too well and
falls under `lo`. Base64 or random content does not compress and rises over
`hi`. Perplexity had only one side.

### 3.4 Replay

`replay = ReplaySufficiency::score()` from
`trace_commons_protocol::trace_contribution::replay_sufficiency`: equal thirds
for an initial prompt with content, arguments on calls, and results with
content, with partial coverage earning partial credit. The envelope's
`replayable = false` veto zeroes it, as today.

`replay = graded(replay, replay_floor_mult)`, default `replay_floor_mult =
0.5`. Replay grades; it does not gate.

### 3.5 Composite and gate

```
substance = work · density · outcome · replay          in [0, 1]
substance_passed = substance_micros >= substance_floor_micros
```

Work and density can zero the composite. Outcome and replay cannot. That is
the design: the two anti-filler terms gate, the two value-grading terms rank.

`substance_floor_micros` has no default. Calibration sets it (section 6.5).
A bundle configuration without it is refused with
`substance_floor_unset`.

### 3.6 Version

`substance_version = "substance.v1+deflate6"`. Any change to a formula, a
field mapping, the compressor, or the agent-prose split bumps the version.
Constants do not bump the version; they are in the bundle configuration and
change the bundle id.

## 4. Credit quality `cq4`

`credit_quality.rs` gains a second function beside `credit_quality`:

```
credit_quality_v4(substance_micros, nov_rep_micros, k) -> CreditQualityScore
  h = graded(sat_term(substance, k.sub_floor, k.sub_ceil), k.sub_floor_mult)
  g = graded(sat_term(novelty,   k.nov_floor, k.nov_ceil), k.nov_floor_mult)
  q = clamp01(h · g)
```

`CREDIT_QUALITY_CONSTANTS_V4`: `sub_floor_micros = substance_floor_micros`
(the same value as the gate), `sub_ceil_micros = 1_000_000`, novelty values
from V3, `version: 4`. There is no anomaly term; it existed to catch one
inserted garbage chunk under perplexity, and the density band covers that
case.

The substance bundle pins `credit_quality_version = 4` in its configuration.
It does not call `constants_at(now)`; the bundle closes over its decision
function, which is the classifier-audit principle. `CREDIT_QUALITY_SCHEDULE`
is unchanged: it is the legacy path's time-based schedule, and the legacy path
keeps scoring with it.

`anomaly_ratio_micros` is reported as 1_000_000 and `anomaly_withheld` as
false, so `CreditQualityScore` keeps its shape.

The public label is `cq4`. The account-trust rule allowlist and the
credit-estimate table add it (Stage 2).

## 5. The bundle

### 5.1 Family and ids

A new family `substance`, implementation ids
`trace_commons.{admission,review,score,settle}.substance.v1`, rule id
`substance_novelty_v1`. Admission, Review, and Settle reuse the compatibility
structs unchanged; only Score is new.

### 5.2 Configuration

`SubstanceBundleConfig` in a new module
`crates/trace-commons-server/src/versioned_pipeline_substance.rs` (AGPL
header), `deny_unknown_fields`:

- The novelty half, copied from `CompatibilityBundleConfig`: `projection_id`,
  `index_id`, `novelty_floor_micros`, `embed_insert_novelty_micros`, `top_k`,
  the four chunk knobs, `novelty_utility_microcredits`, the instrument.
- The substance constants of section 3.
- `substance_floor_micros`, `credit_quality_version` (must be 4).
- `render_version` and `chunker_version` (section 5.6).

No `scorer_model_id`, no perplexity floor, no tail floor.

### 5.3 Score policy

`SubstanceScorePolicy::evaluate`, in order:

1. Deserialize `reviewed_artifact` as `TraceContributionEnvelope`. A parse
   failure is the permanent `substance_envelope_unreadable`.
2. Compute the four terms, the composite, and `substance_passed`.
3. Chunk the envelope with the production chunker, embed each chunk, query
   the index, and aggregate novelty. This is the compatibility code path,
   moved behind a shared function so the two policies call one
   implementation.
4. `q = credit_quality_v4(substance, novelty)`.
5. Index membership and the award follow the compatibility rule with
   `substance_passed` in place of `quality_passed`.
6. Fill the evidence.

Step 3 keeps the Score lock and the `UnappliedIndexCommandsReader`; both
protect index consistency and apply to any family that writes the index. The
runtime check at `versioned_pipeline.rs:13089` becomes "the family writes the
index", not "the family is compatibility".

### 5.4 Evidence

Seven flat `Option` fields on `ScoreEvidence`, `ScoreEvidenceFields`, the
`TryFrom`, and `fixed()`, each with `serde(default, skip_serializing_if)`:

```
substance_micros, substance_passed, substance_version,
substance_work_micros, substance_outcome_micros,
substance_density_micros, substance_replay_micros
```

`credit_quality_micros` and `credit_quality_version` are filled as today.
The perplexity fields stay `None`. Compatibility outcomes serialize
byte-identically, so stored hashes and the 10k comparison report do not move.

The loader drops a key the struct lacks. In a mixed-version rollout an old
binary reads a substance row and sees no substance fields. That is accepted:
the old binary also cannot run the substance family, so it never reads such a
row for a decision.

### 5.5 Runtime arms

- `from_package_with_runtime` gains a third arm for the substance id tuple.
  It needs no scorer; the signature drops nothing, because the compatibility
  arm still needs its scorer.
- `package_configuration_is_qualifiable` gains the family.
- `validate_production_package` accepts the substance id tuple.
- The compat-only branches at `versioned_pipeline.rs:13552` (legacy row
  check), `:13616` (duplicate verdict), and `:5785` (legacy row write) are
  not taken for the substance family. The duplicate verdict is a legacy-row
  consumer and returns with Stage 2 on the evidence path.
- `trace_credit_event` is `NoveltyUtility`, as for compatibility.
- `pipeline.py package --bundle substance` and the production assembly learn
  the family.

### 5.6 Chunker ownership of token counts, and versions

`aggregate_chunked_novelty(novelty, chunk_tokens, min_chunk_tokens)` takes
token counts that come from the perplexity scorer today. The chunker gains a
token estimate per planned chunk (its own whitespace-and-punctuation
tokenizer; the count is a guard, not a score), and both policies pass that.
Novelty no longer depends on a scorer.

`CANONICAL_RENDER_VERSION = "events.v1"` exists (`chunker.rs:329`) and the
legacy path hashes it. A `CHUNKER_VERSION` constant is added beside it. The
substance configuration carries both, so the bundle id changes when the text
a score sees changes. The compatibility bundle is not changed.

## 6. Evaluation

### 6.1 Principle

No ground truth of economic value exists. The score is therefore held to
contracts that a pinned dataset can test, and to one agreement report that
is not a gate until the data supports it.

### 6.2 The benchmark dataset

Format `trace_commons.substance_benchmark.v1`:

```json
{
  "schema": "trace_commons.substance_benchmark.v1",
  "recipe": "substance-benchmark-v1",
  "source": { "hf_pin_digest": "sha256:...", "seed": 42 },
  "envelopes": [ { "id": "...", "envelope": { ... } }, ... ],
  "pairs": [
    { "base": "...", "variant": "...", "transform": "append_noise",
      "expect": "variant_le_base" },
    ...
  ],
  "validity": { "measures": { ... }, "ceiling": 0.15, "passed": true }
}
```

`expect` is one of `variant_lt_base`, `variant_le_base`, `variant_eq_base`,
`variant_gt_base`. A fixture is committed under
`docs/superpowers/specs/fixtures/` with its digest in the file name's
companion `.digest`.

### 6.3 The generator

`pipeline.py dataset generate --recipe substance-benchmark-v1 --source <hf-pin>
--seed N --out <file>`. The generator is Rust (a subcommand of
`trace-commons-pipeline-corpus-export`, which already holds the pinned HF
loader and the envelope builder), and `pipeline.py` drives it. A Python
generator would be the fifth copy of the text extraction.

Base selection: the generator takes a base envelope only when it has at
least one paired tool call, at least 256 bytes of agent prose, and an
`outcome` block. These are structural checks; the generator never runs the
score. They keep every `lt` pair meaningful, because a base at substance 0
cannot be lowered.

Recipe `substance-benchmark-v1`, one variant per base envelope per transform:

| Transform | Change | `expect` | Perplexity today |
|---|---|---|---|
| `append_noise` | 4 KiB of base64 random bytes appended to the last assistant message | `variant_le_base` | rises |
| `add_scaffold` | 20 `tool_call` events with no arguments and no results | `variant_le_base` | falls |
| `strip_results` | every `tool_result` body removed | `variant_lt_base` | about equal |
| `truncate_half` | the second half of the events removed | `variant_le_base` | varies |
| `duplicate_events` | the event list repeated once | `variant_le_base` | about equal |
| `assert_success_no_work` | all tool events removed, `task_success = success` | `variant_lt_base` | varies |
| `correct_failure` | base: `task_success = failure`, no correction (a derived envelope, included in `envelopes`); variant: the same plus a `human_correction` | `variant_gt_base` | about equal |
| `template_filler` | every assistant message replaced by one fixed paragraph, repeated to the original byte length | `variant_lt_base` | falls |

`add_scaffold` and `truncate_half` are `le`, not `eq` or `lt`: scaffold
lowers replay coverage honestly (calls with no arguments cannot be seeded),
and a truncation that removes no tool call leaves work unchanged. The
contract is that neither can raise the score.

The last column is the baseline the substance bundle must beat; it is
reported, not assumed, by running the compatibility bundle on the same file.
In CI that column comes from the reference scorer, a byte-entropy proxy. The
production baseline column comes from the operator run with `--assembly
production`, which uses the NEAR AI scorer.

Before it writes, the generator runs the trivial-measure battery
(`corpus-validity`, extended with event count, tool-call count, and byte
count) over the base envelopes against the `pairs` labels. If any measure
predicts the expected ordering above the ceiling, the dataset is refused.
That is the #204 lesson as a contract.

### 6.4 The evaluation command

`pipeline.py evaluate --dataset <file> --bundle <family | package>
[--assembly reference | production]`. It:

1. Checks the dataset digest.
2. Builds the bundle through the harness assembly switch.
3. Runs the Score policy only, in-process, against an
   `IsolatedPipelineIndex` seeded with the base envelopes in file order, so
   novelty is defined and repeatable. No HTTP, no Admission, no Settle. The
   pairwise table reads `substance_micros` only; a variant's novelty against
   its own base is near zero by construction, and that is not what the
   table measures.
4. Writes per-trace records (every evidence field) to a records file as it
   goes, and resumes from that file when restarted.
5. Writes the report through `pipeline_tooling`: canonical digest, markdown,
   the hash-only `validate_evidence` check, optional `--archive` to the lab
   catalog.

The report holds:

- The pairwise table: per transform, the share of pairs that satisfy
  `expect`, with the term that moved most.
- The baseline-dominance table: for each trivial measure, its AUC against
  `substance_passed` and its Spearman correlation with `substance_micros`.
- Percentiles of `substance_micros` and of each term over the base
  envelopes, and the operating-point table: pass rate at each candidate
  floor.
- The outcome join, when the dataset has outcome labels: AUC of
  `substance_micros` against `task_success`, with the length covariate
  beside it (#199's two guards).

With the substance family and `--assembly reference`, the run needs no
model and no GPU; the reference and production assemblies are identical for
this family. The synthetic fixture runs in CI under `pipeline qualification
and restore`, in seconds.

### 6.5 Calibration

Calibration is one `evaluate` run on the pinned real corpus (the 10k HF pin
that the comparison already uses), followed by a choice:

- `substance_floor_micros`: the operating-point table gives the pass rate at
  each floor. The owner picks the floor from that table and records it in
  the bundle configuration. The report digest goes in the configuration's
  companion note, so the floor points at the evidence that set it.
- The density band and the ceilings: the percentile tables show where real
  prose sits. The defaults in section 3 are starting points; the run
  replaces them.

A change to any constant produces a new bundle id, a new `evaluate` run, and
a new qualification. There is no env var for a substance constant.

### 6.6 Acceptance

Substance v1 is accepted for qualification when, on the pinned benchmark:

1. Every transform row in the pairwise table is at or above 0.95 for the
   substance bundle. The compatibility bundle's rows are reported beside
   them; the rows it fails are the pathologies this design exists to remove.
2. No trivial measure exceeds the ceiling in the baseline-dominance table.
3. The novelty values are byte-identical to the compatibility bundle on the
   same file, because the novelty half is unchanged.
4. The outcome join is reported with the length covariate. It is not a gate
   until each class holds at least 125 traces, the #199 minimum.

A pass on the synthetic slice proves the metric avoids the known failures of
perplexity. It does not prove economic value. Only the outcome join can, and
the pilot has not produced that data yet. This limit is stated here so that a
synthetic pass is not sold as a value proof, which is what happened with the
A2.6 corpus.

## 7. Gaming

Every outcome and feedback field is client-asserted. The composite is
multiplicative, so an asserted success with no paired tool call earns
`work = 0` and substance 0. An asserted correction on a trace with real work
earns at most the outcome ceiling, 1.0, which a plain success also earns.

Work can be fabricated with an LLM call per trace, as perplexity could. The
cost is the same; the gain is bounded by saturation at `work_calls_ceil`.
Compressibility can be tuned, and that gains at most one term. The witness
proves the last model call; everything else is bounded, graded, and recorded
with its sub-terms, so an audit can see which term carried a suspicious
trace. Contributor caps and delayed settlement remain the economic defense.

## 8. Stage 2: the `q` consumers read the pipeline evidence

The substance family writes no legacy row (D4). Four consumers read `q`
from `trace_gate_decisions` today. Each moves to a read of the pipeline
Score evidence for pipeline-scored traces, keeping the legacy read for
legacy rows:

| Consumer | Today | Stage 2 |
|---|---|---|
| contributor points (`credit_points_from_quality_micros`) | legacy row | pipeline status already reads `evidence->>'credit_quality_micros'`; the points path uses the same read |
| contributor cap increment (`contributor_cap.rs`) | `list_gate_decisions_for_credit_scoring` | a union read over the legacy rows and the Score evidence |
| account-trust growth rule (`account_trust_rule.rs`) | `q` plus version allowlist | the same, with `cq4` allowed and the evidence read |
| credit-estimate fit (`credit_estimate_fit.rs`) | scores by submission | the same union read; label `cq4` |

The duplicate verdict, which is a legacy-row consumer today, moves with the
cap increment. The signed score attestation adds schema v3 with
`substance_micros` beside `credit_quality_micros`; v2 stays readable. The
public analytics gains a `substance_failed` label beside `perplexity_failed`.

The exact read paths are confirmed at plan time; the consumer sweep of
2026-10-14 is the inventory.

## 9. Non-goals

- A model-backed density term (per-author perplexity band or a judge). Later
  version, only if the pairwise table shows filler passing.
- Per-event `success` and `failure_modes` as terms. Sparse today; later.
- Any change to novelty, the embedder, the index, or the award amount.
- A rename or relaxation of any `trace_gate_decisions` column.
- Stage 3: removal of the perplexity driver, the rescore route, the 21 env
  names, and the `calibrate` and bake-off scoring loops.
- A two-bundle `pipeline.py compare`. `evaluate` on one file with two bundles
  covers the Score-stage comparison this design needs.

## 10. Components

| Component | Where |
|---|---|
| `SubstanceBundleConfig`, `SubstanceScorePolicy`, the four terms, `substance_version` | new `crates/trace-commons-server/src/versioned_pipeline_substance.rs` |
| shared novelty evaluation (moved out of `CompatibilityScorePolicy`) | `versioned_pipeline_compat.rs`, called by both policies |
| `credit_quality_v4`, `CREDIT_QUALITY_CONSTANTS_V4` | `credit_quality.rs` |
| seven evidence fields | `crates/trace-commons-gate-api/src/pipeline.rs` |
| chunk token estimate, `CHUNKER_VERSION` | `crates/trace-commons-gate-enclave/src/chunker.rs` |
| `substance_package()`, runtime arm, qualifiable family | `versioned_pipeline_bundle.rs` |
| production acceptance | `versioned_pipeline_qualification.rs` |
| family-generic runtime branches | `versioned_pipeline.rs` |
| benchmark format, generator, recipe | `trace-commons-pipeline-corpus-export` bin, new `substance_benchmark` module |
| `evaluate` driver, metrics, report | library module `versioned_pipeline_evaluation.rs` (dataset loader, pairwise and dominance metrics, records, report), driven by an `#[ignore]` test in a new `pipeline_evaluate_tests.rs` that `pipeline.py evaluate` runs, the same shape as `run` and `compare`; `pipeline_tooling/evaluate.py` |
| `pipeline.py dataset generate`, `pipeline.py evaluate`, `--bundle substance` | `scripts/operator/pipeline.py` |
| committed fixture | `docs/superpowers/specs/fixtures/substance-benchmark-v1.json` |
| runbook | `docs/operator/substance-evaluation.md`, listed in `docs/operator/README.md` |
| Stage 2 consumer reads | `contributor_cap.rs`, `account_trust_rule.rs`, `credit_estimate_fit.rs`, the points path, `trace_score_attestation.rs` |

## 11. Testing

- Golden tests: fixed envelopes with pinned term values and composite, per
  `substance_version`. A formula change breaks a pinned value and forces a
  version bump.
- Contract tests on the committed benchmark fixture, in CI: the pairwise
  table at 1.0 for the substance family on the fixture; the compatibility
  family under the reference scorer reported beside it.
- The existing compatibility baseline test
  (`compatibility_baseline_is_executable_and_detects_drift`) stays green,
  which proves the evidence change is byte-neutral for that family.
- Novelty byte-identity across the two families on one file.
- Qualification: `pipeline.py qualify` with `--bundle substance` passes the
  package checks and the corpus runs.
- Stage 2: each consumer has one test with a legacy row and one with a
  pipeline evidence row, both yielding the same consumer output for equal `q`.
