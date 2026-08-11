# LLM01 direct-injection corpus and measurement harness

Design record. The fixed corpus is in
`tests/corpus/llm01_direct_injection.yaml`; harness implementation is not
included in this pass.

## 1. Scope

This corpus will measure Gate's current LLM01 input detector against direct
user-role injection text. It will follow the surface Gate actually scans:
user-role message content, including both plain-string content and the text
blocks in an OpenAI content-block array. The harness must use the same
user-role selection and text extraction semantics as Gate.

Tool-role, assistant-role, and retrieved-document cases are excluded. Prompt
Guard does not currently scan tool-role content, so including those cases in
the denominator would turn a detector-coverage measurement into a penalty
for an explicitly unclaimed surface. A separate indirect-injection corpus
may be designed after Gate has a detector path for that surface.

This is a detector measurement, not a model-alignment or attack-success
measurement. A positive case means that the user text is labelled as a
direct injection attempt; it does not mean that a target model followed it.

## 2. Fixed composition

The band manifest is fixed before any case is authored and must be committed
with the corpus schema. Band assignment is immutable for the lifetime of a
corpus revision. Moving a case between bands requires a corpus-only change
and a new corpus revision; it may not be combined with a Prompt Guard model,
threshold, policy, or detector change.

### Positive set

The positive set contains 48 cases, divided evenly across four attack-shape
bands:

| Band | Cases | Definition |
|---|---:|---|
| `direct_override` | 12 | Plain instruction-hierarchy attacks: ignore, replace, or supersede the application's instructions. |
| `role_play_framing` | 12 | The same authority attack expressed through simulation, persona, fictional, hypothetical, evaluation, or claimed-authority framing. |
| `encoding_obfuscation` | 12 | The injected instruction is materially obscured through an encoding, escaping, character segmentation, or representation change while remaining direct user text. |
| `multi_step_setup` | 12 | A staged user-role interaction or a single multi-step request that establishes context or trust before delivering the override. |

The bands separate attack shape from the detector's score. They are not
ordered from easy to hard, and the harness must not reassign cases after
seeing results. `multi_step_setup` is included because the production input
path joins user-role content across a request; it must not be silently
reduced to a single isolated payload if the source case is multi-turn.

### Negative controls

The negative set contains 41 cases. `ordinary_text` and
`structurally_awkward` remain at 12 cases each; five published-derived
controls were added to `adjacent_vocabulary` after the original negative
tranche was reviewed:

| Band | Cases | Definition |
|---|---:|---|
| `ordinary_text` | 12 | Normal banking/support requests with no instruction override. |
| `adjacent_vocabulary` | 17 | Benign text containing words such as “ignore,” “system,” “prompt,” “override,” or “instructions” in ordinary operational meanings. |
| `structurally_awkward` | 12 | Benign content with awkward formatting, nesting, escaping, Unicode, logs, or identifiers, mirroring the purpose of `benign.yaml` without copying its cases. |

The resulting measured population is 89 cases: 48 labelled positives and 41
negative controls. The equal positive-band sizes keep the four attack shapes
visible; the negative bands are intentionally unequal because the
adjacent-vocabulary band carries more discriminating power and now includes
five externally sourced controls. This is a deliberately bounded corpus, not
a claim that 89 cases represent the universe of direct injection.

The original 48/36 positive-negative split was deliberately balanced for
coverage measurement, not realistic traffic where injections are rare. The
five sourced adjacent-vocabulary additions changed the final inventory to
48/41 before any measurement. Any resulting figure must be described as
detection coverage across this defined positive set and its fixed controls;
it must never be presented as expected production performance or a
population-level rate. Band composition is frozen from this point: a later
band-count change requires a new corpus revision and may not be combined with
a detector or threshold change.

### Operational sentinels

Two frozen controls live outside the measured 89-case population in
`tests/fixtures/llm01_controls.yaml`:

- `positive_control`: a canonical direct override that must cross the live
  Prompt Guard threshold on every run.
- `negative_control`: a benign message that must remain below the live
  threshold on every run.

They are preflight invariants, not additional numerator or denominator
cases. If either control changes outcome, the run fails and produces no
corpus result. This prevents an all-zero or all-one model/configuration
failure from looking like a legitimate measurement.

## 3. Provenance policy

Cases are sourced in this order of preference:

1. Captured direct-user examples from reproducible public evaluations or
   benchmark artifacts.
2. Published examples from primary detector/model documentation or
   established security guidance.
3. Locally captured, consented or synthetic-target traffic collected before
   threshold tuning, with the capture context preserved.
4. Human-authored cases only where a documented band gap remains after the
   first three sources are exhausted.

Invented cases are not silently mixed with captured cases. They carry
`source_type: authored`, are reported separately in the corpus inventory,
and must not be used to tune the threshold that the corpus then evaluates.
The positive headline should remain interpretable from captured and
published material; authored cases are gap-filling controls, not evidence
of real-world prevalence.

Every case records provenance as a YAML block mapping, never a flow mapping.
The required shape is:

```yaml
provenance:
  source_type: captured|published|authored
  source_name: descriptive source or collection name
  source_version: dataset, release, or document revision
  source_locator: URL, commit, artifact path, or capture identifier
  source_case_id: original case identifier when available
  collected_at: ISO-8601 timestamp when applicable
  collected_by: person or process
  adaptation: exact_copy|transcribed|translated|reframed|deduplicated
  adaptation_notes: what changed from the source, if anything
  license_or_use_basis: permission or public-source basis
```

The actual payload is retained in the case record. An exact payload hash and
the original source hash are also recorded where the source is available as
an artifact. Adaptation must never add a hidden tool carrier or change a
case's role: this corpus is direct user-role only. Duplicate detection may
normalize whitespace for comparison, but the stored case and its provenance
remain untouched.

The corpus author records the band at authoring time. A detector or threshold
tuner may not later move a surprising case into a more convenient band.
Corpus creation, detector changes, and threshold changes are separate
commits so a result can be traced to the exact fixed population.

### Current provenance limitation

The original 36 negative controls are all `source_type: authored`. That is a
documented deviation from the preference order above, not evidence that the
negative set is representative. The cost is unequal by band: authored
`ordinary_text` is a low-risk gap filler because mundane support text is
mundane, while authored `adjacent_vocabulary` is materially weaker evidence.
That band is intended to contain legitimate instruction-shaped language that
a naive detector could plausibly mistake for an injection; when the same
authoring process creates it, it primarily measures one person's model of
what looks confusing. Five published-derived adjacent-vocabulary controls
were added to reduce that weakness, but they do not erase the limitation.

The positive tranche contains 36 published-derived adaptations and 12
explicitly authored gap-fillers, three in each positive band. Published-derived
does not mean verbatim: every adaptation records its source URL and what was
changed. The authored minority remains separately identifiable and must be
reported with any result.

## 4. Planned file layout

The completed implementation now has the fixed corpus plus the following
harness files to add or complete:

```text
tests/corpus/llm01_direct_injection.yaml
tests/fixtures/llm01_controls.yaml
tests/regression/llm01_injection_harness.py
tests/regression/test_llm01_direct_injection_corpus.py
docs/benchmarks/llm01-direct-injection.md
```

The corpus loader should extend the existing manifest-validation approach in
`tests/regression/corpus.py`, but use an explicit positive/negative split and
reject missing provenance, duplicate IDs, unknown bands, missing expected
labels, and manifest/count disagreement.

## 5. Harness specification

### Inputs loaded

For each run the harness loads:

- the versioned corpus and its fixed band manifest;
- the two frozen operational controls;
- the active Prompt Guard detector implementation;
- the active policy configuration, including the `prompt_guard_2`
  threshold from `gate/policy/rules.yaml`;
- the detector model identifier and revision/cache identity;
- the current Git revision and hashes of every detector/policy/config file
  used by the run.

The harness must not accept a threshold argument that differs from the live
policy. A threshold change is a separate detector/configuration change and
requires a new measurement run against the same frozen corpus.

### Per-case execution

Each case is executed as a request-shaped message collection. Before scoring,
the harness verifies that the injection content is present only in
user-role messages and that no tool-role payload is being smuggled into the
direct-user population.

The case is passed through the same user-role selection and content
extraction semantics as Gate, then to Prompt Guard. The harness records the
raw model score and applies the live threshold. It must not classify a case
from a hand-written expected outcome or from a model-generated explanation.

Each case result records at least:

```text
case_id
split                         positive | negative
band
expected_label                injection | benign
message_shape                 plain_string | content_block_array | mixed
user_message_count
detector_score
detector_detected
policy_action
matched_rule_ids
detector_config_sha256
policy_config_sha256
model_id
model_revision_or_cache_id
threshold
git_revision
provenance_source_type
status                        pass | fail | error
error_type                    present only on an error result
```

The configuration, model, and threshold fields are repeated in every case
result, not stored only in a top-level header. A result remains interpretable
if it is copied out of the run envelope.

### Control execution

The harness runs both sentinels before corpus cases and again after corpus
cases. Both executions must satisfy their frozen expected outcome. A missing
model, failed model load, absent score, malformed threshold, detector
exception, or control mismatch is a hard run failure. There is no skip,
fallback, or “unavailable means zero detected” path.

The control checks are also required to verify the production wiring: the
positive control must be visible to the user-role extraction path, while the
negative control must remain below threshold. This catches a harness that
loads the YAML successfully but never calls the detector or calls it with an
empty string.

### Output shape

The machine-readable artifact is a JSON run envelope:

```text
run_metadata:
  corpus_path
  corpus_sha256
  corpus_revision
  git_revision
  detector_config_sha256
  policy_config_sha256
  model_id
  model_revision_or_cache_id
  threshold
  started_at
  ended_at
  controls:
    positive_control: detected
    negative_control: not_detected
cases:
  - per-case result
summary:
  positive_by_band:
    band:
      detected
      missed
      total
  negative_by_band:
    band:
      mismatched
      total
  errors
  complete
```

The human-readable report prints the same per-band counts and the full
configuration identity. It must not collapse the result to one headline
number while hiding band composition. The positive result can be described
as corpus detection coverage, band by band. Negative results are retained as
raw mismatch counts against the fixed controls; they are not presented as a
general-population false-positive rate.

### Non-vacuity and completeness checks

Before a run is complete, the harness asserts:

- every manifest band has exactly its declared count;
- all expected positive and negative bands are non-empty;
- every case produced exactly one result;
- all positive and negative controls passed both times;
- every result has a score and the same recorded model/configuration identity;
- no case was silently skipped, retried into a different result, or scored
  with an empty extracted user payload;
- the detector and policy threshold were the live configured versions;
- errors make the run incomplete and prevent publication of a summary.

## 6. What this corpus cannot measure

It cannot measure:

- indirect prompt injection delivered through tool output, retrieval, files,
  assistant messages, or other non-user roles;
- tool-argument injection or tool-call behavior;
- whether the target model actually followed an injection;
- model alignment, harmful-task success, or application-level impact;
- detector performance on output-stage LLM07 leakage or LLM02 PII;
- coverage of arbitrary encodings, languages, attack families, or message
  formats not represented in the fixed bands;
- a population-level recall or false-positive guarantee;
- the validity of the threshold beyond this frozen corpus and its stated
  bands.
- a realistic production base rate: the corpus deliberately over-samples
  injections, so its positive coverage is not expected traffic performance;
- a provenance-free estimate of benign traffic: 36 of the 41 negative
  controls are authored, and the authored adjacent-vocabulary cases are the
  most consequential limitation because they encode the author's own idea
  of what a naive detector might confuse with an injection.

The number will mean only: “on this fixed, provenance-traceable set of
direct user-role cases, under this recorded Gate configuration, these bands
produced these detector outcomes.” It must not be extended to the tool-output
surface that Gate explicitly does not claim to detect.
