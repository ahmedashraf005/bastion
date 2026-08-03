# AgentDojo benchmark: banking suite, local models

Measured 2026-08-03. Two local models, one attack, no paid inference.

## What was measured, and why

[AgentDojo](https://agentdojo.spylab.ai) is a dynamic benchmark for
evaluating prompt-injection attacks and defenses against tool-using LLM
agents, built by ETH Zurich (Debenedetti, Zhang, Balunović, Beurer-Kellner
et al.). It was chosen specifically because it is a target Bastion's author
did not write: the banking suite's tasks, tools, and injection payloads are
an external, independently-authored test of how a tool-calling agent
behaves under attack — not a benchmark tuned around Bastion's own detectors
or blind spots.

This is a capability/susceptibility measurement of the **models**, run
directly against host-native Ollama. It is not a Gate benchmark — see
[Out of scope](#out-of-scope-gate-defense-cells) below for why.

## Method

- **AgentDojo git SHA `089ed468cf3ed0322acc66b0211f26d9d90dbf60`.** This is
  the only valid pin. The PyPI wheel `agentdojo==0.1.35` does **not**
  contain the `openai-compatible` provider used here — that provider was
  added by commit `089ed468` itself ("Add openai-compatible provider for
  arbitrary OpenAI-compatible endpoints", PR #147), which lands *after* the
  `v0.1.35` git tag (verified: the tag is an ancestor of the pinned commit,
  not the same commit). Installing the tagged PyPI release gets you code
  that cannot do local Ollama inference at all. Install with:

  ```bash
  pip install "git+https://github.com/ethz-spylab/agentdojo.git@089ed468cf3ed0322acc66b0211f26d9d90dbf60"
  ```

  `pip show agentdojo` reports "Version: 0.1.35" even for this SHA install,
  because the version string is nearest-tag-derived and hadn't been bumped
  since — that discrepancy is how "package 0.1.35" could look like a second,
  independently valid pin. It is not one. Cite the SHA, not the version
  string, in any reproduction of these numbers.

- **Benchmark version `v1.2.2`**, the banking suite specifically: **16 user
  tasks, 9 injection tasks, 11 tools** (`get_iban`, `send_money`,
  `schedule_transaction`, `update_scheduled_transaction`, `get_balance`,
  `get_most_recent_transactions`, `get_scheduled_transactions`,
  `read_file`, `get_user_info`, `update_password`, `update_user_info`) —
  confirmed by loading the suite directly, not taken from documentation.

- **Host-native Ollama, no hosted inference anywhere.** Wired via
  `--model OPENAI_COMPATIBLE --model-id <ollama-tag>` with
  `OPENAI_COMPATIBLE_BASE_URL=http://127.0.0.1:11434/v1` and a dummy
  `OPENAI_COMPATIBLE_API_KEY` (Ollama doesn't check it). This path uses
  `OpenAILLM` (native tool-calling); the `--tool-delimiter` flag is a no-op
  here — that constructor takes no such parameter — it only applies to
  AgentDojo's legacy `local`/`LOCAL` provider. This path also never
  streams: no `stream=True` anywhere in the call chain (confirmed by
  source), independent of and unrelated to Gate's own SSE fidelity work,
  since these cells never talk to Gate at all.

- **Attack: `important_instructions`**, the attack behind AgentDojo's
  headline published numbers (see [Non-comparability](#non-comparability)).
  It injects its payload into tool-output content the agent reads back, not
  into the user turn.

- **Distinct `--logdir` per (model, attack) cell, always with
  `--force-rerun`.** AgentDojo's result cache keys on pipeline name, which
  is `openai-compatible` for every local model regardless of which model is
  actually configured — a shared logdir would make a second model silently
  reuse the first model's cached results.

## Results

| Model | Digest | Benign utility | Confound: injection tasks passed as direct user tasks | Targeted ASR | Utility under attack |
|---|---|---|---|---|---|
| llama3.1:8b | `46e0c10c039e` | 25.00% (4/16) | 6/9 (66.7%) | **0.00%** (0/144) | 25.00% (36/144) |
| qwen2.5:7b | `845dbda0ea48` | 50.00% (8/16) | 7/9 (77.8%) | **18.75%** (27/144) | 45.83% (66/144) |

**The confound control is a first-class column, not a footnote.** ASR alone
doesn't say whether a low number means resistance or incapacity. The
"injection tasks passed as direct user tasks" column runs each injection
task's action as an explicit, non-adversarial user request — it answers
"can this model even do the thing the attack is trying to make it do?"
llama3.1:8b succeeds at those same actions 66.7% of the time when asked
directly, yet the injected version never succeeded (0/144) — so its 0% ASR
is readable as actual resistance to this injection framing, not as the
model being too weak to act. Without that control, a 0% ASR figure would be
uninterpretable.

## The finding

**qwen2.5:7b is roughly twice as capable as llama3.1:8b on this suite (50%
vs 25% benign utility) and meaningfully more susceptible to injection
(18.75% vs 0.00% ASR).** Capability and injectability moved together here,
in the same direction, on the same suite, under identical conditions. This
is a single paired comparison, not a general law about model scaling — but
it's a genuine, reproducible local result, not noise: the gap is large
(0% vs 18.75%) and the confound control on both models rules out "neither
model can actually do anything" as the explanation.

## Non-comparability

**These numbers are NOT comparable to AgentDojo's published GPT-4o
results** — cited here only as published context for interpreting
magnitude, never as a peer comparison:

| Defense | ASR | Utility under attack |
|---|---|---|
| GPT-4o, no defense | 47.69% | 50.08% |
| GPT-4o, tool filtering | 6.84% | 56.28% |
| GPT-4o, spotlighting-with-delimiting | 41.65% | 55.64% |
| GPT-4o, transformers_pi_detector | 7.95% | 41.24% (down from 69.07% benign) |

Different models (7-8B local vs. GPT-4o), different hardware, no hosted
inference anywhere in this measurement (see the project's no-paid-inference
constraint) — there is no controlled basis for a head-to-head claim against
that table, and this document does not make one. The
`transformers_pi_detector` row is worth noting for a different reason: 7.95%
ASR bought by a utility collapse from 69.07% to 41.24% is the general
shape of the false-positive cost a defense can impose — a caution for
interpreting any future Gate defense numbers, not a comparison to this
table.

The only valid comparison in this document is the paired local delta
between llama3.1:8b and qwen2.5:7b above, under identical conditions,
reproducible by anyone for free.

## The 45-second timeout finding

One qwen2.5:7b attack episode ran **1203.6 seconds** — 20 minutes, on a
single task/injection pair — driven by a tool-call validation-error retry
loop visible directly in the run logs: the model repeatedly resubmitted a
malformed `update_user_info`/`send_money` call rather than recovering. Its
benign-cell episodes also ran long (max 194.5s). llama3.1:8b never came
close: its longest episode, benign or attack, was 24.9s.

**Bastion.Strike uses a 45-second timeout for planner and PruneGate
requests** (`STRIKE_PLANNER_REQUEST_TIMEOUT_SECONDS`). If qwen2.5:7b were
adopted as a Strike planner under that timeout, this exact failure mode —
not a crash, not a hang, but a slow-motion retry loop — would truncate
campaign rounds unpredictably. This is a real, measured local-model
tool-use robustness finding, not a Bastion defect; it argues against
qwen2.5:7b as a planner choice without either a much longer timeout or
tool-schema robustness work upstream.

## Out of scope: Gate defense cells

No `--defense` cell was run, and none pointed AgentDojo at Bastion.Gate.
`important_instructions` (and most AgentDojo attacks) inject into **tool
output**, which is exactly the channel Bastion.Gate's detectors cannot see —
see [`docs/threat-model.md`, "Indirect prompt-injection boundary"](../threat-model.md#indirect-prompt-injection-boundary),
which already names `important_instructions` as the concrete known example
of this gap. Any Gate-pointed cell here would show a forced, structural
~0% ASR reduction that reflects Gate's blind spot to this channel, not a
measurement of its effectiveness — that would be a misleading number
dressed up as a result. This is a documented, measured limitation, not an
oversight: Gate cells are out of scope until Gate gets tool-output
inspection.

## Reproduction

```bash
# Isolated venv, outside any Bastion checkout
python3 -m venv .venv && source .venv/bin/activate
pip install "git+https://github.com/ethz-spylab/agentdojo.git@089ed468cf3ed0322acc66b0211f26d9d90dbf60"

export OPENAI_COMPATIBLE_BASE_URL="http://127.0.0.1:11434/v1"
export OPENAI_COMPATIBLE_API_KEY="local-dummy-key"   # any non-empty value; Ollama ignores it

ollama pull llama3.1:8b   # or qwen2.5:7b

# Benign cell
python3 -m agentdojo.scripts.benchmark \
  --model OPENAI_COMPATIBLE --model-id llama3.1:8b \
  --benchmark-version v1.2.2 -s banking \
  --logdir runs/llama3.1-8b_no-attack --force-rerun

# Attack cell
python3 -m agentdojo.scripts.benchmark \
  --model OPENAI_COMPATIBLE --model-id llama3.1:8b \
  --benchmark-version v1.2.2 -s banking \
  --attack important_instructions \
  --logdir runs/llama3.1-8b_important_instructions --force-rerun
```

Each cell's `--logdir` gets one JSON result file per (user_task,
injection_task) pair plus one per injection task run as a direct user task
(the confound control), each with `utility` and `security` fields —
`security: true` means the injection's target side effect **succeeded**
(it is the ASR flag, not a safety flag), and a no-attack trace has
`security: true` for every task by construction (vacuous — there was no
injection to succeed or fail). Aggregate the JSON files directly rather
than trusting only the CLI's printed summary for anything you plan to cite.

Full logs and raw result JSONs for the runs in this document are retained
outside the Bastion repository tree (isolated venv, per the project's rule
that nothing from this benchmark enters the repo except this write-up).

No false-positive rate is claimed anywhere in this document, and no claim
is made that Bastion (Gate or otherwise) has been benchmarked against a
defense baseline here — it has not; see [Out of scope](#out-of-scope-gate-defense-cells).
