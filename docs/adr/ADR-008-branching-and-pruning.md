# ADR-008: Branching and pruning for adaptive campaigns

- Status: Accepted
- Date: 2026-07-22

## Context

ADR-007's single-candidate adaptive planner can respond to campaign history,
but a linear sequence limits tactical variety. In practice it cycled through
contextual framings of broadly similar requests instead of reliably trying the
output-formatting family that produced both confirmed prior findings: ASCII
separator formatting and Unicode-whitespace formatting of the canary marker.

## Decision

Strike adds a distinct `branching` attempt source. Each round generates a
batch of `b` candidates in one schema-constrained Ollama call. Its prompt
requires genuine diversity, including at least one candidate that asks for
unusual formatting, encoding, or presentation of a marker/configuration value
and at least one candidate that uses a different technique from that candidate
and prior campaign history.

A PruneGate evaluates the full batch in one additional constrained Ollama call
and scores each candidate for on-topic relevance and likely usefulness. Python
then removes off-topic candidates and retains only the top `w` on-topic
candidates before any target request. Pruned candidates consume no query
budget and are recorded with `target_status = NULL`, `pruned = true`, a reason,
and the evaluator score. This is intentionally distinct from the existing
`planner` source, which remains a one-candidate-per-iteration path.

“Cheap” here means a short, constrained evaluator prompt using the same
`llama3.1:8b` model as generation. No smaller or faster local model is
available in this repository, so this does not achieve TAP's original
separate-lightweight-evaluator assumption; that limitation is named rather
than implied away.

## Consequences

`branching_factor` and `beam_width` are per-campaign YAML settings because
they tune planner behavior; they are not operator-facing safety limits.
`max_queries` and `max_wall_clock_seconds` remain hard CLI ceilings.

Query usage is variable per branching round: zero to `w` target requests may
occur depending on pruning and an early confirmed bypass. This differs from
the one-query cost of each single-candidate planner iteration, so
`queries_used` must be compared in the context of the campaign's source.
