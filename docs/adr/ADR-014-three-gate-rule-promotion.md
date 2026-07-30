# ADR-014: Three-gate rule promotion

- Status: Accepted
- Date: 2026-07-30

## Context

A proposed rule can close its originating bypass yet still block legitimate
traffic. Mechanical verification alone proves only the former. The relevant
risk became concrete when Gate 3's benign corpus blocked an
alphabet-restricted extraction proposal: it would have over-redacted a
211-character span in legitimate content.

The benign corpus is deliberately banded. Its discriminatory power comes from
fixed composition and realistic adjacent-vocabulary and structurally awkward
cases, not from treating the total case count as statistical rigor. Its power
is conditional on the current detector pattern set; adding patterns can change
the false-positive surface and requires the gate to be run again.

## Decision

Every proposed rule follows three technical gates before human approval:

1. Mechanical verification against the originating evidence.
2. Deterministic bypass regression: every retained known bypass must still be
   blocked.
3. Benign false-positive evaluation, with fixed corpus bands and their
   configured thresholds.

Only after all applicable technical gates pass may a human sign off. The
approval record snapshots the specific corpus versions, case counts,
per-band false-positive rates, and verification result. A later corpus or
pattern change is visibly outside that approval's evidence scope.

## Rejected alternatives

Mechanical verification plus human review was rejected because it leaves
false-positive effects invisible at the sign-off point. A flat aggregate FP
threshold was rejected because it could hide a harmful false positive in an
ordinary or adjacent-vocabulary case. Alphabet-restricted extraction was
rejected after Gate 3 exposed its 211-character over-redaction; it improved
evasion coverage at an unacceptable span-safety cost.

## Consequences

Promotion takes longer and requires maintaining byte-exact bypass and benign
corpora, test harnesses, manifests, and an evidence snapshot. A proposal can
be technically effective yet remain blocked until representative benign
coverage exists. Corpus cases require deliberate curation: bulk-generated
generic prompts increase a count without necessarily improving detection of
over-broad rules.

This process does not make every policy safe. It only establishes behavior
against the current corpus and pattern set; the gate must be rerun whenever
patterns are added or the relevant normalization behavior changes.

## Revisit trigger

Revisit the thresholds, bands, or gate ordering after a confirmed production
false positive or bypass that the existing corpus missed, or when the detector
pattern set materially changes such that the current corpus no longer
represents its risk surface.
