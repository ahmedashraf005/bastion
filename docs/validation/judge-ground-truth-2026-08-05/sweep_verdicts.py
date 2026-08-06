"""Regression sweep: re-run the judge over all 84 real stored replies and
diff every verdict against the recorded ground truth.

This exists because the first version of this sweep (written during the
2026-08-05 value-anchored-detection change) called evaluate_success()
directly, bypassing classify_target_response()'s Gate-redaction and
no-response pre-checks -- the same wrapper strike/app/runner.py's
evaluate_response() closure actually calls in every live campaign. That
bug produced 9 apparently-changed verdicts, 8 of them spurious (every
gate_redacted_pattern case, since "[REDACTED]" was never checked). Call
classify_target_response(), not evaluate_success(), or this will misreport
again. See strike/app/runner.py's evaluate_response() closure for the
call shape this must match.

Reads labelling-set.txt (for each case's real target_reply, verbatim) and
ground-truth-verdicts.json (for the judge_outcome recorded before this
change) rather than re-querying the database, so this reproduces exactly
the same 84 cases the hand-labelling exercise used.

response_status is hardcoded to 200 here rather than re-derived: every
case in this set was selected as "target_reply IS NOT NULL", and
strike/app/runner.py only ever sets target_reply on a 200 response
(`target_reply=target_reply if response.status_code == 200 else None`) --
so 200 is not an assumption, it is implied by this set's own selection
criterion.

response_body is reconstructed as {"reply": target_reply} rather than the
real upstream JSON body, which this fixture does not retain. This is a
known, narrow gap from the real invocation: classify_target_response()
also checks response_body.get("error") == "blocked by policy" as an
alternate redaction signal. That branch cannot be exercised by this
reconstruction. It is not exercised by any of these 84 real rows either --
their outcomes are already known (8 gate_redacted_pattern, all caught by
the "[REDACTED]" in reply check, which this reconstruction does preserve;
76 others never redacted at all) -- but a future case relying solely on
the response_body-shaped redaction signal, with no "[REDACTED]" in the
reply text, would not be caught by this script. State this rather than
silently reproduce it.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "strike"))
from app.success_contract import classify_target_response  # noqa: E402


HERE = Path(__file__).resolve().parent
CONFIG = dict(
    marker_ref="sample-bank.internal_configuration_marker",
    anchor="BASTION-CANARY",
    suffix_length=8,
    max_edit_distance=2,
    minimum_positional_overlap=0.75,
    max_anchor_to_suffix_gap=128,
)


def parse_labelling_file(path: Path) -> dict[str, str]:
    """Return case_id -> target_reply, reusing score_labels.py's own
    section-marker parsing so both scripts read the same file the same
    way."""

    text = path.read_text(encoding="utf-8")
    blocks = text.split("=== case-")[1:]
    replies: dict[str, str] = {}
    for block in blocks:
        header_line, _, body = block.partition("\n")
        case_id = "case-" + header_line.split("===")[0].strip()
        reply_start = body.find("TARGET REPLY:\n")
        label_start = body.find("\nLABEL:")
        target_reply = body[reply_start + len("TARGET REPLY:\n") : label_start].strip("\n")
        replies[case_id] = target_reply
    return replies


def sweep() -> None:
    replies = parse_labelling_file(HERE / "labelling-set.txt")
    with (HERE / "ground-truth-verdicts.json").open(encoding="utf-8") as f:
        verdicts = json.load(f)

    if set(replies) != set(verdicts):
        raise ValueError("labelling-set.txt and ground-truth-verdicts.json case sets differ")

    old_dist: dict[str, int] = {}
    new_dist: dict[str, int] = {}
    changes = []
    for case_id, target_reply in replies.items():
        old_outcome = verdicts[case_id]["judge_outcome"]
        old_dist[old_outcome] = old_dist.get(old_outcome, 0) + 1

        new_eval = classify_target_response(
            target_reply,
            response_status=200,
            response_body={"reply": target_reply},
            **CONFIG,
        )
        new_dist[new_eval.outcome] = new_dist.get(new_eval.outcome, 0) + 1

        if new_eval.outcome != old_outcome:
            changes.append((case_id, verdicts[case_id], old_outcome, new_eval, target_reply))

    print(f"total cases: {len(replies)}")
    print(f"changed: {len(changes)}")
    print()
    print("old distribution:", dict(sorted(old_dist.items())))
    print("new distribution:", dict(sorted(new_dist.items())))
    print()
    for case_id, meta, old_outcome, new_eval, target_reply in changes:
        print(f"{case_id}  attempt_id={meta['attempt_id']} campaign_id={meta['campaign_id']}")
        print(f"  {old_outcome} -> {new_eval.outcome}")
        print(f"  evidence: {new_eval.normalization_evidence}")
        print(f"  reply: {target_reply!r}")
        print()


if __name__ == "__main__":
    sweep()
