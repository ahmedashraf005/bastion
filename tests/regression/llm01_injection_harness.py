"""Gate-path measurement harness for the frozen LLM01 corpus.

This is a measurement harness, not a regression suite. It loads the real
Prompt Guard detector, Presidio input detector, and Gate input PolicyEngine,
then sends every request-shaped case through the shared Gate input-evaluation
function. Missing detector state, missing scores, sentinel mismatches, and
case errors are hard failures; none can become a zero-valued result.
"""

from __future__ import annotations

import argparse
import asyncio
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any, Awaitable, Callable

import yaml

from tests import _pathfix  # noqa: F401
from app.main import (
    PII_ENTITIES_PATH,
    RULES_PATH,
    evaluate_input_request,
    extract_text_content,
)
from detectors.base import DetectorSignal
from detectors.presidio_pii import PresidioPiiDetector
from detectors.prompt_guard import PromptGuardDetector
from policy.engine import PolicyEngine


REPO_ROOT = Path(__file__).resolve().parents[2]
CORPUS_PATH = REPO_ROOT / "tests/corpus/llm01_direct_injection.yaml"
CONTROLS_PATH = REPO_ROOT / "tests/fixtures/llm01_controls.yaml"
PROMPT_GUARD_PATH = REPO_ROOT / "gate/detectors/prompt_guard.py"
GATE_MAIN_PATH = REPO_ROOT / "gate/app/main.py"
EXPECTED_BANDS = {
    "direct_override",
    "role_play_framing",
    "encoding_obfuscation",
    "multi_step_setup",
    "ordinary_text",
    "adjacent_vocabulary",
    "structurally_awkward",
}
CHARACTERIZATION_THRESHOLDS = tuple(round(0.50 + index * 0.05, 2) for index in range(10))


class HarnessFailure(RuntimeError):
    """A failure that invalidates the run instead of producing a summary."""


@dataclass(frozen=True)
class HarnessCase:
    case_id: str
    split: str
    band: str
    expected_label: str
    messages: list[dict[str, Any]]
    provenance: dict[str, Any]


@dataclass(frozen=True)
class HarnessRuntime:
    detector: PromptGuardDetector
    pii_detector: PresidioPiiDetector
    policy: PolicyEngine
    threshold: float
    detector_config_sha256: str
    policy_config_sha256: str
    model_id: str
    model_revision_or_cache_id: str
    git_revision: str


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as file:
            for chunk in iter(lambda: file.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise HarnessFailure(f"cannot hash configuration {path}: {exc}") from exc
    return digest.hexdigest()


def _sha256_paths(paths: tuple[Path, ...]) -> str:
    digest = hashlib.sha256()
    for path in paths:
        digest.update(str(path.relative_to(REPO_ROOT)).encode("utf-8"))
        digest.update(b"\0")
        digest.update(bytes.fromhex(_sha256_path(path)))
    return digest.hexdigest()


def _detector_config_sha256(model_id: str) -> str:
    """Hash detector source plus the runtime-selected model identity."""

    digest = hashlib.sha256()
    digest.update(bytes.fromhex(_sha256_paths((PROMPT_GUARD_PATH, GATE_MAIN_PATH))))
    digest.update(b"\0configured_model_id\0")
    digest.update(model_id.encode("utf-8"))
    return digest.hexdigest()


def _git_revision() -> str:
    supplied_revision = os.getenv("BASTION_GIT_REVISION")
    if supplied_revision:
        return supplied_revision
    try:
        return subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=REPO_ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise HarnessFailure(f"cannot record Git revision: {exc}") from exc


def _load_yaml(path: Path) -> dict[str, Any]:
    try:
        with path.open(encoding="utf-8") as file:
            raw = yaml.safe_load(file)
    except (OSError, yaml.YAMLError) as exc:
        raise HarnessFailure(f"cannot load YAML {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise HarnessFailure(f"{path}: expected a top-level mapping")
    return raw


def _validate_messages(case_id: str, messages: Any) -> list[dict[str, Any]]:
    if not isinstance(messages, list) or not messages:
        raise HarnessFailure(f"{case_id}: messages must be a non-empty list")
    validated: list[dict[str, Any]] = []
    for index, message in enumerate(messages):
        if not isinstance(message, dict) or message.get("role") != "user":
            raise HarnessFailure(
                f"{case_id}: message {index} is not a direct user-role message"
            )
        content = message.get("content")
        if not isinstance(content, (str, list)):
            raise HarnessFailure(f"{case_id}: message {index} has unsupported content")
        if isinstance(content, list):
            for block in content:
                if not isinstance(block, dict):
                    raise HarnessFailure(f"{case_id}: invalid content block")
        validated.append(message)
    return validated


def load_corpus(path: Path = CORPUS_PATH) -> list[HarnessCase]:
    """Load and reconcile the frozen positive/negative corpus manifest."""

    raw = _load_yaml(path)
    if raw.get("version") != 1:
        raise HarnessFailure(f"{path}: expected corpus version 1")
    manifest = raw.get("band_manifest")
    if not isinstance(manifest, dict) or set(manifest) != EXPECTED_BANDS:
        raise HarnessFailure(f"{path}: band_manifest must contain exactly {sorted(EXPECTED_BANDS)}")
    if any(type(count) is not int or count < 0 for count in manifest.values()):
        raise HarnessFailure(f"{path}: band_manifest counts must be non-negative integers")

    raw_cases = raw.get("cases")
    if not isinstance(raw_cases, list):
        raise HarnessFailure(f"{path}: cases must be a list")
    seen: set[str] = set()
    cases: list[HarnessCase] = []
    for raw_case in raw_cases:
        if not isinstance(raw_case, dict):
            raise HarnessFailure(f"{path}: every case must be a mapping")
        case_id = raw_case.get("id")
        split = raw_case.get("split")
        band = raw_case.get("band")
        expected_label = raw_case.get("expected_label")
        if (
            not isinstance(case_id, str)
            or not case_id
            or case_id in seen
            or split not in {"positive", "negative"}
            or band not in EXPECTED_BANDS
            or expected_label not in {"injection", "benign"}
        ):
            raise HarnessFailure(f"{path}: malformed or duplicate case metadata: {case_id!r}")
        expected_for_split = "injection" if split == "positive" else "benign"
        if expected_label != expected_for_split:
            raise HarnessFailure(f"{case_id}: expected_label does not match split")
        provenance = raw_case.get("provenance")
        if not isinstance(provenance, dict) or provenance.get("source_type") not in {
            "captured",
            "published",
            "authored",
        }:
            raise HarnessFailure(f"{case_id}: provenance.source_type is required")
        cases.append(
            HarnessCase(
                case_id=case_id,
                split=split,
                band=band,
                expected_label=expected_label,
                messages=_validate_messages(case_id, raw_case.get("messages")),
                provenance=provenance,
            )
        )
        seen.add(case_id)

    counts = {band: sum(case.band == band for case in cases) for band in EXPECTED_BANDS}
    declared = {band: manifest[band] for band in EXPECTED_BANDS}
    if counts != declared:
        raise HarnessFailure(f"{path}: manifest {declared} != actual {counts}")
    if len(cases) != 89:
        raise HarnessFailure(f"{path}: frozen corpus must contain 89 cases, found {len(cases)}")
    if sum(case.split == "positive" for case in cases) != 48:
        raise HarnessFailure(f"{path}: frozen corpus must contain 48 positives")
    if sum(case.split == "negative" for case in cases) != 41:
        raise HarnessFailure(f"{path}: frozen corpus must contain 41 negatives")
    return cases


def load_controls(path: Path = CONTROLS_PATH) -> dict[str, HarnessCase]:
    """Load exactly one frozen positive and negative operational sentinel."""

    raw = _load_yaml(path)
    if raw.get("version") != 1:
        raise HarnessFailure(f"{path}: expected controls version 1")
    controls: dict[str, HarnessCase] = {}
    for name, expected_label in (("positive_control", "injection"), ("negative_control", "benign")):
        raw_control = raw.get(name)
        if not isinstance(raw_control, dict):
            raise HarnessFailure(f"{path}: missing {name}")
        case_id = raw_control.get("id")
        if not isinstance(case_id, str) or not case_id:
            raise HarnessFailure(f"{path}: {name}.id is required")
        if raw_control.get("expected_label") != expected_label:
            raise HarnessFailure(f"{path}: {name} expected_label must be {expected_label}")
        provenance = raw_control.get("provenance")
        if not isinstance(provenance, dict):
            raise HarnessFailure(f"{path}: {name}.provenance is required")
        controls[name] = HarnessCase(
            case_id=case_id,
            split="control",
            band="sentinel",
            expected_label=expected_label,
            messages=_validate_messages(case_id, raw_control.get("messages")),
            provenance=provenance,
        )
    if len({case.case_id for case in controls.values()}) != 2:
        raise HarnessFailure(f"{path}: control IDs must be distinct")
    return controls


def _prompt_guard_threshold(policy_path: Path) -> float:
    try:
        with policy_path.open(encoding="utf-8") as file:
            raw = yaml.safe_load(file)
    except (OSError, yaml.YAMLError) as exc:
        raise HarnessFailure(f"cannot load policy YAML {policy_path}: {exc}") from exc
    if not isinstance(raw, list):
        raise HarnessFailure(f"{policy_path}: expected a list of policy rules")
    candidates = [
        rule
        for rule in raw if isinstance(rule, dict)
        and rule.get("enabled") is True
        and rule.get("stage") == "input"
        and rule.get("detector") == "prompt_guard_2"
        and rule.get("matcher_type") == "threshold"
    ]
    if len(candidates) != 1:
        raise HarnessFailure(
            f"{policy_path}: expected exactly one enabled prompt_guard_2 input threshold, found {len(candidates)}"
        )
    try:
        threshold = float(candidates[0]["matcher_config"]["threshold"])
    except (KeyError, TypeError, ValueError) as exc:
        raise HarnessFailure(f"{policy_path}: invalid prompt_guard_2 threshold") from exc
    if not 0.0 <= threshold <= 1.0:
        raise HarnessFailure(f"{policy_path}: threshold outside [0, 1]: {threshold}")
    return threshold


def load_runtime() -> HarnessRuntime:
    """Load every live detector/config dependency without a fail-open path."""

    policy = PolicyEngine.from_yaml(RULES_PATH)
    threshold = _prompt_guard_threshold(RULES_PATH)
    try:
        detector = PromptGuardDetector.load()
    except Exception as exc:
        raise HarnessFailure(
            "detector initialization failed; no measurement was produced: "
            f"{exc.__class__.__name__}: {exc}"
        ) from exc
    try:
        pii_detector = PresidioPiiDetector.from_yaml(PII_ENTITIES_PATH)
    except Exception as exc:
        raise HarnessFailure(
            "Gate input-detector initialization failed; no measurement was produced: "
            f"{exc.__class__.__name__}: {exc}"
        ) from exc
    return HarnessRuntime(
        detector=detector,
        pii_detector=pii_detector,
        policy=policy,
        threshold=threshold,
        detector_config_sha256=_detector_config_sha256(detector.model_id),
        policy_config_sha256=_sha256_path(RULES_PATH),
        model_id=detector.model_id,
        model_revision_or_cache_id=detector.model_revision_or_cache_id,
        git_revision=_git_revision(),
    )


def _message_shape(messages: list[dict[str, Any]]) -> str:
    has_array = any(isinstance(message.get("content"), list) for message in messages)
    has_string = any(isinstance(message.get("content"), str) for message in messages)
    if has_array and has_string:
        return "mixed"
    if has_array:
        return "content_block_array"
    return "plain_string"


def _config_fields(runtime: HarnessRuntime) -> dict[str, Any]:
    return {
        "detector_config_sha256": runtime.detector_config_sha256,
        "detector_config_paths": [
            str(PROMPT_GUARD_PATH.relative_to(REPO_ROOT)),
            str(GATE_MAIN_PATH.relative_to(REPO_ROOT)),
        ],
        "policy_config_sha256": runtime.policy_config_sha256,
        "policy_config_path": str(RULES_PATH.relative_to(REPO_ROOT)),
        "model_id": runtime.model_id,
        "model_revision_or_cache_id": runtime.model_revision_or_cache_id,
        "threshold": runtime.threshold,
        "git_revision": runtime.git_revision,
    }


async def execute_case(case: HarnessCase, runtime: HarnessRuntime) -> dict[str, Any]:
    """Execute one case through Gate's shared input detector/policy path."""

    body = {"model": "llm01-harness", "messages": case.messages, "stream": False}
    evaluation = await evaluate_input_request(
        body,
        prompt_guard_detector=runtime.detector,
        pii_detector=runtime.pii_detector,
        policy_engine=runtime.policy,
        scan_tool_output=False,
    )
    signal = next(
        (signal for signal in evaluation.signals if signal.detector == "prompt_guard_2"),
        None,
    )
    score = signal.injection_score if signal is not None else None
    if score is None:
        raise HarnessFailure(
            f"{case.case_id}: Prompt Guard returned no score; run is incomplete"
        )
    detected = score >= runtime.threshold
    expected_detected = case.expected_label == "injection"
    result = {
        "case_id": case.case_id,
        "split": case.split,
        "band": case.band,
        "expected_label": case.expected_label,
        "message_shape": _message_shape(case.messages),
        "user_message_count": len(case.messages),
        "detector_score": score,
        "detector_detected": detected,
        "policy_action": evaluation.policy_result.action,
        "matched_rule_ids": evaluation.policy_result.matched_rules,
        **_config_fields(runtime),
        "provenance_source_type": case.provenance.get("source_type"),
        "status": "pass" if detected == expected_detected else "fail",
    }
    return result


async def _run_control(
    name: str, case: HarnessCase, runtime: HarnessRuntime, phase: str
) -> dict[str, Any]:
    result = await execute_case(case, runtime)
    expected_detected = case.expected_label == "injection"
    if result["detector_detected"] != expected_detected:
        raise HarnessFailure(
            f"sentinel mismatch phase={phase} name={name} case_id={case.case_id} "
            f"expected_detected={expected_detected} "
            f"actual_detected={result['detector_detected']} "
            f"score={result['detector_score']:.6f} threshold={runtime.threshold:.6f}"
        )
    result["status"] = "pass"
    return result


def _summary(results: list[dict[str, Any]]) -> dict[str, Any]:
    positive_bands = ("direct_override", "role_play_framing", "encoding_obfuscation", "multi_step_setup")
    negative_bands = ("ordinary_text", "adjacent_vocabulary", "structurally_awkward")
    positive_by_band: dict[str, dict[str, int]] = {}
    negative_by_band: dict[str, dict[str, int]] = {}
    for band in positive_bands:
        band_results = [result for result in results if result["band"] == band]
        tp = sum(result["detector_detected"] for result in band_results)
        positive_by_band[band] = {
            "tp": tp,
            "fn": len(band_results) - tp,
            "total": len(band_results),
        }
    for band in negative_bands:
        band_results = [result for result in results if result["band"] == band]
        fp = sum(result["detector_detected"] for result in band_results)
        negative_by_band[band] = {
            "fp": fp,
            "tn": len(band_results) - fp,
            "total": len(band_results),
        }
    return {"positive_by_band": positive_by_band, "negative_by_band": negative_by_band}


def _threshold_curve(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Characterize the recorded scores without changing the live threshold."""

    positive_bands = ("direct_override", "role_play_framing", "encoding_obfuscation", "multi_step_setup")
    negative_bands = ("ordinary_text", "adjacent_vocabulary", "structurally_awkward")
    curve: list[dict[str, Any]] = []
    for threshold in CHARACTERIZATION_THRESHOLDS:
        positive_by_band: dict[str, dict[str, int]] = {}
        negative_by_band: dict[str, dict[str, int]] = {}
        for band in positive_bands:
            band_results = [result for result in results if result["band"] == band]
            tp = sum(result["detector_score"] >= threshold for result in band_results)
            positive_by_band[band] = {
                "tp": tp,
                "fn": len(band_results) - tp,
                "total": len(band_results),
            }
        for band in negative_bands:
            band_results = [result for result in results if result["band"] == band]
            fp = sum(result["detector_score"] >= threshold for result in band_results)
            negative_by_band[band] = {
                "fp": fp,
                "tn": len(band_results) - fp,
                "total": len(band_results),
            }
        curve.append(
            {
                "threshold": threshold,
                "positive_by_band": positive_by_band,
                "negative_by_band": negative_by_band,
                "positive_total": {
                    "tp": sum(band["tp"] for band in positive_by_band.values()),
                    "fn": sum(band["fn"] for band in positive_by_band.values()),
                    "total": sum(band["total"] for band in positive_by_band.values()),
                },
                "negative_total": {
                    "fp": sum(band["fp"] for band in negative_by_band.values()),
                    "tn": sum(band["tn"] for band in negative_by_band.values()),
                    "total": sum(band["total"] for band in negative_by_band.values()),
                },
            }
        )
    return curve


async def run_harness(
    *,
    runtime: HarnessRuntime | None = None,
    corpus_path: Path = CORPUS_PATH,
    controls_path: Path = CONTROLS_PATH,
) -> dict[str, Any]:
    """Run controls, the frozen corpus, and controls again."""

    cases = load_corpus(corpus_path)
    controls = load_controls(controls_path)
    runtime = runtime or load_runtime()

    controls_before = {
        name: await _run_control(name, case, runtime, "before")
        for name, case in controls.items()
    }
    results: list[dict[str, Any]] = []
    for case in cases:
        result = await execute_case(case, runtime)
        results.append(result)
    controls_after = {
        name: await _run_control(name, case, runtime, "after")
        for name, case in controls.items()
    }
    case_mismatches = [
        result["case_id"] for result in results if result["status"] != "pass"
    ]
    summary = _summary(results)
    summary["case_mismatches"] = case_mismatches
    summary["threshold_curve"] = _threshold_curve(results)
    return {
        "version": 1,
        "status": "complete",
        "scope": "direct_user_role_llm01",
        "run_metadata": {
            "corpus_path": str(corpus_path.relative_to(REPO_ROOT)),
            "corpus_sha256": _sha256_path(corpus_path),
            "corpus_revision": "frozen-89-case-v1",
            **_config_fields(runtime),
        },
        "controls": {"before": controls_before, "after": controls_after},
        "cases": results,
        "summary": summary,
        "errors": [],
        "complete": True,
    }


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=CORPUS_PATH)
    parser.add_argument("--controls", type=Path, default=CONTROLS_PATH)
    parser.add_argument(
        "--output",
        type=Path,
        help="write the complete JSON envelope, including every raw score, to this path",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        envelope = asyncio.run(
            run_harness(corpus_path=args.corpus, controls_path=args.controls)
        )
    except HarnessFailure as exc:
        print(f"HARNESS FAILURE: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(
            "HARNESS FAILURE: unexpected exception; no measurement was produced: "
            f"{exc.__class__.__name__}: {exc}",
            file=sys.stderr,
        )
        return 2
    rendered = json.dumps(envelope, ensure_ascii=False, indent=2, sort_keys=True)
    if args.output is not None:
        try:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(rendered + "\n", encoding="utf-8")
        except OSError as exc:
            print(f"HARNESS FAILURE: cannot write output {args.output}: {exc}", file=sys.stderr)
            return 2
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
