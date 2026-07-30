"""Resolved Gate policy/profile paths shared by startup and promotion tools."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml


GATE_ROOT = Path(__file__).resolve().parent.parent
PROFILE_ROOT = GATE_ROOT / "policy" / "profiles"
_PROFILE_NAME = re.compile(r"^[a-z0-9][a-z0-9-]*$")


@dataclass(frozen=True)
class PolicyProfilePaths:
    """Every config file that jointly defines the output leak detector."""

    name: str
    rules: Path
    leak_patterns: Path
    normalization_versions: Path
    pattern_versions: Path


def resolve_policy_profile(profile_name: str | None, rules_override: Path | None = None) -> PolicyProfilePaths:
    """Return complete paths, refusing partial or traversal-prone profiles."""

    if profile_name is None:
        return PolicyProfilePaths(
            name="default",
            rules=rules_override or GATE_ROOT / "policy" / "rules.yaml",
            leak_patterns=GATE_ROOT / "detectors" / "leak_patterns.yaml",
            normalization_versions=GATE_ROOT / "detectors" / "normalization_versions.yaml",
            pattern_versions=GATE_ROOT / "detectors" / "pattern_versions.yaml",
        )
    if rules_override is not None:
        raise RuntimeError("GATE_RULES_PATH cannot be combined with GATE_POLICY_PROFILE")
    if not _PROFILE_NAME.fullmatch(profile_name):
        raise RuntimeError(f"invalid Gate policy profile name: {profile_name!r}")

    directory = (PROFILE_ROOT / profile_name).resolve()
    if directory.parent != PROFILE_ROOT.resolve():
        raise RuntimeError(f"invalid Gate policy profile path: {profile_name!r}")
    resolved = PolicyProfilePaths(
        name=profile_name,
        rules=directory / "rules.yaml",
        leak_patterns=directory / "leak_patterns.yaml",
        normalization_versions=directory / "normalization_versions.yaml",
        pattern_versions=directory / "pattern_versions.yaml",
    )
    missing = [path.name for path in (
        resolved.rules,
        resolved.leak_patterns,
        resolved.normalization_versions,
        resolved.pattern_versions,
    ) if not path.is_file()]
    if missing:
        raise RuntimeError(
            f"Gate policy profile {profile_name!r} is incomplete; missing: {', '.join(missing)}"
        )
    return resolved


def active_manifest_version(path: Path) -> str | None:
    """Return the one active manifest version, rejecting ambiguous manifests."""

    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, list):
        raise RuntimeError(f"Gate version manifest must be a YAML list: {path}")
    active_ids = [
        entry.get("version_id")
        for entry in loaded
        if isinstance(entry, dict) and entry.get("active") is True
    ]
    if len(active_ids) > 1 or any(not isinstance(version_id, str) for version_id in active_ids):
        raise RuntimeError(f"Gate version manifest has ambiguous active versions: {path}")
    return active_ids[0] if active_ids else None
