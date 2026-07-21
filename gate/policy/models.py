"""Pydantic models for the interim Gate policy contract."""

from typing import Any, Literal

from pydantic import BaseModel

from detectors.base import DetectorSignal


PolicyAction = Literal["block", "redact", "flag", "allow"]
PolicyStage = Literal["input", "output"]


class PolicyRule(BaseModel):
    """One ordered rule loaded from the version-controlled YAML file."""

    id: str
    owasp_id: str
    enabled: bool
    stage: PolicyStage
    detector: str
    matcher_type: str
    matcher_config: dict[str, Any]
    action: PolicyAction


class RuleMatch(BaseModel):
    """One rule-to-signal match in policy evaluation order."""

    rule_id: str
    action: PolicyAction
    signal: DetectorSignal


class PolicyEvaluation(BaseModel):
    """The ordered result of evaluating a set of detector signals."""

    action: PolicyAction | None = None
    matched_rules: list[str]
    matches: list[RuleMatch]
    terminal_rule_id: str | None = None
    signals: list[DetectorSignal]
