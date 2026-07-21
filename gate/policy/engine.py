"""Ordered evaluation for Gate's interim YAML policy rules."""

import operator
from pathlib import Path
from typing import Any, Callable

import yaml
from pydantic import TypeAdapter

from detectors.base import DetectorSignal
from policy.models import (
    PolicyAction,
    PolicyEvaluation,
    PolicyRule,
    PolicyStage,
    RuleMatch,
)


COMPARISONS: dict[str, Callable[[float, float], bool]] = {
    "gte": operator.ge,
    "gt": operator.gt,
    "lte": operator.le,
    "lt": operator.lt,
    "eq": operator.eq,
}


class PolicyEngine:
    """Evaluates version-controlled rules in their file-defined order."""

    def __init__(self, rules: list[PolicyRule]) -> None:
        self._rules = rules

    @classmethod
    def from_yaml(cls, rules_path: Path) -> "PolicyEngine":
        """Load and validate the complete interim policy file once at startup."""

        with rules_path.open(encoding="utf-8") as rules_file:
            raw_rules = yaml.safe_load(rules_file)

        rules = TypeAdapter(list[PolicyRule]).validate_python(raw_rules)
        return cls(rules)

    def evaluate(
        self, signals: list[DetectorSignal], *, stage: PolicyStage
    ) -> PolicyEvaluation:
        """Return the stage-specific terminal action and ordered rule matches."""

        matched_rules: list[str] = []
        matches: list[RuleMatch] = []
        non_terminal_action: PolicyAction | None = None

        for rule in self._rules:
            if not rule.enabled or rule.stage != stage:
                continue

            matching_signals = [
                signal for signal in signals if signal.detector == rule.detector
            ]
            matched_signals = [
                signal for signal in matching_signals if self._matches(rule, signal)
            ]
            if not matched_signals:
                continue

            matched_rules.append(rule.id)
            matches.extend(
                RuleMatch(rule_id=rule.id, action=rule.action, signal=signal)
                for signal in matched_signals
            )
            if rule.action in {"block", "allow"}:
                return PolicyEvaluation(
                    action=rule.action,
                    matched_rules=matched_rules,
                    matches=matches,
                    terminal_rule_id=rule.id,
                    signals=signals,
                )

            non_terminal_action = rule.action

        return PolicyEvaluation(
            action=non_terminal_action,
            matched_rules=matched_rules,
            matches=matches,
            signals=signals,
        )

    @staticmethod
    def _matches(rule: PolicyRule, signal: DetectorSignal) -> bool:
        if rule.matcher_type == "threshold":
            return PolicyEngine._matches_threshold(rule.matcher_config, signal)
        if rule.matcher_type == "boolean_true":
            return PolicyEngine._matches_boolean_true(rule.matcher_config, signal)
        if rule.matcher_type == "list_nonempty":
            return PolicyEngine._matches_list_nonempty(rule.matcher_config, signal)

        raise ValueError(f"unsupported matcher_type: {rule.matcher_type}")

    @staticmethod
    def _matches_threshold(
        matcher_config: dict[str, Any], signal: DetectorSignal
    ) -> bool:
        try:
            signal_field = matcher_config["signal_field"]
            threshold = float(matcher_config["threshold"])
            comparison_name = matcher_config["comparison"]
            comparison = COMPARISONS[comparison_name]
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("invalid threshold matcher configuration") from exc

        signal_value = getattr(signal, signal_field, None)
        if signal_value is None:
            return False
        if not isinstance(signal_value, (int, float)):
            return False

        return comparison(float(signal_value), threshold)

    @staticmethod
    def _matches_boolean_true(
        matcher_config: dict[str, Any], signal: DetectorSignal
    ) -> bool:
        try:
            signal_field = matcher_config["signal_field"]
        except (KeyError, TypeError) as exc:
            raise ValueError("invalid boolean_true matcher configuration") from exc

        return getattr(signal, signal_field, None) is True

    @staticmethod
    def _matches_list_nonempty(
        matcher_config: dict[str, Any], signal: DetectorSignal
    ) -> bool:
        try:
            signal_field = matcher_config["signal_field"]
        except (KeyError, TypeError) as exc:
            raise ValueError("invalid list_nonempty matcher configuration") from exc

        signal_value = getattr(signal, signal_field, None)
        return isinstance(signal_value, list) and bool(signal_value)
