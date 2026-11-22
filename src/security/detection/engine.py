"""Stateless orchestration for the phase 4A rule engine."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any
from urllib.parse import unquote
from unicodedata import normalize

from .models import DetectionContext, DetectionResult, DetectionRule, RuleFinding
from .rules import DEFAULT_RULES


def _build_context(value: str) -> DetectionContext:
    decoded = value
    for _ in range(2):
        decoded = unquote(decoded, errors="replace")

    return DetectionContext(
        raw=value,
        decoded=decoded,
        normalized=normalize("NFKC", decoded),
    )


def analyze_parameter(
    parameter_name: str,
    value: str | int | float | bool,
    *,
    parameter_path: str | None = None,
    rules: Sequence[DetectionRule] = DEFAULT_RULES,
) -> tuple[RuleFinding, ...]:
    """Evaluate one scalar parameter without scoring or persistence."""

    context = _build_context(str(value))
    path = parameter_path or parameter_name
    findings = []
    for rule in rules:
        finding = rule.evaluate(parameter_name, path, context)
        if finding is not None:
            findings.append(finding)
    return tuple(findings)


def analyze_parameters(
    parameters: Mapping[str, Any],
    *,
    rules: Sequence[DetectionRule] = DEFAULT_RULES,
) -> DetectionResult:
    """Analyze flat or repeated request parameters in deterministic order."""

    findings: list[RuleFinding] = []
    parameters_checked = 0

    for parameter_name, value in parameters.items():
        if value is None:
            continue

        if isinstance(value, (str, int, float, bool)):
            values = ((parameter_name, value),)
        elif isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
            values = tuple(
                (f"{parameter_name}[{index}]", item)
                for index, item in enumerate(value)
                if isinstance(item, (str, int, float, bool))
            )
        else:
            continue

        for parameter_path, scalar_value in values:
            findings.extend(
                analyze_parameter(
                    parameter_name,
                    scalar_value,
                    parameter_path=parameter_path,
                    rules=rules,
                )
            )
            parameters_checked += 1

    return DetectionResult(
        findings=tuple(findings),
        parameters_checked=parameters_checked,
    )
