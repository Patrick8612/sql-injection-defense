"""Data structures shared by detection rules and future scoring stages."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True, slots=True)
class DetectionContext:
    """Normalized representations of one submitted parameter value."""

    raw: str
    decoded: str
    normalized: str


RuleDetector = Callable[[DetectionContext], str | None]


@dataclass(frozen=True, slots=True)
class DetectionRule:
    """One independently testable detection rule."""

    code: str
    name: str
    category: str
    message: str
    detector: RuleDetector

    def evaluate(
        self,
        parameter_name: str,
        parameter_path: str,
        context: DetectionContext,
    ) -> RuleFinding | None:
        evidence = self.detector(context)
        if evidence is None:
            return None

        return RuleFinding(
            rule_code=self.code,
            rule_name=self.name,
            category=self.category,
            parameter_name=parameter_name,
            parameter_path=parameter_path,
            message=self.message,
            evidence=evidence,
        )


@dataclass(frozen=True, slots=True)
class RuleFinding:
    """A sanitized description of a rule match."""

    rule_code: str
    rule_name: str
    category: str
    parameter_name: str
    parameter_path: str
    message: str
    evidence: str


@dataclass(frozen=True, slots=True)
class DetectionResult:
    """Findings for one parameter collection, before scoring or persistence."""

    findings: tuple[RuleFinding, ...]
    parameters_checked: int

    @property
    def matched(self) -> bool:
        return bool(self.findings)

    @property
    def rule_codes(self) -> tuple[str, ...]:
        return tuple(finding.rule_code for finding in self.findings)
