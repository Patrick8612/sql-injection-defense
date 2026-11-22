"""Explainable risk scoring and disposition for detected rules."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum

from .models import DetectionResult, RuleFinding


class RiskLevel(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class DispositionAction(str, Enum):
    ALLOW = "allow"
    ALERT = "alert"
    BLOCK = "block"


DEFAULT_RULE_WEIGHTS = {
    "PARAM_LENGTH": 10,
    "SQL_KEYWORD": 25,
    "LOGICAL_COMBINATION": 30,
    "COMMENT_OR_SEPARATOR": 20,
    "ENCODED_PAYLOAD": 25,
    "SPECIAL_CHARACTER_RUN": 15,
    "REQUEST_FREQUENCY": 40,
}
DEFAULT_UNKNOWN_RULE_WEIGHT = 10
DEFAULT_MAX_RISK_SCORE = 100


@dataclass(frozen=True, slots=True)
class RuleContribution:
    """Points assigned once for a distinct matched rule code."""

    rule_code: str
    points: int


@dataclass(frozen=True, slots=True)
class RiskAssessment:
    """Risk level, action, and explainable score contributions."""

    score: int
    level: RiskLevel
    action: DispositionAction
    findings: tuple[RuleFinding, ...]
    contributions: tuple[RuleContribution, ...]
    reasons: tuple[str, ...]

    @property
    def matched_rule_codes(self) -> tuple[str, ...]:
        return tuple(contribution.rule_code for contribution in self.contributions)


def _diversity_bonus(rule_count: int) -> int:
    if rule_count >= 4:
        return 25
    if rule_count == 3:
        return 20
    if rule_count == 2:
        return 10
    return 0


def _level_and_action(score: int) -> tuple[RiskLevel, DispositionAction]:
    if score >= 60:
        return RiskLevel.HIGH, DispositionAction.BLOCK
    if score >= 25:
        return RiskLevel.MEDIUM, DispositionAction.ALERT
    if score >= 1:
        return RiskLevel.LOW, DispositionAction.ALLOW
    return RiskLevel.NONE, DispositionAction.ALLOW


def assess_detection(
    detection: DetectionResult,
    *,
    rule_weights: Mapping[str, int] | None = None,
    max_score: int = DEFAULT_MAX_RISK_SCORE,
) -> RiskAssessment:
    """Turn distinct rule findings into a bounded and explainable risk result."""

    weights = DEFAULT_RULE_WEIGHTS if rule_weights is None else rule_weights
    distinct_codes = sorted(set(detection.rule_codes))

    contributions = tuple(
        RuleContribution(
            rule_code=code,
            points=max(
                0,
                int(weights.get(code, DEFAULT_UNKNOWN_RULE_WEIGHT)),
            ),
        )
        for code in distinct_codes
    )

    rule_score = sum(contribution.points for contribution in contributions)
    diversity_bonus = _diversity_bonus(len(contributions))
    raw_score = rule_score + diversity_bonus
    score = min(max(0, int(max_score)), raw_score)
    level, action = _level_and_action(score)

    reasons = [
        f"{contribution.rule_code} +{contribution.points}"
        for contribution in contributions
    ]
    if diversity_bonus:
        reasons.append(f"多规则组合 +{diversity_bonus}")
    if raw_score > score:
        reasons.append(f"总分按上限封顶为 {score}")
    if not reasons:
        reasons.append("未命中检测规则")

    return RiskAssessment(
        score=score,
        level=level,
        action=action,
        findings=detection.findings,
        contributions=contributions,
        reasons=tuple(reasons),
    )
