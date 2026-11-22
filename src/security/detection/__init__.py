"""Rule-based SQL injection detection primitives."""

from .engine import analyze_parameter, analyze_parameters
from .models import DetectionResult, RuleFinding
from .rules import DEFAULT_RULES
from .scoring import (
    DEFAULT_RULE_WEIGHTS,
    DispositionAction,
    RiskAssessment,
    RiskLevel,
    RuleContribution,
    assess_detection,
)

__all__ = [
    "DEFAULT_RULES",
    "DEFAULT_RULE_WEIGHTS",
    "DetectionResult",
    "DispositionAction",
    "RiskAssessment",
    "RiskLevel",
    "RuleContribution",
    "RuleFinding",
    "analyze_parameter",
    "analyze_parameters",
    "assess_detection",
]
