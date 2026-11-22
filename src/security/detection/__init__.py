"""Rule-based SQL injection detection primitives."""

from .engine import analyze_parameter, analyze_parameters
from .frequency import (
    DEFAULT_FREQUENCY_LIMIT,
    DEFAULT_FREQUENCY_WINDOW_SECONDS,
    FrequencyDecision,
    RequestFrequencyTracker,
    build_frequency_finding,
)
from .models import DetectionResult, RuleFinding
from .policy import SecurityRequestDecision, decide_request_action
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
    "DEFAULT_FREQUENCY_LIMIT",
    "DEFAULT_FREQUENCY_WINDOW_SECONDS",
    "DetectionResult",
    "DispositionAction",
    "FrequencyDecision",
    "RequestFrequencyTracker",
    "RiskAssessment",
    "RiskLevel",
    "RuleContribution",
    "RuleFinding",
    "SecurityRequestDecision",
    "analyze_parameter",
    "analyze_parameters",
    "assess_detection",
    "build_frequency_finding",
    "decide_request_action",
]
