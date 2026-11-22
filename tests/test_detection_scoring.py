import pytest

from src.security.detection import (
    DetectionResult,
    DispositionAction,
    RiskLevel,
    RuleFinding,
    analyze_parameters,
    assess_detection,
)


def finding(rule_code: str, parameter_path: str = "q") -> RuleFinding:
    return RuleFinding(
        rule_code=rule_code,
        rule_name=rule_code,
        category="test",
        parameter_name="q",
        parameter_path=parameter_path,
        message="test finding",
        evidence="sanitized",
    )


def detection(*codes: str) -> DetectionResult:
    return DetectionResult(
        findings=tuple(finding(code) for code in codes),
        parameters_checked=1,
    )


def test_no_findings_has_no_risk_and_allows_request():
    assessment = assess_detection(detection())

    assert assessment.score == 0
    assert assessment.level is RiskLevel.NONE
    assert assessment.action is DispositionAction.ALLOW
    assert assessment.reasons == ("未命中检测规则",)


def test_single_low_weight_rule_allows_request():
    assessment = assess_detection(detection("PARAM_LENGTH"))

    assert assessment.score == 10
    assert assessment.level is RiskLevel.LOW
    assert assessment.action is DispositionAction.ALLOW


def test_single_sql_keyword_rule_alerts_request():
    assessment = assess_detection(detection("SQL_KEYWORD"))

    assert assessment.score == 25
    assert assessment.level is RiskLevel.MEDIUM
    assert assessment.action is DispositionAction.ALERT


def test_logical_and_encoded_rules_are_high_risk_and_blocked():
    assessment = assess_detection(
        detection("LOGICAL_COMBINATION", "ENCODED_PAYLOAD")
    )

    assert assessment.score == 65
    assert assessment.level is RiskLevel.HIGH
    assert assessment.action is DispositionAction.BLOCK
    assert assessment.matched_rule_codes == (
        "ENCODED_PAYLOAD",
        "LOGICAL_COMBINATION",
    )


def test_score_is_capped_at_one_hundred():
    assessment = assess_detection(
        detection(
            "PARAM_LENGTH",
            "SQL_KEYWORD",
            "LOGICAL_COMBINATION",
            "COMMENT_OR_SEPARATOR",
            "ENCODED_PAYLOAD",
            "SPECIAL_CHARACTER_RUN",
        )
    )

    assert assessment.score == 100
    assert assessment.level is RiskLevel.HIGH
    assert assessment.action is DispositionAction.BLOCK
    assert assessment.reasons[-1] == "总分按上限封顶为 100"


def test_duplicate_rule_codes_are_scored_once_but_findings_are_retained():
    result = DetectionResult(
        findings=(
            finding("SQL_KEYWORD", "q[0]"),
            finding("SQL_KEYWORD", "q[1]"),
        ),
        parameters_checked=2,
    )

    assessment = assess_detection(result)

    assert assessment.score == 25
    assert assessment.matched_rule_codes == ("SQL_KEYWORD",)
    assert len(assessment.findings) == 2


@pytest.mark.parametrize(
    ("points", "expected_level", "expected_action"),
    [
        (24, RiskLevel.LOW, DispositionAction.ALLOW),
        (25, RiskLevel.MEDIUM, DispositionAction.ALERT),
        (59, RiskLevel.MEDIUM, DispositionAction.ALERT),
        (60, RiskLevel.HIGH, DispositionAction.BLOCK),
    ],
)
def test_risk_threshold_boundaries(points, expected_level, expected_action):
    assessment = assess_detection(
        detection("CUSTOM_RULE"),
        rule_weights={"CUSTOM_RULE": points},
    )

    assert assessment.score == points
    assert assessment.level is expected_level
    assert assessment.action is expected_action


def test_unknown_rule_uses_default_weight():
    assessment = assess_detection(detection("CUSTOM_RULE"))

    assert assessment.score == 10
    assert assessment.contributions[0].points == 10


def test_negative_custom_weight_is_treated_as_zero():
    assessment = assess_detection(
        detection("CUSTOM_RULE"),
        rule_weights={"CUSTOM_RULE": -50},
    )

    assert assessment.score == 0
    assert assessment.level is RiskLevel.NONE


def test_real_detection_result_flows_into_risk_assessment():
    detection_result = analyze_parameters(
        {"q": "%2527%2520OR%25201%253D1"}
    )

    assessment = assess_detection(detection_result)

    assert assessment.score == 65
    assert assessment.level is RiskLevel.HIGH
    assert assessment.action is DispositionAction.BLOCK
    assert assessment.matched_rule_codes == (
        "ENCODED_PAYLOAD",
        "LOGICAL_COMBINATION",
    )
