import pytest

from src.security.detection import (
    DetectionResult,
    DispositionAction,
    RequestFrequencyTracker,
    RiskAssessment,
    RiskLevel,
    RuleFinding,
    assess_detection,
    build_frequency_finding,
    decide_request_action,
)


def risk_assessment(
    code: str,
    *,
    rule_weights: dict[str, int],
) -> RiskAssessment:
    finding = RuleFinding(
        rule_code=code,
        rule_name=code,
        category="test",
        parameter_name="q",
        parameter_path="q",
        message="test",
        evidence="sanitized",
    )
    detection = DetectionResult(
        findings=(finding,),
        parameters_checked=1,
    )
    return assess_detection(detection, rule_weights=rule_weights)


def test_frequency_tracker_escalates_on_fifth_event():
    now = [100.0]
    tracker = RequestFrequencyTracker(
        window_seconds=60,
        limit=5,
        clock=lambda: now[0],
    )

    decisions = [tracker.record("user:1|demo") for _ in range(5)]

    assert [decision.count for decision in decisions] == [1, 2, 3, 4, 5]
    assert [decision.exceeded for decision in decisions] == [
        False,
        False,
        False,
        False,
        True,
    ]


def test_frequency_tracker_expires_old_events():
    now = [100.0]
    tracker = RequestFrequencyTracker(
        window_seconds=60,
        limit=3,
        clock=lambda: now[0],
    )

    tracker.record("key")
    tracker.record("key")
    now[0] = 161.0
    decision = tracker.record("key")

    assert decision.count == 1
    assert decision.exceeded is False


def test_frequency_tracker_isolates_keys():
    now = [100.0]
    tracker = RequestFrequencyTracker(
        window_seconds=60,
        limit=2,
        clock=lambda: now[0],
    )

    tracker.record("first")
    second = tracker.record("second")

    assert second.count == 1
    assert second.exceeded is False


def test_frequency_finding_is_sanitized():
    now = [100.0]
    tracker = RequestFrequencyTracker(clock=lambda: now[0], limit=1)
    decision = tracker.record("private-client-key")
    finding = build_frequency_finding(decision)

    assert finding.rule_code == "REQUEST_FREQUENCY"
    assert "private-client-key" not in finding.evidence


@pytest.mark.parametrize(
    ("endpoint", "security_mode", "expected_action"),
    [
        ("article_search", "safe", DispositionAction.BLOCK),
        ("sql_injection_demo", "vulnerable", DispositionAction.ALERT),
        ("sql_injection_demo", "safe", DispositionAction.ALLOW),
    ],
)
def test_high_risk_policy_by_endpoint(
    endpoint,
    security_mode,
    expected_action,
):
    assessment = risk_assessment(
        "HIGH_RULE",
        rule_weights={"HIGH_RULE": 80},
    )

    decision = decide_request_action(
        assessment,
        endpoint=endpoint,
        security_mode=security_mode,
    )

    assert assessment.level is RiskLevel.HIGH
    assert decision.effective_action is expected_action


def test_medium_risk_is_alerted_and_not_blocked():
    assessment = risk_assessment(
        "MEDIUM_RULE",
        rule_weights={"MEDIUM_RULE": 30},
    )

    decision = decide_request_action(
        assessment,
        endpoint="article_search",
        security_mode="safe",
    )

    assert decision.effective_action is DispositionAction.ALERT


def test_frequency_contribution_is_included_in_scoring():
    assessment = risk_assessment(
        "REQUEST_FREQUENCY",
        rule_weights={"REQUEST_FREQUENCY": 40},
    )

    assert assessment.score == 40
    assert assessment.level is RiskLevel.MEDIUM
