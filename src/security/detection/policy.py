"""Request-level policy mapping of risk actions to effective actions."""

from __future__ import annotations

from dataclasses import dataclass

from .scoring import DispositionAction, RiskAssessment


DEMO_ENDPOINT = "sql_injection_demo"


@dataclass(frozen=True, slots=True)
class SecurityRequestDecision:
    """Declared risk action plus the action actually enforced by policy."""

    assessment: RiskAssessment
    effective_action: DispositionAction
    policy_note: str


def decide_request_action(
    assessment: RiskAssessment,
    *,
    endpoint: str | None,
    security_mode: str,
) -> SecurityRequestDecision:
    """Apply request-level policy without weakening normal business routes."""

    if assessment.action is not DispositionAction.BLOCK:
        return SecurityRequestDecision(
            assessment=assessment,
            effective_action=assessment.action,
            policy_note="按风险等级执行处置动作",
        )

    if endpoint == DEMO_ENDPOINT:
        if security_mode == "vulnerable":
            return SecurityRequestDecision(
                assessment=assessment,
                effective_action=DispositionAction.ALERT,
                policy_note="受控漏洞演示允许运行，高风险评估降级为告警",
            )
        return SecurityRequestDecision(
            assessment=assessment,
            effective_action=DispositionAction.ALLOW,
            policy_note="安全模式不执行演示查询",
        )

    return SecurityRequestDecision(
        assessment=assessment,
        effective_action=DispositionAction.BLOCK,
        policy_note="高风险输入已拦截",
    )
