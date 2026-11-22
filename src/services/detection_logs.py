"""Persist sanitized detection decisions in the application database."""

from __future__ import annotations

from ..database import get_db
from ..security.detection.scoring import (
    DispositionAction,
    RiskAssessment,
    RiskLevel,
)


def classify_attack_type(rule_codes: tuple[str, ...]) -> str:
    """Map stable rule codes to concise dashboard-friendly categories."""

    codes = set(rule_codes)
    categories: list[str] = []

    sql_codes = {
        "SQL_KEYWORD",
        "LOGICAL_COMBINATION",
        "COMMENT_OR_SEPARATOR",
    }
    if codes & sql_codes:
        categories.append("SQL 注入")
    if "ENCODED_PAYLOAD" in codes:
        categories.append("编码绕过")
    if "REQUEST_FREQUENCY" in codes:
        categories.append("高频请求")
    if not categories:
        categories.append("异常输入")

    return "+".join(categories)


def record_detection(
    assessment: RiskAssessment,
    *,
    endpoint: str,
    payload_masked: str,
    action: DispositionAction,
) -> int:
    """Insert one matched detection with its effective action."""

    if assessment.level is RiskLevel.NONE:
        raise ValueError("risk-free detections must not be persisted")

    db = get_db()
    with db:
        cursor = db.execute(
            """
            INSERT INTO detection_logs (
                attack_type,
                endpoint,
                payload_masked,
                risk_level,
                score,
                action
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                classify_attack_type(assessment.matched_rule_codes),
                endpoint,
                payload_masked,
                assessment.level.value,
                assessment.score,
                action.value,
            ),
        )

    return int(cursor.lastrowid)
