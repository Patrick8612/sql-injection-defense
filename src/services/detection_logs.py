"""Persist sanitized detection decisions in the application database."""

from __future__ import annotations

from dataclasses import dataclass

from ..database import get_db
from ..security.detection.scoring import (
    DispositionAction,
    RiskAssessment,
    RiskLevel,
)

RISK_LEVEL_LABELS = {
    "low": "低风险",
    "medium": "中风险",
    "high": "高风险",
}

ACTION_LABELS = {
    "allow": "放行",
    "alert": "告警",
    "block": "拦截",
}


@dataclass(frozen=True, slots=True)
class DetectionSummary:
    """Aggregated detection counts derived only from persisted logs."""

    total: int
    low: int
    medium: int
    high: int
    allow: int
    alert: int
    block: int
    last_detected_at: str | None

    def risk_percentage(self, count: int) -> int:
        if self.total == 0:
            return 0
        return round(count / self.total * 100)


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


def get_detection_summary() -> DetectionSummary:
    """Return dashboard totals from the persisted detection log only."""

    row = get_db().execute(
        """
        SELECT
            COUNT(*) AS total,
            COALESCE(SUM(CASE WHEN risk_level = 'low' THEN 1 ELSE 0 END), 0)
                AS low,
            COALESCE(SUM(CASE WHEN risk_level = 'medium' THEN 1 ELSE 0 END), 0)
                AS medium,
            COALESCE(SUM(CASE WHEN risk_level = 'high' THEN 1 ELSE 0 END), 0)
                AS high,
            COALESCE(SUM(CASE WHEN action = 'allow' THEN 1 ELSE 0 END), 0)
                AS allow_count,
            COALESCE(SUM(CASE WHEN action = 'alert' THEN 1 ELSE 0 END), 0)
                AS alert_count,
            COALESCE(SUM(CASE WHEN action = 'block' THEN 1 ELSE 0 END), 0)
                AS block_count,
            MAX(created_at) AS last_detected_at
        FROM detection_logs
        """
    ).fetchone()

    return DetectionSummary(
        total=int(row["total"]),
        low=int(row["low"]),
        medium=int(row["medium"]),
        high=int(row["high"]),
        allow=int(row["allow_count"]),
        alert=int(row["alert_count"]),
        block=int(row["block_count"]),
        last_detected_at=row["last_detected_at"],
    )


def list_recent_detections(limit: int = 20):
    """Return newest detection records up to the requested bounded limit."""

    bounded_limit = min(max(int(limit), 1), 100)
    return get_db().execute(
        """
        SELECT id, attack_type, endpoint, payload_masked, risk_level,
               score, action, created_at
        FROM detection_logs
        ORDER BY id DESC
        LIMIT ?
        """,
        (bounded_limit,),
    ).fetchall()


def get_detection_log(log_id: int):
    """Return one persisted detection record or None."""

    return get_db().execute(
        """
        SELECT id, attack_type, endpoint, payload_masked, risk_level,
               score, action, created_at
        FROM detection_logs
        WHERE id = ?
        """,
        (log_id,),
    ).fetchone()
