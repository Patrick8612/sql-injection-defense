"""Controlled same-input comparisons between vulnerable and safe queries."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from ..database import get_db
from ..security.detection import (
    analyze_parameters,
    assess_detection,
    mask_parameters,
)
from ..security.validation import InputValidationError
from .articles import search_articles
from .sql_injection_demo import run_demo_query


@dataclass(frozen=True, slots=True)
class ComparisonCase:
    """One fixed and repeatable comparison experiment."""

    code: str
    name: str
    scenario: str
    parameter: str


COMPARISON_CASES = (
    ComparisonCase(
        code="C-01",
        name="正常中文关键词",
        scenario="normal",
        parameter="参数化",
    ),
    ComparisonCase(
        code="C-02",
        name="普通特殊字符",
        scenario="error",
        parameter="O'Reilly",
    ),
    ComparisonCase(
        code="C-03",
        name="联合查询",
        scenario="union",
        parameter=(
            "x%' OR 1=1 UNION SELECT 900, '对照演示行', '虚构', '本地演示' --"
        ),
    ),
    ComparisonCase(
        code="C-04",
        name="布尔条件真",
        scenario="boolean",
        parameter="1 = 1",
    ),
    ComparisonCase(
        code="C-05",
        name="布尔条件假",
        scenario="boolean",
        parameter="1 = 2",
    ),
    ComparisonCase(
        code="C-06",
        name="重复编码",
        scenario="error",
        parameter="%2527%2520OR%25201%253D1",
    ),
)


def _conclusion(
    *,
    vulnerable_success: bool,
    vulnerable_count: int,
    safe_success: bool,
    safe_count: int,
    risk_level: str,
) -> str:
    if not vulnerable_success and safe_success:
        return "漏洞查询失败，安全查询保持结构稳定"
    if vulnerable_success and not safe_success:
        return "安全侧输入校验拦截异常参数"
    if vulnerable_count != safe_count:
        return "相同输入在两侧产生不同返回数量"
    if risk_level in {"medium", "high"}:
        return "两侧数量相同，但检测模块识别到注入风险特征"
    if not vulnerable_success and not safe_success:
        return "两侧均未完成查询，需检查固定用例"
    return "两侧完成查询且返回数量一致"


def run_comparison_experiment() -> int:
    """Execute all fixed cases and persist a sanitized comparison run."""

    result_rows = []

    for order, case in enumerate(COMPARISON_CASES, 1):
        vulnerable = run_demo_query(case.scenario, case.parameter)

        safe_success = True
        safe_count = 0
        safe_error = None
        try:
            safe_rows = search_articles(keyword=case.parameter)
            safe_count = len(safe_rows)
        except InputValidationError as error:
            safe_success = False
            safe_error = error.message
        except sqlite3.Error:
            safe_success = False
            safe_error = "安全查询未完成，系统已隐藏数据库细节。"

        detection = analyze_parameters({"q": case.parameter})
        assessment = assess_detection(detection)
        vulnerable_success = vulnerable.error is None
        conclusion = _conclusion(
            vulnerable_success=vulnerable_success,
            vulnerable_count=vulnerable.match_count,
            safe_success=safe_success,
            safe_count=safe_count,
            risk_level=assessment.level.value,
        )

        result_rows.append(
            (
                order,
                case.code,
                case.name,
                case.scenario,
                mask_parameters({"q": case.parameter}),
                1 if vulnerable_success else 0,
                vulnerable.match_count,
                vulnerable.error,
                1 if safe_success else 0,
                safe_count,
                safe_error,
                assessment.level.value,
                assessment.score,
                assessment.action.value,
                ",".join(assessment.matched_rule_codes),
                conclusion,
            )
        )

    db = get_db()
    with db:
        cursor = db.execute("INSERT INTO comparison_runs DEFAULT VALUES")
        run_id = int(cursor.lastrowid)
        db.executemany(
            """
            INSERT INTO comparison_results (
                run_id,
                case_order,
                case_code,
                case_name,
                scenario,
                parameter_masked,
                vulnerable_success,
                vulnerable_count,
                vulnerable_error,
                safe_success,
                safe_count,
                safe_error,
                risk_level,
                risk_score,
                suggested_action,
                rule_codes,
                conclusion
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (run_id, *row)
                for row in result_rows
            ],
        )

    return run_id


def list_comparison_runs(limit: int = 10):
    """Return recent comparison runs with aggregate case counts."""

    bounded_limit = min(max(int(limit), 1), 50)
    return get_db().execute(
        """
        SELECT
            runs.id,
            runs.created_at,
            COUNT(results.id) AS case_count,
            COALESCE(SUM(
                CASE WHEN results.risk_level = 'high' THEN 1 ELSE 0 END
            ), 0) AS high_count
        FROM comparison_runs AS runs
        LEFT JOIN comparison_results AS results
            ON results.run_id = runs.id
        GROUP BY runs.id, runs.created_at
        ORDER BY runs.id DESC
        LIMIT ?
        """,
        (bounded_limit,),
    ).fetchall()


def get_comparison_run(run_id: int):
    """Return one comparison run or None."""

    return get_db().execute(
        "SELECT id, created_at FROM comparison_runs WHERE id = ?",
        (run_id,),
    ).fetchone()


def list_comparison_results(run_id: int):
    """Return ordered, sanitized case results for one comparison run."""

    return get_db().execute(
        """
        SELECT case_order, case_code, case_name, scenario, parameter_masked,
               vulnerable_success, vulnerable_count, vulnerable_error,
               safe_success, safe_count, safe_error,
               risk_level, risk_score, suggested_action, rule_codes,
               conclusion
        FROM comparison_results
        WHERE run_id = ?
        ORDER BY case_order
        """,
        (run_id,),
    ).fetchall()
