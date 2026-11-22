"""Generate reproducible experiment reports from persisted measurements."""

from __future__ import annotations

from datetime import datetime
from importlib.metadata import version
from platform import python_version

from ..database import get_db
from ..security.detection import RiskLevel
from .comparison import get_comparison_run, list_comparison_results
from .detection_logs import (
    ACTION_LABELS,
    RISK_LEVEL_LABELS,
    get_detection_summary,
    list_recent_detections,
)
from .settings import get_security_mode, security_mode_label


def _markdown_cell(value: object) -> str:
    text = "" if value is None else str(value)
    return text.replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _outcome(success: int, count: int, error: str | None) -> str:
    status = "完成" if success else "未完成"
    detail = error or "无错误"
    return f"{status}；返回 {count} 条；{detail}"


def _build_markdown(run_id: int) -> str:
    run = get_comparison_run(run_id)
    if run is None:
        raise ValueError("comparison run not found")

    results = list_comparison_results(run_id)
    detection_summary = get_detection_summary()
    recent_detections = list_recent_detections(limit=20)
    current_mode = get_security_mode()
    generated_at = datetime.now().astimezone().isoformat(timespec="seconds")

    differing_cases = sum(
        row["vulnerable_count"] != row["safe_count"]
        for row in results
    )
    vulnerable_failures = sum(
        not bool(row["vulnerable_success"])
        for row in results
    )
    safe_failures = sum(
        not bool(row["safe_success"])
        for row in results
    )
    high_risk_cases = sum(
        row["risk_level"] == RiskLevel.HIGH.value
        for row in results
    )

    lines = [
        "# SQL 注入漏洞检测与防御演示系统实验报告",
        "",
        f"- 报告生成时间：{generated_at}",
        f"- 对照实验编号：RUN-{run_id}",
        f"- 实验执行时间：{run['created_at']}（数据库 UTC）",
        f"- 当前系统模式：{security_mode_label(current_mode)}",
        "- 运行地址：`127.0.0.1` 本地实验环境",
        f"- Python：{python_version()}",
        f"- Flask：{version('Flask')}",
        "",
        "## 1. 实验目的",
        "",
        "使用相同输入分别执行隔离漏洞查询和参数化安全查询，"
        "比较完成状态、返回数量、检测风险与处置建议，验证参数化查询的防护效果。",
        "",
        "## 2. 安全边界",
        "",
        "- 仅使用虚构账号、虚构文章和本地 SQLite。",
        "- 漏洞侧仅访问独立只读演示数据库。",
        "- 安全侧使用参数绑定和列级只读权限。",
        "- 对照记录与报告只保存脱敏参数摘要。",
        "- 实验不连接真实业务系统或外部目标。",
        "",
        "## 3. 同输入对照结果",
        "",
        "| 用例 | 场景 | 脱敏输入 | 漏洞查询 | 安全查询 | 风险 | 建议动作 | 结论 |",
        "|---|---|---|---|---|---|---|---|",
    ]

    for item in results:
        lines.append(
            "| "
            + " | ".join(
                [
                    _markdown_cell(f"{item['case_code']} {item['case_name']}"),
                    _markdown_cell(item["scenario"]),
                    _markdown_cell(item["parameter_masked"]),
                    _markdown_cell(
                        _outcome(
                            item["vulnerable_success"],
                            item["vulnerable_count"],
                            item["vulnerable_error"],
                        )
                    ),
                    _markdown_cell(
                        _outcome(
                            item["safe_success"],
                            item["safe_count"],
                            item["safe_error"],
                        )
                    ),
                    _markdown_cell(
                        f"{RISK_LEVEL_LABELS.get(item['risk_level'], item['risk_level'])}"
                        f" / {item['risk_score']} 分"
                    ),
                    _markdown_cell(
                        ACTION_LABELS.get(
                            item["suggested_action"],
                            item["suggested_action"],
                        )
                    ),
                    _markdown_cell(item["conclusion"]),
                ]
            )
            + " |"
        )

    lines.extend(
        [
            "",
            "## 4. 检测日志统计",
            "",
            f"- 检测总数：{detection_summary.total}",
            f"- 低风险：{detection_summary.low}",
            f"- 中风险：{detection_summary.medium}",
            f"- 高风险：{detection_summary.high}",
            f"- 放行：{detection_summary.allow}",
            f"- 告警：{detection_summary.alert}",
            f"- 拦截：{detection_summary.block}",
            f"- 最近检测时间：{detection_summary.last_detected_at or '暂无记录'}",
            "",
            "### 最近检测记录",
            "",
            "| 编号 | 类型 | 路由 | 风险 | 分值 | 动作 | 时间 |",
            "|---|---|---|---|---|---|---|",
        ]
    )

    if recent_detections:
        for item in recent_detections:
            lines.append(
                "| "
                + " | ".join(
                    [
                        f"D-{item['id']}",
                        _markdown_cell(item["attack_type"]),
                        _markdown_cell(item["endpoint"]),
                        _markdown_cell(
                            RISK_LEVEL_LABELS.get(
                                item["risk_level"],
                                item["risk_level"],
                            )
                        ),
                        str(item["score"]),
                        _markdown_cell(
                            ACTION_LABELS.get(item["action"], item["action"])
                        ),
                        _markdown_cell(item["created_at"]),
                    ]
                )
                + " |"
            )
    else:
        lines.append("| - | 暂无检测记录 | - | - | - | - | - |")

    lines.extend(
        [
            "",
            "## 5. 结果分析",
            "",
            f"- 固定用例总数：{len(results)}。",
            f"- 漏洞侧未完成查询：{vulnerable_failures} 个。",
            f"- 安全侧未完成查询：{safe_failures} 个。",
            f"- 两侧返回数量不同：{differing_cases} 个。",
            f"- 高风险用例：{high_risk_cases} 个。",
            "",
            "漏洞侧用于观察不安全拼接造成的结构变化；"
            "安全侧使用参数绑定，将输入作为数据处理。"
            "两侧返回数量相同的用例仍需结合风险规则判断，"
            "不能仅凭结果数量认定输入安全。",
            "",
            "## 6. 结论与不足",
            "",
            "本次报告中的用例、数量、风险和日志统计均直接读取自系统数据库。"
            "实验表明安全查询能够保持 SQL 结构稳定，"
            "同时检测模块可对逻辑条件、编码和关键字特征生成风险信号。",
            "",
            "当前不足包括：检测规则可能产生误报或漏报；"
            "请求频率窗口保存在内存中，应用重启后清空；"
            "实验仅覆盖本地 SQLite 虚构数据，不能代替真实业务系统性能测试。",
            "",
            "---",
            "",
            "本报告是课程论文的实验数据来源，不替代论文中的背景、"
            "文献综述、学术分析、创新点和完整论证。",
        ]
    )

    return "\n".join(lines) + "\n"


def generate_experiment_report(run_id: int) -> int:
    """Create and persist a Markdown snapshot for one comparison run."""

    content = _build_markdown(run_id)
    generated_at = datetime.now().astimezone().isoformat(timespec="seconds")
    db = get_db()
    with db:
        cursor = db.execute(
            """
            INSERT INTO experiment_reports (
                comparison_run_id,
                generated_at,
                content_markdown
            )
            VALUES (?, ?, ?)
            """,
            (run_id, generated_at, content),
        )
    return int(cursor.lastrowid)


def list_experiment_reports(limit: int = 20):
    """Return recent persisted experiment reports."""

    bounded_limit = min(max(int(limit), 1), 100)
    return get_db().execute(
        """
        SELECT reports.id, reports.comparison_run_id,
               reports.generated_at
        FROM experiment_reports AS reports
        ORDER BY reports.id DESC
        LIMIT ?
        """,
        (bounded_limit,),
    ).fetchall()


def get_experiment_report(report_id: int):
    """Return one persisted experiment report or None."""

    return get_db().execute(
        """
        SELECT id, comparison_run_id, generated_at, content_markdown
        FROM experiment_reports
        WHERE id = ?
        """,
        (report_id,),
    ).fetchone()
