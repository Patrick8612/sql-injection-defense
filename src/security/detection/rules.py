"""Initial stateless rules for the SQL injection detector."""

from __future__ import annotations

import re

from .models import DetectionContext, DetectionRule


DEFAULT_MAX_PARAMETER_LENGTH = 120
SQL_KEYWORD_THRESHOLD = 1

SQL_KEYWORDS = (
    "ALTER",
    "ATTACH",
    "CREATE",
    "DELETE",
    "DETACH",
    "DROP",
    "EXEC",
    "INSERT",
    "PRAGMA",
    "REPLACE",
    "SELECT",
    "TRUNCATE",
    "UNION",
    "UPDATE",
)

SQL_KEYWORD_PATTERN = re.compile(
    r"\b(" + "|".join(SQL_KEYWORDS) + r")\b",
    re.IGNORECASE,
)
BOOLEAN_OPERATOR_PATTERN = re.compile(r"\b(?:AND|OR)\b", re.IGNORECASE)
COMPARISON_PATTERN = re.compile(r"(?:<>|!=|<=|>=|=|<|>|\bLIKE\b)", re.IGNORECASE)
ALWAYS_TRUE_PATTERN = re.compile(r"\b\d+\s*=\s*\d+\b")
QUOTE_PATTERN = re.compile(r"""['"`]""")
COMMENT_OR_SEPARATOR_PATTERN = re.compile(r"(?:--|/\*|\*/|;|#)")
SPECIAL_CHARACTER_RUN_PATTERN = re.compile(
    r"""[^\w\s\u4e00-\u9fff]{8,}""",
    re.UNICODE,
)
ENCODED_FRAGMENTS = {
    "%00": "空字节",
    "%0A": "换行编码",
    "%0D": "回车编码",
    "%23": "注释符编码",
    "%27": "单引号编码",
    "%2A": "星号编码",
    "%2D%2D": "注释符编码",
    "%2F%2A": "块注释编码",
    "%3B": "语句分隔符编码",
    "%5C": "反斜杠编码",
}
DOUBLE_ENCODING_PATTERN = re.compile(
    r"%25(?:25)*(?:00|0a|0d|23|27|2a|2d%2d|2f%2a|3b|5c)",
    re.IGNORECASE,
)


def _length_detector(context: DetectionContext) -> str | None:
    length = len(context.raw)
    if length <= DEFAULT_MAX_PARAMETER_LENGTH:
        return None
    return f"长度 {length} 超过阈值 {DEFAULT_MAX_PARAMETER_LENGTH}"


def _sql_keyword_detector(context: DetectionContext) -> str | None:
    keywords = tuple(
        dict.fromkeys(match.group(1).upper() for match in SQL_KEYWORD_PATTERN.finditer(context.normalized))
    )
    if len(keywords) < SQL_KEYWORD_THRESHOLD:
        return None
    return "命中关键字：" + "、".join(keywords)


def _logical_combination_detector(context: DetectionContext) -> str | None:
    text = context.normalized
    has_quote = bool(QUOTE_PATTERN.search(text))
    has_boolean = bool(BOOLEAN_OPERATOR_PATTERN.search(text))
    has_comparison = bool(COMPARISON_PATTERN.search(text))

    if has_quote and has_boolean and has_comparison:
        return "引号、逻辑运算符和比较条件组合出现"
    if ALWAYS_TRUE_PATTERN.search(text):
        return "出现数字恒真比较结构"
    return None


def _comment_or_separator_detector(context: DetectionContext) -> str | None:
    matched = COMMENT_OR_SEPARATOR_PATTERN.search(context.normalized)
    if matched is None:
        return None
    labels = {
        "--": "行注释",
        "/*": "块注释开始",
        "*/": "块注释结束",
        ";": "语句分隔符",
        "#": "注释符",
    }
    return "出现" + labels[matched.group(0)]


def _encoded_payload_detector(context: DetectionContext) -> str | None:
    labels = [
        label
        for fragment, label in ENCODED_FRAGMENTS.items()
        if fragment.lower() in context.raw.lower()
    ]
    if DOUBLE_ENCODING_PATTERN.search(context.raw):
        labels.append("重复编码特征")

    decoded_danger = bool(
        QUOTE_PATTERN.search(context.decoded)
        or COMMENT_OR_SEPARATOR_PATTERN.search(context.decoded)
    )
    if decoded_danger and context.decoded != context.raw:
        labels.append("解码后出现 SQL 结构字符")

    unique_labels = tuple(dict.fromkeys(labels))
    if not unique_labels:
        return None
    return "发现：" + "、".join(unique_labels)


def _special_character_run_detector(context: DetectionContext) -> str | None:
    matched = SPECIAL_CHARACTER_RUN_PATTERN.search(context.normalized)
    if matched is None:
        return None
    return f"连续特殊字符长度 {len(matched.group(0))}"


DEFAULT_RULES = (
    DetectionRule(
        code="PARAM_LENGTH",
        name="参数长度异常",
        category="length",
        message="参数长度超过检测阈值",
        detector=_length_detector,
    ),
    DetectionRule(
        code="SQL_KEYWORD",
        name="SQL 关键字",
        category="syntax",
        message="参数中包含 SQL 关键字",
        detector=_sql_keyword_detector,
    ),
    DetectionRule(
        code="LOGICAL_COMBINATION",
        name="逻辑条件组合",
        category="logic",
        message="参数中出现可用于改变条件的逻辑结构",
        detector=_logical_combination_detector,
    ),
    DetectionRule(
        code="COMMENT_OR_SEPARATOR",
        name="注释或语句分隔符",
        category="syntax",
        message="参数中出现注释符或语句分隔符",
        detector=_comment_or_separator_detector,
    ),
    DetectionRule(
        code="ENCODED_PAYLOAD",
        name="异常编码",
        category="encoding",
        message="参数中出现可疑编码或重复编码",
        detector=_encoded_payload_detector,
    ),
    DetectionRule(
        code="SPECIAL_CHARACTER_RUN",
        name="连续特殊字符",
        category="structure",
        message="参数中出现异常长度的连续特殊字符",
        detector=_special_character_run_detector,
    ),
)
