from src.security.detection import (
    DEFAULT_RULES,
    analyze_parameter,
    analyze_parameters,
)


def finding_codes(**kwargs):
    return tuple(finding.rule_code for finding in analyze_parameter(**kwargs))


def test_benign_text_does_not_trigger_rules():
    assert finding_codes(parameter_name="q", value="参数化查询") == ()
    assert finding_codes(parameter_name="q", value="O'Reilly") == ()


def test_benign_percent_encoded_unicode_does_not_trigger_rules():
    parameter = "%E5%8F%82%E6%95%B0%E5%8C%96"

    assert finding_codes(parameter_name="q", value=parameter) == ()


def test_length_rule_reports_only_length_information():
    findings = analyze_parameter(
        "q",
        "a" * 121,
    )

    assert [finding.rule_code for finding in findings] == ["PARAM_LENGTH"]
    assert "121" in findings[0].evidence
    assert "a" * 20 not in findings[0].evidence


def test_sql_keyword_rule_is_case_insensitive_and_deduplicated():
    findings = analyze_parameter("q", "union select UNION")

    assert [finding.rule_code for finding in findings] == ["SQL_KEYWORD"]
    assert "UNION" in findings[0].evidence
    assert "SELECT" in findings[0].evidence


def test_logical_combination_rule_detects_quote_boolean_and_comparison():
    codes = finding_codes(parameter_name="q", value="x' OR 1=1")

    assert "LOGICAL_COMBINATION" in codes


def test_logical_combination_rule_normalizes_fullwidth_quote():
    codes = finding_codes(parameter_name="q", value="＇ OR 1=1")

    assert "LOGICAL_COMBINATION" in codes


def test_comment_or_separator_rule_detects_multiple_forms():
    for parameter in ("abc -- tail", "abc; next", "abc /* tail"):
        codes = finding_codes(parameter_name="q", value=parameter)
        assert "COMMENT_OR_SEPARATOR" in codes


def test_encoded_payload_rule_detects_double_encoding():
    codes = finding_codes(
        parameter_name="q",
        value="%2527%2520OR%25201%253D1",
    )

    assert "ENCODED_PAYLOAD" in codes
    assert "LOGICAL_COMBINATION" in codes


def test_special_character_run_rule_detects_long_symbol_sequence():
    assert finding_codes(parameter_name="q", value="!!!!!!!!!") == (
        "SPECIAL_CHARACTER_RUN",
    )


def test_multiple_parameters_and_repeated_values_are_counted():
    result = analyze_parameters(
        {
            "q": ["hello", "x' OR 1=1"],
            "category": "安全防护",
            "empty": None,
        }
    )

    assert result.parameters_checked == 3
    assert result.matched is True
    assert any(
        finding.parameter_path == "q[1]"
        and finding.rule_code == "LOGICAL_COMBINATION"
        for finding in result.findings
    )


def test_findings_do_not_echo_the_complete_parameter():
    secret_marker = "private-marker"
    findings = analyze_parameter(
        "q",
        f"{secret_marker}-" + "a" * 150,
    )

    assert findings
    assert all(secret_marker not in finding.evidence for finding in findings)


def test_rule_metadata_is_unique_and_stable():
    codes = [rule.code for rule in DEFAULT_RULES]

    assert len(codes) == len(set(codes))
    assert codes == [
        "PARAM_LENGTH",
        "SQL_KEYWORD",
        "LOGICAL_COMBINATION",
        "COMMENT_OR_SEPARATOR",
        "ENCODED_PAYLOAD",
        "SPECIAL_CHARACTER_RUN",
    ]
