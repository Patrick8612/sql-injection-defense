import pytest

from src.security.validation import (
    InputValidationError,
    validate_choice,
    validate_password,
    validate_text,
)


def test_text_validation_trims_and_accepts_normal_input():
    assert validate_text(
        "  参数化查询  ",
        field="关键词",
        max_length=80,
    ) == "参数化查询"


def test_text_validation_rejects_overlength_instead_of_truncating():
    with pytest.raises(InputValidationError) as error:
        validate_text("a" * 81, field="关键词", max_length=80)

    assert error.value.field == "关键词"
    assert "最多允许 80" in error.value.message


def test_text_validation_rejects_control_characters():
    with pytest.raises(InputValidationError):
        validate_text("safe\nvalue", field="关键词", max_length=80)


def test_required_text_rejects_blank_value():
    with pytest.raises(InputValidationError):
        validate_text("   ", field="用户名", max_length=80, required=True)


def test_password_validation_preserves_spaces_but_limits_length():
    assert validate_password(" pass word ") == " pass word "

    with pytest.raises(InputValidationError):
        validate_password("x" * 201)


def test_password_validation_rejects_null_byte():
    with pytest.raises(InputValidationError):
        validate_password("safe\x00password")


def test_choice_validation_uses_explicit_allowlist():
    assert validate_choice(
        "safe",
        field="运行模式",
        allowed_values=("safe", "vulnerable"),
    ) == "safe"

    with pytest.raises(InputValidationError):
        validate_choice(
            "unsafe",
            field="运行模式",
            allowed_values=("safe", "vulnerable"),
        )


def test_blank_choice_can_be_allowed():
    assert validate_choice(
        "",
        field="分类",
        allowed_values=("安全防护",),
        allow_blank=True,
    ) == ""
