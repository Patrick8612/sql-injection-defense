"""Small, explicit validators for request inputs used by business routes."""

from __future__ import annotations

from collections.abc import Iterable


MAX_SEARCH_KEYWORD_LENGTH = 80
MAX_CATEGORY_LENGTH = 40
MAX_USERNAME_LENGTH = 80
MAX_PASSWORD_LENGTH = 200


class InputValidationError(ValueError):
    """A user-facing request validation failure."""

    def __init__(self, field: str, message: str) -> None:
        super().__init__(message)
        self.field = field
        self.message = message


def validate_text(
    value: str | None,
    *,
    field: str,
    max_length: int,
    required: bool = False,
) -> str:
    """Validate single-line text without silently truncating the input."""

    text = "" if value is None else value.strip()
    if required and not text:
        raise InputValidationError(field, "该字段不能为空。")
    if len(text) > max_length:
        raise InputValidationError(
            field,
            f"{field}最多允许 {max_length} 个字符。",
        )
    if any(ord(character) < 32 or ord(character) == 127 for character in text):
        raise InputValidationError(field, f"{field}包含不允许的控制字符。")
    return text


def validate_password(value: str | None) -> str:
    """Validate password length and control characters without trimming it."""

    password = "" if value is None else value
    if len(password) > MAX_PASSWORD_LENGTH:
        raise InputValidationError(
            "password",
            f"密码最多允许 {MAX_PASSWORD_LENGTH} 个字符。",
        )
    if "\x00" in password:
        raise InputValidationError("password", "密码包含空字节。")
    return password


def validate_choice(
    value: str,
    *,
    field: str,
    allowed_values: Iterable[str],
    allow_blank: bool = False,
) -> str:
    """Require a value from an explicit allowlist."""

    choices = tuple(allowed_values)
    if not value and allow_blank:
        return ""
    if value not in choices:
        raise InputValidationError(field, f"{field}不在允许范围内。")
    return value
