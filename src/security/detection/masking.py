"""Non-reversible summaries for payloads that must not be logged verbatim."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any


MAX_MASKED_PAYLOAD_LENGTH = 600
QUOTE_CHARACTERS = {'"', "'", "`"}


def _summarize_value(value: str) -> str:
    counts = {
        "alpha": 0,
        "digit": 0,
        "space": 0,
        "quote": 0,
        "symbol": 0,
        "control": 0,
    }

    for character in value:
        if character.isalpha():
            counts["alpha"] += 1
        elif character.isdigit():
            counts["digit"] += 1
        elif character.isspace():
            counts["space"] += 1
        elif character in QUOTE_CHARACTERS:
            counts["quote"] += 1
        elif ord(character) < 32 or ord(character) == 127:
            counts["control"] += 1
        else:
            counts["symbol"] += 1

    details = ", ".join(f"{name}={count}" for name, count in counts.items())
    return f"len={len(value)}, {details}"


def mask_parameters(parameters: Mapping[str, Any]) -> str:
    """Return parameter lengths and character-class counts without raw values."""

    descriptions: list[str] = []

    for parameter_name, value in parameters.items():
        if value is None:
            continue

        if isinstance(value, (str, int, float, bool)):
            descriptions.append(
                f"{parameter_name}{{{_summarize_value(str(value))}}}"
            )
            continue

        if isinstance(value, Sequence) and not isinstance(
            value, (bytes, bytearray)
        ):
            for index, item in enumerate(value):
                if isinstance(item, (str, int, float, bool)):
                    descriptions.append(
                        f"{parameter_name}[{index}]"
                        f"{{{_summarize_value(str(item))}}}"
                    )

    if not descriptions:
        return "(empty)"

    masked = "; ".join(descriptions)
    if len(masked) > MAX_MASKED_PAYLOAD_LENGTH:
        return masked[: MAX_MASKED_PAYLOAD_LENGTH - 14] + "...[truncated]"
    return masked
