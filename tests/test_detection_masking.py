from src.security.detection import MAX_MASKED_PAYLOAD_LENGTH, mask_parameters


def test_masking_reports_structure_without_raw_text():
    masked = mask_parameters({"q": "UNION SELECT"})

    assert "q{len=12" in masked
    assert "alpha=11" in masked
    assert "space=1" in masked
    assert "UNION" not in masked
    assert "SELECT" not in masked


def test_masking_counts_quotes_and_symbols():
    masked = mask_parameters({"q": "x' OR 1=1"})

    assert "quote=1" in masked
    assert "digit=2" in masked
    assert "symbol=1" in masked
    assert "x' OR" not in masked


def test_masking_handles_repeated_parameters():
    masked = mask_parameters({"q": ["first", "second"]})

    assert "q[0]{len=5" in masked
    assert "q[1]{len=6" in masked
    assert "first" not in masked
    assert "second" not in masked


def test_masking_truncates_many_parameter_summaries():
    masked = mask_parameters(
        {f"q{index}": "value" for index in range(100)}
    )

    assert len(masked) <= MAX_MASKED_PAYLOAD_LENGTH
    assert masked.endswith("...[truncated]")


def test_masking_handles_empty_and_scalar_values():
    assert mask_parameters({}) == "(empty)"
    assert "flag{len=4, alpha=4" in mask_parameters({"flag": True})
