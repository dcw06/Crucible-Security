from code_pipeline import is_approved


def test_approval_is_exact():
    assert is_approved("APPROVED") is True
    assert is_approved("APPROVED with caveats") is False
