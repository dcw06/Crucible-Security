"""Strict model-output contracts for requirements, Writer, and Critic."""

from agents.critic import is_approved
from agents.requirements_analyzer import _parse_requirements


def test_critic_approval_must_be_exact():
    assert is_approved("APPROVED") is True
    assert is_approved("APPROVED with caveats") is False
    assert is_approved(" approved ") is False


def test_requirements_are_deduplicated_and_priorities_are_validated():
    raw = """[
      {"req_id":"REQ-1","description":"first","priority":"high"},
      {"req_id":"REQ-1","description":"duplicate","priority":"LOW"},
      {"req_id":"REQ-2","description":"bad priority","priority":"URGENT"},
      {"req_id":"","description":"empty id","priority":"LOW"},
      {"req_id":"REQ-3","description":"third","priority":"medium"}
    ]"""
    assert _parse_requirements(raw) == [
        {"req_id": "REQ-1", "description": "first", "priority": "HIGH"},
        {"req_id": "REQ-3", "description": "third", "priority": "MEDIUM"},
    ]
