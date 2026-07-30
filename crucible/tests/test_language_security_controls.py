"""Completeness tests for language-specific security detector profiles."""

from language_security_controls import (
    EXPECTED_LANGUAGE_COUNT,
    LANGUAGE_SECURITY_CONTROLS,
    detected_languages,
    language_controls_prompt,
    validate_language_catalog,
)


def test_all_requested_language_profiles_exist():
    validate_language_catalog()
    assert set(LANGUAGE_SECURITY_CONTROLS) == {
        "Web", "Python", "Java", "JavaScript", "TypeScript", "C", "C++", "C#",
    }
    assert len(LANGUAGE_SECURITY_CONTROLS) == EXPECTED_LANGUAGE_COUNT == 8


def test_every_profile_entry_reaches_claude_prompt():
    prompt = language_controls_prompt()
    for language, profile in LANGUAGE_SECURITY_CONTROLS.items():
        assert f"{language}:" in prompt
        for group, entries in profile.items():
            if group == "extensions":
                continue
            for entry in entries:
                assert f"- {entry}" in prompt


def test_language_detection_handles_overlapping_web_and_native_extensions():
    assert detected_languages({".py", ".tsx", ".h", ".cs"}) == [
        "Python", "TypeScript", "C", "C#",
    ]


def test_language_detection_recognizes_web_component_files():
    assert detected_languages({".html", ".vue", ".svelte"}) == ["Web"]


def test_named_high_risk_patterns_are_preserved():
    prompt = language_controls_prompt()
    required = {
        "pickle.loads()", "subprocess.run(..., shell=True)",
        "ObjectInputStream.readObject()", "React dangerouslySetInnerHTML",
        'localStorage.setItem("token", ...)', "const input: any = req.body",
        "gets()", "reinterpret_cast<>()", "BinaryFormatter.Deserialize()",
    }
    assert all(pattern in prompt for pattern in required)
