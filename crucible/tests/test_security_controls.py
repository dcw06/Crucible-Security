"""Completeness tests for the user-defined application-security catalog."""

from security_controls import (
    EXPECTED_CATEGORY_COUNT,
    EXPECTED_CONTROL_COUNT,
    SECURITY_CONTROLS,
    PRODUCT_CONTROLS,
    controls_prompt,
    validate_catalog,
)


EXPECTED_CATEGORIES = {
    "Database and Data Security",
    "Login and Authentication Security",
    "Chat and Communication Privacy",
    "Authorization and Access Control",
    "API Security",
    "Session and Token Security",
    "File Upload Security",
    "Web Application Security",
    "Privacy and Personal Information",
    "Logging and Monitoring",
    "Third-Party Integration Security",
    "Abuse and Content Safety",
    "Infrastructure and Deployment Security",
    "Availability and Reliability",
    "Mobile and Device Security",
}


def test_catalog_has_every_category_and_control():
    validate_catalog()
    assert set(SECURITY_CONTROLS) == EXPECTED_CATEGORIES
    assert len(SECURITY_CONTROLS) == EXPECTED_CATEGORY_COUNT == 15
    assert sum(map(len, SECURITY_CONTROLS.values())) == EXPECTED_CONTROL_COUNT == 87


def test_prompt_contains_every_catalog_entry():
    prompt = controls_prompt()
    for category, controls in SECURITY_CONTROLS.items():
        assert category in prompt
        for control in controls:
            assert control in prompt
    assert len(PRODUCT_CONTROLS) == 87
    assert len(set(PRODUCT_CONTROLS)) == 87


def test_high_risk_controls_are_explicit():
    prompt = controls_prompt()
    required_phrases = {
        "SQL injection prevention",
        "Avoiding storage of passwords in plain text",
        "Secure Google, Facebook, Microsoft, Apple, WhatsApp, and other OAuth logins",
        "End-to-end encryption",
        "Preventing IDOR through changed IDs in URLs or APIs",
        "Secure cookies using HttpOnly, Secure, and SameSite",
        "Malware scanning",
        "Cross-site scripting prevention",
        "Preventing passwords, tokens, and private messages from appearing in logs",
        "Scanning dependencies for vulnerabilities",
        "Protection against denial-of-service attacks",
        "Hiding sensitive information when the app enters the background",
    }
    assert all(phrase in prompt for phrase in required_phrases)
