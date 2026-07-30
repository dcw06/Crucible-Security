"""Security control catalog shared by the Writer and uploaded-app reviewer."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

SECURITY_CONTROLS: dict[str, list[str]] = {
    "Database and Data Security": [
        "SQL injection prevention", "Database encryption", "Secure backups and recovery",
        "Restricting database access", "Preventing unauthorized data modification",
        "Avoiding storage of passwords in plain text",
    ],
    "Login and Authentication Security": [
        "Secure Google, Facebook, Microsoft, Apple, WhatsApp, and other OAuth logins",
        "Secure password hashing", "Multi-factor authentication", "Password reset security",
        "Protection against brute-force login attempts", "Secure logout and session invalidation",
        "Preventing account takeover", "Email or phone verification",
    ],
    "Chat and Communication Privacy": [
        "End-to-end encryption", "Secure storage of chat history",
        "Preventing unauthorized users from reading messages",
        "Message deletion and retention policies", "Blocking, muting, and reporting users",
        "Protection against screenshots or message forwarding where applicable",
        "Preventing sensitive information from appearing in notifications",
    ],
    "Authorization and Access Control": [
        "Role-based access control", "Ensuring users can access only their own data",
        "Admin permission restrictions", "Preventing IDOR through changed IDs in URLs or APIs",
        "Separating regular-user and administrator functions",
    ],
    "API Security": [
        "Authentication for every protected API endpoint", "Input validation and sanitization",
        "API rate limiting", "Protection against replay attacks", "Secure API keys and secrets",
        "Preventing excessive data exposure in API responses",
    ],
    "Session and Token Security": [
        "Secure JWT or session-token storage", "Token expiration and refresh",
        "Revoking tokens after logout or password changes",
        "Secure cookies using HttpOnly, Secure, and SameSite",
        "Protection against session hijacking",
    ],
    "File Upload Security": [
        "Restricting file types and sizes", "Malware scanning",
        "Preventing executable-file uploads", "Randomizing stored filenames",
        "Preventing users from accessing other users' files",
        "Removing sensitive image metadata",
    ],
    "Web Application Security": [
        "Cross-site scripting prevention", "Cross-site request forgery protection",
        "Clickjacking protection", "Content Security Policy", "Secure HTTPS connections",
        "Safe handling of redirects and external links",
    ],
    "Privacy and Personal Information": [
        "Collecting only necessary personal data", "Encrypting sensitive information",
        "Allowing users to download or delete their data", "Clear privacy policies and consent",
        "Protecting phone numbers, emails, locations, and payment information",
        "Avoiding unnecessary tracking",
    ],
    "Logging and Monitoring": [
        "Recording suspicious login attempts", "Monitoring unusual account activity",
        "Maintaining security audit logs",
        "Preventing passwords, tokens, and private messages from appearing in logs",
        "Alerting administrators about attacks or system failures",
    ],
    "Third-Party Integration Security": [
        "Verifying OAuth providers and callback URLs", "Limiting third-party permissions",
        "Protecting third-party API credentials", "Reviewing third-party SDK data collection",
        "Handling compromised or unavailable external services",
    ],
    "Abuse and Content Safety": [
        "Spam prevention", "Bot detection", "Harassment and impersonation reporting",
        "Malicious-link detection", "Preventing phishing through chat",
        "Moderation tools for harmful or illegal content",
    ],
    "Infrastructure and Deployment Security": [
        "Keeping libraries and dependencies updated",
        "Scanning dependencies for vulnerabilities",
        "Separating development and production environments",
        "Protecting environment variables", "Configuring firewalls and cloud permissions",
        "Preventing debug information from being exposed in production",
    ],
    "Availability and Reliability": [
        "Protection against denial-of-service attacks", "Rate limits for expensive operations",
        "Database and server backups", "Disaster recovery procedures",
        "Preventing one user from overloading the system",
    ],
    "Mobile and Device Security": [
        "Secure local storage", "Avoiding passwords or tokens in plain-text device storage",
        "Biometric login protection", "Detecting rooted or jailbroken devices where necessary",
        "Hiding sensitive information when the app enters the background",
    ],
}

EXPECTED_CATEGORY_COUNT = 15
EXPECTED_CONTROL_COUNT = 87


class VerificationMode(str, Enum):
    STATIC = "STATIC"
    DYNAMIC = "DYNAMIC"
    INFRASTRUCTURE = "INFRASTRUCTURE"
    DOCUMENTATION = "DOCUMENTATION"
    MANUAL = "MANUAL"
    DEDICATED_SCANNER = "DEDICATED_SCANNER"


@dataclass(frozen=True)
class ProductControl:
    id: str
    category: str
    name: str
    verification_modes: frozenset[VerificationMode]


_PREFIXES = {
    "Database and Data Security": "DATA",
    "Login and Authentication Security": "AUTH",
    "Chat and Communication Privacy": "CHAT",
    "Authorization and Access Control": "ACCESS",
    "API Security": "API",
    "Session and Token Security": "TOKEN",
    "File Upload Security": "FILE",
    "Web Application Security": "WEB",
    "Privacy and Personal Information": "PRIV",
    "Logging and Monitoring": "LOG",
    "Third-Party Integration Security": "THIRD",
    "Abuse and Content Safety": "ABUSE",
    "Infrastructure and Deployment Security": "INFRA",
    "Availability and Reliability": "AVAIL",
    "Mobile and Device Security": "MOBILE",
}


def _verification_modes(name: str) -> frozenset[VerificationMode]:
    lowered = name.lower()
    if "malware scanning" in lowered or "scanning dependencies" in lowered:
        return frozenset({VerificationMode.DEDICATED_SCANNER})
    if any(term in lowered for term in (
        "backup", "recovery", "firewall", "cloud permissions", "alerting administrators",
        "monitoring unusual", "denial-of-service",
    )):
        return frozenset({VerificationMode.INFRASTRUCTURE, VerificationMode.MANUAL})
    if any(term in lowered for term in (
        "privacy policies", "consent", "data collection", "retention policies",
        "sdk data collection", "moderation tools", "harassment", "reporting users",
        "screenshot", "message forwarding", "tracking",
    )):
        return frozenset({VerificationMode.DOCUMENTATION, VerificationMode.MANUAL})
    return frozenset({VerificationMode.STATIC, VerificationMode.DYNAMIC})


PRODUCT_CONTROLS: dict[str, ProductControl] = {}
for _category, _controls in SECURITY_CONTROLS.items():
    for _index, _name in enumerate(_controls, 1):
        _control_id = f"{_PREFIXES[_category]}-{_index:03d}"
        PRODUCT_CONTROLS[_control_id] = ProductControl(
            id=_control_id,
            category=_category,
            name=_name,
            verification_modes=_verification_modes(_name),
        )


def controls_prompt() -> str:
    lines: list[str] = []
    for category in SECURITY_CONTROLS:
        lines.append(f"{category}:")
        lines.extend(
            f"- {control.id}: {control.name} "
            f"[verification={','.join(sorted(mode.value for mode in control.verification_modes))}]"
            for control in PRODUCT_CONTROLS.values() if control.category == category
        )
    return "\n".join(lines)


def validate_catalog() -> None:
    """Fail fast if a category/control is accidentally removed or duplicated."""
    category_count = len(SECURITY_CONTROLS)
    controls = [
        control
        for category_controls in SECURITY_CONTROLS.values()
        for control in category_controls
    ]
    if category_count != EXPECTED_CATEGORY_COUNT:
        raise RuntimeError(
            f"Security catalog has {category_count} categories; "
            f"expected {EXPECTED_CATEGORY_COUNT}."
        )
    if len(controls) != EXPECTED_CONTROL_COUNT:
        raise RuntimeError(
            f"Security catalog has {len(controls)} controls; "
            f"expected {EXPECTED_CONTROL_COUNT}."
        )
    if len(controls) != len(set(controls)):
        raise RuntimeError("Security catalog contains duplicate controls.")
    if len(PRODUCT_CONTROLS) != EXPECTED_CONTROL_COUNT:
        raise RuntimeError("Stable product-control ID catalog is incomplete.")
    if any(not category.strip() for category in SECURITY_CONTROLS):
        raise RuntimeError("Security catalog contains an empty category.")
    if any(not control.strip() for control in controls):
        raise RuntimeError("Security catalog contains an empty control.")


validate_catalog()
