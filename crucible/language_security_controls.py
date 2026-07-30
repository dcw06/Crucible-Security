"""Language, framework, and dangerous-pattern catalog for uploaded-app review."""

from __future__ import annotations

LANGUAGE_SECURITY_CONTROLS: dict[str, dict[str, list[str]]] = {
    "Web": {
        "extensions": [
            ".html", ".htm", ".css", ".scss", ".sass", ".less", ".vue", ".svelte",
        ],
        "common_issues": [
            "Cross-site scripting through unsafe HTML insertion",
            "Missing content security policy",
            "Sensitive information embedded in client assets",
            "Unsafe external scripts or styles",
            "Insecure forms and mixed-content resources",
            "Clickjacking due to missing frame restrictions",
        ],
        "high_risk_patterns": [
            "v-html", "{@html", "javascript:", "http://",
            "target=\"_blank\" without rel=\"noopener\"",
        ],
        "frameworks": ["Vue", "Svelte", "Static HTML"],
        "framework_checks": [
            "Vue v-html with untrusted content",
            "Svelte {@html} with untrusted content",
            "Forms submitting secrets over insecure transport",
            "Third-party resources without integrity controls",
        ],
    },
    "Python": {
        "extensions": [".py"],
        "common_issues": [
            "SQL injection through string-formatted queries",
            "Command injection through os.system, subprocess, or shell execution",
            "Unsafe deserialization with pickle, marshal, or unsafe YAML loading",
            "Path traversal in file-handling code",
            "Server-side request forgery through user-controlled URLs",
            "Hardcoded API keys, passwords, and tokens",
            "Weak random-number generation using random for security purposes",
            "Debug mode enabled in production", "Insecure temporary-file handling",
            "Missing input validation", "Unrestricted file uploads",
            "Regular-expression denial of service",
            "Dependency vulnerabilities in requirements.txt or pyproject.toml",
        ],
        "high_risk_patterns": [
            "eval()", "exec()", "pickle.loads()", "yaml.load()", "os.system()",
            "subprocess.run(..., shell=True)", 'cursor.execute(f"...")',
            "requests.get(user_url)",
        ],
        "frameworks": ["Django", "Flask", "FastAPI"],
        "framework_checks": [
            "Django DEBUG=True", "Missing CSRF protection",
            "Flask secret key hardcoded", "Unprotected FastAPI routes",
            "Overly permissive CORS",
        ],
    },
    "Java": {
        "extensions": [".java"],
        "common_issues": [
            "SQL injection through concatenated queries", "Unsafe Java deserialization",
            "XML external entity attacks", "Command injection through Runtime.exec",
            "Path traversal", "Server-side request forgery", "Insecure reflection",
            "Weak cryptographic algorithms", "Hardcoded credentials",
            "Improper authorization", "Missing Spring Security protection",
            "Mass assignment or automatic object binding", "Log injection",
            "Insecure file uploads", "Dependency vulnerabilities in Maven or Gradle",
        ],
        "high_risk_patterns": [
            "Runtime.getRuntime().exec()", "ObjectInputStream.readObject()",
            "Statement.executeQuery()", "Class.forName(userInput)",
            "new File(basePath, userInput)",
        ],
        "frameworks": ["Spring Boot", "Spring MVC", "Jakarta EE", "Android SDK"],
        "framework_checks": [
            "Disabled CSRF protection", "Publicly exposed Spring Actuator endpoints",
            "Missing authorization annotations", "Overly permissive CORS",
            "Unsafe Spring Expression Language usage",
            "Sensitive information in application.properties",
        ],
    },
    "JavaScript": {
        "extensions": [".js", ".jsx", ".mjs", ".cjs"],
        "common_issues": [
            "Cross-site scripting", "DOM-based cross-site scripting",
            "Prototype pollution", "Command injection in Node.js",
            "SQL or NoSQL injection", "Insecure use of eval", "Open redirects",
            "Cross-site request forgery", "Insecure browser storage",
            "Exposed secrets in frontend code", "Server-side request forgery",
            "Path traversal", "Weak authentication logic", "Unsafe regular expressions",
            "Dependency and supply-chain attacks", "Insecure postMessage handling",
        ],
        "high_risk_patterns": [
            "eval()", "new Function()", "innerHTML =", "document.write()",
            "child_process.exec()", 'localStorage.setItem("token", ...)',
            "window.location = userInput",
        ],
        "frameworks": ["React", "Vue", "Angular", "Express", "Next.js", "Electron"],
        "framework_checks": [
            "React dangerouslySetInnerHTML", "Vue v-html",
            "Express routes without authentication", "Missing Helmet middleware",
            "Missing CSRF protection",
            "Next.js secrets exposed through public environment variables",
            "Electron nodeIntegration: true",
        ],
    },
    "TypeScript": {
        "extensions": [".ts", ".tsx", ".mts", ".cts"],
        "common_issues": [
            "All JavaScript security risks", "False confidence from static typing",
            "Unsafe use of any", "Type assertions bypassing validation",
            "Runtime input not validated", "Secrets exposed in compiled frontend bundles",
            "Prototype pollution", "Unsafe dependency usage",
        ],
        "high_risk_patterns": [
            "const input: any = req.body", "const user = input as User",
            "element.innerHTML = input", "exec(input.command)",
        ],
        "frameworks": ["React", "Vue", "Angular", "Express", "Next.js", "Electron"],
        "framework_checks": [
            "Validate API input at runtime",
            "Do not rely only on TypeScript interfaces",
            "Inspect compiled JavaScript behavior",
            "Check frontend and backend separately",
        ],
    },
    "C": {
        "extensions": [".c", ".h"],
        "common_issues": [
            "Buffer overflow", "Stack overflow", "Heap overflow", "Use-after-free",
            "Double free", "Null-pointer dereference", "Integer overflow",
            "Format-string vulnerabilities", "Uninitialized memory",
            "Out-of-bounds reads and writes", "Race conditions", "Memory leaks",
            "Command injection", "Unsafe string handling", "Insecure cryptography",
        ],
        "high_risk_patterns": [
            "gets()", "strcpy()", "strcat()", "sprintf()", 'scanf("%s", ...)',
            "system()", "memcpy()",
        ],
        "frameworks": [],
        "framework_checks": [
            "Missing bounds validation", "Unsafe pointer arithmetic",
            "Improper memory allocation", "Missing return-value checks",
            "Signed and unsigned integer conversions",
        ],
    },
    "C++": {
        "extensions": [".cpp", ".cc", ".cxx", ".hpp", ".hh", ".hxx"],
        "common_issues": [
            "Buffer overflow", "Use-after-free", "Double deletion", "Dangling pointers",
            "Iterator invalidation", "Integer overflow", "Type confusion",
            "Format-string vulnerabilities", "Race conditions", "Unsafe casting",
            "Command injection", "Insecure deserialization", "Memory corruption",
        ],
        "high_risk_patterns": [
            "strcpy()", "sprintf()", "system()", "reinterpret_cast<>()",
            "delete rawPointer", "memcpy()",
        ],
        "frameworks": [],
        "framework_checks": [
            "Raw pointer ownership", "Unsafe manual memory management",
            "Array-bound violations", "Incorrect smart-pointer usage",
            "Concurrent access without locking",
        ],
    },
    "C#": {
        "extensions": [".cs"],
        "common_issues": [
            "SQL injection", "Command injection", "Path traversal",
            "XML external entity attacks", "Unsafe deserialization",
            "Cross-site scripting", "Cross-site request forgery",
            "Improper authentication and authorization",
            "Hardcoded connection strings", "Weak cryptography",
            "Insecure file uploads", "Mass assignment", "Server-side request forgery",
        ],
        "high_risk_patterns": [
            "Process.Start()", "BinaryFormatter.Deserialize()",
            'SqlCommand("SELECT ... " + input)', "Path.Combine(basePath, userInput)",
            "Html.Raw(userInput)",
        ],
        "frameworks": [".NET", "ASP.NET", "ASP.NET Core"],
        "framework_checks": [],
    },
}

EXPECTED_LANGUAGE_COUNT = 8


def detected_languages(suffixes: set[str]) -> list[str]:
    return [
        language
        for language, profile in LANGUAGE_SECURITY_CONTROLS.items()
        if suffixes.intersection(profile["extensions"])
    ]


def language_controls_prompt(languages: list[str] | None = None) -> str:
    selected = languages or list(LANGUAGE_SECURITY_CONTROLS)
    sections = []
    for language in selected:
        profile = LANGUAGE_SECURITY_CONTROLS[language]
        lines = [f"{language}:"]
        for group in ("common_issues", "high_risk_patterns", "frameworks", "framework_checks"):
            lines.append(f"  {group}:")
            lines.extend(f"  - {item}" for item in profile[group])
        sections.append("\n".join(lines))
    return "\n\n".join(sections)


def validate_language_catalog() -> None:
    if len(LANGUAGE_SECURITY_CONTROLS) != EXPECTED_LANGUAGE_COUNT:
        raise RuntimeError("Language security catalog is incomplete.")
    for language, profile in LANGUAGE_SECURITY_CONTROLS.items():
        expected = {"extensions", "common_issues", "high_risk_patterns", "frameworks", "framework_checks"}
        if set(profile) != expected:
            raise RuntimeError(f"{language} security profile has invalid sections.")
        if not profile["extensions"] or not profile["common_issues"]:
            raise RuntimeError(f"{language} security profile is incomplete.")


validate_language_catalog()
