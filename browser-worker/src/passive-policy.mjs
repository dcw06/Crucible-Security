export function passiveFindings(headers, cookies = [], responseUrl = "") {
  const findings = [];
  const add = (type, severity, evidence) => findings.push({
    type,
    severity,
    confidence: 1,
    evidence,
    response_url: responseUrl,
  });
  const csp = headers["content-security-policy"] || "";
  const xfo = (headers["x-frame-options"] || "").toLowerCase();
  if (!csp) add("MISSING_CSP", "MEDIUM", "content-security-policy is absent");
  else if (csp.includes("'unsafe-eval'")) add("CSP_UNSAFE_EVAL", "HIGH", "CSP permits unsafe-eval");
  else if (csp.includes("'unsafe-inline'")) add("CSP_UNSAFE_INLINE", "MEDIUM", "CSP permits unsafe-inline");
  if (!csp.toLowerCase().includes("frame-ancestors") && !["deny", "sameorigin"].includes(xfo)) {
    add("MISSING_CLICKJACKING_DEFENSE", "MEDIUM", "Neither CSP frame-ancestors nor X-Frame-Options protects this response");
  }
  const expected = [
    ["strict-transport-security", "MEDIUM"],
    ["x-content-type-options", "LOW"],
    ["referrer-policy", "LOW"],
    ["permissions-policy", "LOW"],
  ];
  for (const [header, severity] of expected) {
    if (!headers[header]) add("MISSING_SECURITY_HEADER", severity, `${header} is absent`);
  }
  if (
    headers["access-control-allow-origin"] === "*"
    && headers["access-control-allow-credentials"]?.toLowerCase() === "true"
  ) add("CREDENTIALED_WILDCARD_CORS", "HIGH", "Wildcard CORS is combined with credentials");
  for (const cookie of cookies) {
    const sessionLike = /(session|auth|token|sid)/i.test(cookie.name);
    if (!cookie.secure) add("COOKIE_MISSING_SECURE", sessionLike ? "HIGH" : "MEDIUM", `${cookie.name} is missing Secure`);
    if (sessionLike && !cookie.httpOnly) add("SESSION_COOKIE_MISSING_HTTPONLY", "HIGH", `${cookie.name} is missing HttpOnly`);
    if (!["Lax", "Strict"].includes(cookie.sameSite)) add("COOKIE_WEAK_SAMESITE", "MEDIUM", `${cookie.name} has SameSite=${cookie.sameSite || "unset"}`);
  }
  return findings;
}
