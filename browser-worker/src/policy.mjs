import crypto from "node:crypto";

export const ALLOWED_ACTIONS = new Set([
  "navigate",
  "assert_page_loaded",
  "assert_visible_text",
  "discover_surface",
  "run_axe",
  "inspect_response",
  "review_required",
]);

export const REQUIRED_ISOLATION = Object.freeze({
  ephemeral: true,
  run_as_non_root: true,
  host_filesystem: "none",
  credentials: "job_scoped",
  destructive_actions: false,
});

export function stableJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map(stableJson).join(",")}]`;
  }
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map(
      (key) => `${JSON.stringify(key)}:${stableJson(value[key])}`,
    ).join(",")}}`;
  }
  return JSON.stringify(value);
}

export function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

export function validateJob(body, configuredHosts) {
  if (!body || typeof body !== "object") throw new Error("invalid body");
  if (!/^[a-f0-9]{64}$/.test(body.request_nonce || "")) {
    throw new Error("invalid nonce");
  }
  if (stableJson(body.isolation) !== stableJson(REQUIRED_ISOLATION)) {
    throw new Error("invalid isolation");
  }
  if (sha256(stableJson(body.plan)) !== body.plan_sha256) {
    throw new Error("invalid plan digest");
  }
  const target = new URL(body.target?.url);
  if (target.protocol !== "https:") throw new Error("HTTPS required");
  const requestedHosts = new Set(body.target?.allowed_hosts || []);
  if (!requestedHosts.has(target.hostname)) throw new Error("target not allowed");
  for (const host of requestedHosts) {
    if (!configuredHosts.has(host)) throw new Error("host outside worker scope");
  }
  const planHosts = new Set(body.plan?.allowed_hosts || []);
  if (stableJson([...planHosts].sort()) !== stableJson([...requestedHosts].sort())) {
    throw new Error("plan host scope mismatch");
  }
  const tests = body.plan?.tests;
  if (!Array.isArray(tests) || tests.length < 1 || tests.length > 20) {
    throw new Error("invalid tests");
  }
  const identities = new Set();
  for (const test of tests) {
    if (test.destructive) throw new Error("destructive test forbidden");
    const identity = `${test.test_id}\0${test.requirement_id}`;
    if (identities.has(identity)) throw new Error("duplicate test identity");
    identities.add(identity);
    if (!Array.isArray(test.steps) || test.steps.length > 50) {
      throw new Error("invalid steps");
    }
    for (const step of test.steps) {
      if (!ALLOWED_ACTIONS.has(step.action)) throw new Error("action forbidden");
      if (step.action === "navigate") {
        const destination = new URL(step.target, target);
        if (
          destination.protocol !== "https:"
          || !requestedHosts.has(destination.hostname)
        ) throw new Error("navigation outside scope");
      }
    }
  }
  const browsers = body.plan?.browsers || [];
  if (
    !Array.isArray(browsers)
    || browsers.length < 1
    || browsers.some((name) => !["chromium", "firefox", "webkit"].includes(name))
  ) throw new Error("invalid browsers");
  return { target, requestedHosts, tests, browsers };
}

export function attestationBody(data) {
  const keys = [
    "job_id", "job_status", "request_nonce", "target_url",
    "plan_sha256", "junit_sha256", "evidence_sha256", "isolation",
  ];
  return stableJson(Object.fromEntries(keys.map((key) => [key, data[key]])));
}

export function signAttestation(data, secret) {
  return crypto.createHmac("sha256", secret).update(attestationBody(data)).digest("hex");
}
