import assert from "node:assert/strict";
import test from "node:test";
import { passiveFindings } from "../src/passive-policy.mjs";

test("evaluates headers and cookie attributes without retaining values", () => {
  const findings = passiveFindings(
    {},
    [{
      name: "session",
      value: "must-not-appear",
      secure: false,
      httpOnly: false,
      sameSite: "None",
    }],
    "https://example.com/login",
  );
  const types = new Set(findings.map((finding) => finding.type));

  assert.ok(types.has("MISSING_CSP"));
  assert.ok(types.has("MISSING_CLICKJACKING_DEFENSE"));
  assert.ok(types.has("COOKIE_MISSING_SECURE"));
  assert.ok(types.has("SESSION_COOKIE_MISSING_HTTPONLY"));
  assert.equal(JSON.stringify(findings).includes("must-not-appear"), false);
});

test("accepts meaningful clickjacking and baseline response policy", () => {
  const findings = passiveFindings({
    "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
    "strict-transport-security": "max-age=31536000",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "camera=()",
  });

  assert.deepEqual(findings, []);
});
