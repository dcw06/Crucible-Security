import assert from "node:assert/strict";
import test from "node:test";
import {
  REQUIRED_ISOLATION,
  sha256,
  stableJson,
  validateJob,
} from "../src/policy.mjs";

function validJob() {
  const plan = {
    tests: [{
      test_id: "WEB-1",
      requirement_id: "REQ-1",
      title: "loads",
      steps: [{ action: "navigate", target: "https://example.com", value: "" }],
      destructive: false,
    }],
    allowed_hosts: ["example.com"],
    browsers: ["chromium"],
    capture_trace: true,
    capture_screenshots: true,
    capture_video: false,
  };
  return {
    request_nonce: "a".repeat(64),
    target: { url: "https://example.com", allowed_hosts: ["example.com"] },
    plan,
    plan_sha256: sha256(stableJson(plan)),
    isolation: REQUIRED_ISOLATION,
  };
}

test("accepts a bounded non-destructive plan", () => {
  assert.equal(
    validateJob(validJob(), new Set(["example.com"])).target.hostname,
    "example.com",
  );
});

test("rejects destructive tests", () => {
  const job = validJob();
  job.plan.tests[0].destructive = true;
  job.plan_sha256 = sha256(stableJson(job.plan));
  assert.throws(() => validateJob(job, new Set(["example.com"])), /destructive/);
});

test("rejects navigation outside the authorized host list", () => {
  const job = validJob();
  job.plan.tests[0].steps[0].target = "https://internal.example/path";
  job.plan_sha256 = sha256(stableJson(job.plan));
  assert.throws(() => validateJob(job, new Set(["example.com"])), /outside scope/);
});
