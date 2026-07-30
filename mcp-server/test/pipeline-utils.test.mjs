import assert from "node:assert/strict";
import test from "node:test";
import {
  isExactApproval,
  nextTokenAllowance,
  parseToolArguments,
  validateInputSizes,
} from "../dist/pipeline-utils.js";

test("approval must be exact", () => {
  assert.equal(isExactApproval("APPROVED"), true);
  assert.equal(isExactApproval("APPROVED with caveats"), false);
});

test("oversized code is rejected", () => {
  assert.throws(() => validateInputSizes("x".repeat(100_001)));
});

test("tool arguments are runtime validated", () => {
  assert.deepEqual(parseToolArguments({ code: "x", context: "why" }), {
    code: "x", context: "why",
  });
  assert.equal(parseToolArguments({ code: 42 }), null);
  assert.equal(parseToolArguments({ code: "x", context: [] }), null);
  assert.equal(parseToolArguments(null), null);
});

test("next request is capped by the remaining token budget", () => {
  assert.equal(nextTokenAllowance(10_000, 9_500, 4_096), 500);
  assert.equal(nextTokenAllowance(10_000, 1_000, 4_096), 4_096);
  assert.throws(() => nextTokenAllowance(10_000, 10_000, 4_096));
});
