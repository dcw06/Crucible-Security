const assert = require("node:assert/strict");
const test = require("node:test");
const {
  boundedInteger,
  isExactApproval,
  nextTokenAllowance,
  validateCodeSize,
} = require("../out/pipeline-utils.js");

test("approval must be exact", () => {
  assert.equal(isExactApproval("APPROVED"), true);
  assert.equal(isExactApproval("APPROVED, mostly"), false);
});

test("oversized selections are rejected", () => {
  assert.throws(() => validateCodeSize("x".repeat(100_001)));
});

test("pipeline limits are bounded and remaining tokens cap requests", () => {
  assert.equal(boundedInteger(5, 3, 10), 5);
  assert.throws(() => boundedInteger(11, 3, 10));
  assert.equal(nextTokenAllowance(10_000, 9_750, 4_096), 250);
  assert.throws(() => nextTokenAllowance(10_000, 10_000, 4_096));
});
