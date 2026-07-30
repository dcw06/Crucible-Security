export const MAX_CODE_CHARS = 100_000;

export function isExactApproval(feedback: string): boolean {
  return feedback === "APPROVED";
}

export function validateCodeSize(code: string): void {
  if (code.length > MAX_CODE_CHARS) {
    throw new Error("selected code exceeds the 100,000-character limit");
  }
}

export function boundedInteger(
  value: unknown, fallback: number, maximum: number,
): number {
  const candidate = value === undefined ? fallback : Number(value);
  if (!Number.isInteger(candidate) || candidate < 1 || candidate > maximum) {
    throw new Error(`value must be an integer between 1 and ${maximum}`);
  }
  return candidate;
}

export function nextTokenAllowance(
  totalBudget: number, usedTokens: number, perRequestMaximum: number,
): number {
  const remaining = totalBudget - usedTokens;
  if (remaining < 1) throw new Error("Operation token budget exhausted");
  return Math.min(remaining, perRequestMaximum);
}
