export const MAX_CODE_CHARS = 100_000;
export const MAX_CONTEXT_CHARS = 10_000;

export function isExactApproval(feedback: string): boolean {
  return feedback === "APPROVED";
}

export function validateInputSizes(code: string, context?: string): void {
  if (code.length > MAX_CODE_CHARS || (context?.length ?? 0) > MAX_CONTEXT_CHARS) {
    throw new Error("input exceeds the configured size limit");
  }
}

export function parseToolArguments(
  value: unknown,
): { code: string; context?: string } | null {
  if (
    value === null
    || typeof value !== "object"
    || Array.isArray(value)
  ) return null;
  const args = value as Record<string, unknown>;
  if (
    typeof args.code !== "string"
    || (args.context !== undefined && typeof args.context !== "string")
  ) return null;
  return { code: args.code, context: args.context as string | undefined };
}

export function nextTokenAllowance(
  totalBudget: number, usedTokens: number, perRequestMaximum: number,
): number {
  const remaining = totalBudget - usedTokens;
  if (remaining < 1) throw new Error("Operation token budget exhausted");
  return Math.min(remaining, perRequestMaximum);
}
