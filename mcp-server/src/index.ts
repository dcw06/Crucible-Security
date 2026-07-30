#!/usr/bin/env node
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import Anthropic from "@anthropic-ai/sdk";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import {
  isExactApproval,
  nextTokenAllowance,
  parseToolArguments,
  validateInputSizes,
} from "./pipeline-utils.js";

// ── Models & prompts (same as the VSCode extension) ──────────────────────────
const WRITER_MODEL = process.env.CODE_PIPELINE_WRITER_MODEL ?? "claude-opus-4-7";
const CRITIC_MODEL = process.env.CODE_PIPELINE_CRITIC_MODEL ?? "claude-opus-4-7";

function boundedInteger(name: string, fallback: number, maximum: number): number {
  const value = Number(process.env[name] ?? fallback);
  if (!Number.isInteger(value) || value < 1 || value > maximum) {
    throw new Error(`${name} must be an integer between 1 and ${maximum}`);
  }
  return value;
}

const MAX_ITERATIONS = boundedInteger("CODE_PIPELINE_MAX_ITERATIONS", 5, 10);
const MAX_OUTPUT_TOKENS = boundedInteger("CODE_PIPELINE_MAX_OUTPUT_TOKENS", 4096, 8096);
const TOTAL_TOKEN_BUDGET = boundedInteger("CODE_PIPELINE_TOTAL_TOKEN_BUDGET", 32_000, 100_000);
const OPERATION_TIMEOUT_MS = boundedInteger("CODE_PIPELINE_TIMEOUT_MS", 120_000, 600_000);

const WRITER_SYSTEM = `You are an expert software developer. When given code to improve,
fix all bugs, edge cases, security issues, and correctness problems.
Return ONLY raw code — no explanation, no markdown, no triple-backtick fences.`;

const CRITIC_SYSTEM = `You are an adversarial senior code reviewer. Find every bug,
edge case, security issue, and logical error in the code given to you.

Respond in one of two ways ONLY:

1. If the code is correct and production-ready:
   APPROVED

2. If there are any issues:
   ISSUES:
   - <specific issue 1>
   - <specific issue 2>

Do not explain what the code does. Only report concrete bugs or correctness problems.`;

// ── API key loading (same logic as the extension) ────────────────────────────
function loadApiKey(): string {
  if (process.env.ANTHROPIC_API_KEY?.trim()) {
    return process.env.ANTHROPIC_API_KEY.trim();
  }
  if (process.env.CODE_PIPELINE_ALLOW_KEY_FILE !== "true") return "";

  const locations = [
    path.join(os.homedir(), ".claude", ".env"),
    path.join(os.homedir(), ".env"),
  ];

  for (const loc of locations) {
    if (fs.existsSync(loc)) {
      const content = fs.readFileSync(loc, "utf8");
      const match = content.match(/^ANTHROPIC_API_KEY=(.+)$/m);
      if (match) return match[1].trim();
    }
  }

  return "";
}

// ── Claude API call ───────────────────────────────────────────────────────────
async function callClaude(
  client: Anthropic,
  model: string,
  system: string,
  userMessage: string,
  signal: AbortSignal,
  maxTokens: number,
): Promise<{ text: string; inputTokens: number; outputTokens: number }> {
  const response = await client.messages.create({
    model,
    max_tokens: maxTokens,
    system,
    messages: [{ role: "user", content: userMessage }],
  }, { signal });
  const text = response.content.find((block) => block.type === "text")?.text.trim() ?? "";
  if (!text) throw new Error("Model returned an empty response");
  return {
    text,
    inputTokens: response.usage.input_tokens,
    outputTokens: response.usage.output_tokens,
  };
}

// ── Writer / critic pipeline ─────────────────────────────────────────────────
async function runPipeline(
  code: string,
  context?: string,
): Promise<{
  improved_code: string;
  iterations: number;
  approved: boolean;
  usage: { input_tokens: number; output_tokens: number };
}> {
  const apiKey = loadApiKey();
  if (!apiKey) throw new Error("ANTHROPIC_API_KEY not found. Add it to ~/.claude/.env");

  const client = new Anthropic({ apiKey });
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), OPERATION_TIMEOUT_MS);

  let current = code;
  let feedback: string | null = null;
  let inputTokens = 0;
  let outputTokens = 0;

  try {
    for (let i = 1; i <= MAX_ITERATIONS; i++) {
      const contextBlock = context ? `Context:\n${context}\n\n` : "";
      const writerPrompt = feedback
        ? `${contextBlock}Original code:\n${code}\n\nIssues found:\n${feedback}\n\nPrevious attempt:\n${current}\n\nFix all issues. Return only raw code.`
        : `${contextBlock}Improve this code — fix any bugs, edge cases, or correctness issues:\n\n${code}`;

      const writer = await callClaude(
        client, WRITER_MODEL, WRITER_SYSTEM, writerPrompt, controller.signal,
        nextTokenAllowance(
          TOTAL_TOKEN_BUDGET, inputTokens + outputTokens, MAX_OUTPUT_TOKENS,
        ),
      );
      inputTokens += writer.inputTokens;
      outputTokens += writer.outputTokens;
      if (inputTokens + outputTokens > TOTAL_TOKEN_BUDGET) {
        throw new Error("Operation token budget exceeded");
      }
      current = writer.text;
      current = current.replace(/^```[\w]*\n?/gm, "").replace(/^```\s*$/gm, "").trim();

      const critic = await callClaude(
        client, CRITIC_MODEL, CRITIC_SYSTEM, current, controller.signal,
        nextTokenAllowance(
          TOTAL_TOKEN_BUDGET, inputTokens + outputTokens, MAX_OUTPUT_TOKENS,
        ),
      );
      inputTokens += critic.inputTokens;
      outputTokens += critic.outputTokens;
      if (inputTokens + outputTokens > TOTAL_TOKEN_BUDGET) {
        throw new Error("Operation token budget exceeded");
      }
      feedback = critic.text;

      if (isExactApproval(feedback)) {
        return {
          improved_code: current,
          iterations: i,
          approved: true,
          usage: { input_tokens: inputTokens, output_tokens: outputTokens },
        };
      }
      if (!feedback.startsWith("ISSUES:")) {
        throw new Error("Critic returned a malformed response");
      }
    }
    return {
      improved_code: current,
      iterations: MAX_ITERATIONS,
      approved: false,
      usage: { input_tokens: inputTokens, output_tokens: outputTokens },
    };
  } finally {
    clearTimeout(timeout);
  }
}

// ── MCP server setup ──────────────────────────────────────────────────────────
const server = new Server(
  { name: "code-pipeline", version: "0.1.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "improve_code",
      description:
        "Run a writer/critic multi-agent loop to fix bugs, edge cases, and correctness issues in code. Returns the improved version and a summary of what changed.",
      inputSchema: {
        type: "object",
        properties: {
          code: {
            type: "string",
            description: "The source code to improve",
          },
          context: {
            type: "string",
            description:
              "Optional: brief description of what the code does or any specific concerns to focus on",
          },
        },
        required: ["code"],
      },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  if (request.params.name !== "improve_code") {
    throw new Error(`Unknown tool: ${request.params.name}`);
  }

  const args = parseToolArguments(request.params.arguments);
  if (args === null) {
    return {
      content: [{ type: "text", text: "Error: invalid arguments." }],
      isError: true,
    };
  }
  const { code, context } = args;
  if (!code.trim()) {
    return {
      content: [{ type: "text", text: "Error: no code provided." }],
      isError: true,
    };
  }
  try {
    validateInputSizes(code, context);
  } catch {
    return {
      content: [{ type: "text", text: "Error: input exceeds the configured size limit." }],
      isError: true,
    };
  }

  try {
    const result = await runPipeline(code, context);

    const summary = [
      result.approved
        ? `✅ Pipeline complete — ${result.iterations} iteration(s), APPROVED by critic.`
        : `⚠️ UNAPPROVED OUTPUT — critic did not approve after ${result.iterations} iterations. Review before use.`,
      "",
      `Usage: ${result.usage.input_tokens} input tokens, ${result.usage.output_tokens} output tokens.`,
      "",
      "**Improved code:**",
      "```",
      result.improved_code,
      "```",
    ].join("\n");

    return { content: [{ type: "text", text: summary }] };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return {
      content: [{ type: "text", text: `Error running pipeline: ${msg}` }],
      isError: true,
    };
  }
});

// ── Start ─────────────────────────────────────────────────────────────────────
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  // MCP servers communicate over stdio — no console.log here
}

main().catch((err) => {
  process.stderr.write(`Fatal: ${err}\n`);
  process.exit(1);
});
