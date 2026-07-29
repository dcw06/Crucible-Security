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

// ── Models & prompts (same as the VSCode extension) ──────────────────────────
const WRITER_MODEL = "claude-opus-4-7";
const CRITIC_MODEL = "claude-opus-4-7";
const MAX_ITERATIONS = 5;

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

  return process.env.ANTHROPIC_API_KEY ?? "";
}

// ── Claude API call ───────────────────────────────────────────────────────────
async function callClaude(
  client: Anthropic,
  model: string,
  system: string,
  userMessage: string
): Promise<string> {
  const response = await client.messages.create({
    model,
    max_tokens: 8096,
    system,
    messages: [{ role: "user", content: userMessage }],
  });
  const block = response.content[0];
  return block.type === "text" ? block.text.trim() : "";
}

// ── Writer / critic pipeline ─────────────────────────────────────────────────
async function runPipeline(
  code: string,
  onProgress: (msg: string) => void
): Promise<{ improved_code: string; iterations: number; approved: boolean }> {
  const apiKey = loadApiKey();
  if (!apiKey) throw new Error("ANTHROPIC_API_KEY not found. Add it to ~/.claude/.env");

  const client = new Anthropic({ apiKey });

  let current = code;
  let feedback: string | null = null;

  for (let i = 1; i <= MAX_ITERATIONS; i++) {
    onProgress(`Iteration ${i}/${MAX_ITERATIONS}: Writer improving code…`);

    const writerPrompt = feedback
      ? `Original code:\n${code}\n\nIssues found:\n${feedback}\n\nPrevious attempt:\n${current}\n\nFix all issues. Return only raw code.`
      : `Improve this code — fix any bugs, edge cases, or correctness issues:\n\n${code}`;

    current = await callClaude(client, WRITER_MODEL, WRITER_SYSTEM, writerPrompt);
    current = current.replace(/^```[\w]*\n?/gm, "").replace(/^```\s*$/gm, "").trim();

    onProgress(`Iteration ${i}/${MAX_ITERATIONS}: Critic reviewing…`);
    feedback = await callClaude(client, CRITIC_MODEL, CRITIC_SYSTEM, current);

    if (feedback.trim().toUpperCase().startsWith("APPROVED")) {
      return { improved_code: current, iterations: i, approved: true };
    }
  }

  return { improved_code: current, iterations: MAX_ITERATIONS, approved: false };
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

  const { code, context } = request.params.arguments as {
    code: string;
    context?: string;
  };

  if (!code?.trim()) {
    return {
      content: [{ type: "text", text: "Error: no code provided." }],
      isError: true,
    };
  }

  const codeToImprove = context
    ? `/* Context: ${context} */\n${code}`
    : code;

  const progressLines: string[] = [];

  try {
    const result = await runPipeline(codeToImprove, (msg) => {
      progressLines.push(msg);
    });

    const summary = [
      `✅ Pipeline complete — ${result.iterations} iteration(s), ${result.approved ? "APPROVED by critic" : "max iterations reached"}.`,
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
