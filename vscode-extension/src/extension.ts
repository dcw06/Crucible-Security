import * as vscode from "vscode";
import Anthropic from "@anthropic-ai/sdk";
import * as path from "path";
import * as fs from "fs";

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

function loadApiKey(workspaceRoot: string | undefined): string {
  // Check workspace .env first, then home directory .env
  const locations = [
    workspaceRoot ? path.join(workspaceRoot, ".env") : null,
    path.join(require("os").homedir(), ".claude", ".env"),
  ].filter(Boolean) as string[];

  for (const loc of locations) {
    if (fs.existsSync(loc)) {
      const content = fs.readFileSync(loc, "utf8");
      const match = content.match(/^ANTHROPIC_API_KEY=(.+)$/m);
      if (match) return match[1].trim();
    }
  }

  return process.env.ANTHROPIC_API_KEY ?? "";
}

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

async function runPipeline(
  code: string,
  apiKey: string,
  progress: vscode.Progress<{ message?: string }>
): Promise<string> {
  const client = new Anthropic({ apiKey });

  let current = code;
  let feedback: string | null = null;

  for (let i = 1; i <= MAX_ITERATIONS; i++) {
    progress.report({ message: `Iteration ${i}/${MAX_ITERATIONS}: Writer improving code...` });

    const writerPrompt = feedback
      ? `Original code:\n${code}\n\nIssues found:\n${feedback}\n\nPrevious attempt:\n${current}\n\nFix all issues. Return only raw code.`
      : `Improve this code — fix any bugs, edge cases, or correctness issues:\n\n${code}`;

    current = await callClaude(client, WRITER_MODEL, WRITER_SYSTEM, writerPrompt);

    // Strip accidental markdown fences
    current = current.replace(/^```[\w]*\n?/gm, "").replace(/^```\s*$/gm, "").trim();

    progress.report({ message: `Iteration ${i}/${MAX_ITERATIONS}: Critic reviewing...` });
    feedback = await callClaude(client, CRITIC_MODEL, CRITIC_SYSTEM, current);

    if (feedback.trim().toUpperCase().startsWith("APPROVED")) {
      return current;
    }
  }

  return current;
}

export function activate(context: vscode.ExtensionContext) {
  const command = vscode.commands.registerCommand("code-pipeline.improve", async () => {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
      vscode.window.showErrorMessage("No active editor.");
      return;
    }

    const selection = editor.selection;
    const selectedText = editor.document.getText(selection);
    if (!selectedText.trim()) {
      vscode.window.showWarningMessage("Select some code first, then run Code Pipeline.");
      return;
    }

    const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
    const apiKey = loadApiKey(workspaceRoot);

    if (!apiKey) {
      vscode.window.showErrorMessage(
        "ANTHROPIC_API_KEY not found. Add it to your workspace .env file."
      );
      return;
    }

    const result = await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: "Code Pipeline",
        cancellable: false,
      },
      async (progress) => {
        progress.report({ message: "Starting writer/critic loop..." });
        try {
          return await runPipeline(selectedText, apiKey, progress);
        } catch (err: unknown) {
          const msg = err instanceof Error ? err.message : String(err);
          vscode.window.showErrorMessage(`Code Pipeline failed: ${msg}`);
          return null;
        }
      }
    );

    if (!result) return;

    const action = await vscode.window.showInformationMessage(
      "Code Pipeline complete. What would you like to do with the result?",
      "Replace Selection",
      "Open in New Tab"
    );

    if (action === "Replace Selection") {
      await editor.edit((eb) => eb.replace(selection, result));
    } else if (action === "Open in New Tab") {
      const lang = editor.document.languageId;
      const doc = await vscode.workspace.openTextDocument({ content: result, language: lang });
      await vscode.window.showTextDocument(doc, vscode.ViewColumn.Beside);
    }
  });

  context.subscriptions.push(command);
}

export function deactivate() {}
