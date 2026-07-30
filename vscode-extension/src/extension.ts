import * as vscode from "vscode";
import Anthropic from "@anthropic-ai/sdk";
import {
  boundedInteger,
  isExactApproval,
  nextTokenAllowance,
  validateCodeSize,
} from "./pipeline-utils";

type PipelineConfig = {
  writerModel: string;
  criticModel: string;
  maxIterations: number;
  maxOutputTokens: number;
  totalTokenBudget: number;
  timeoutMs: number;
};

function loadPipelineConfig(): PipelineConfig {
  const config = vscode.workspace.getConfiguration("codePipeline");
  return {
    writerModel: config.get<string>("writerModel", "claude-opus-4-7").trim(),
    criticModel: config.get<string>("criticModel", "claude-opus-4-7").trim(),
    maxIterations: boundedInteger(config.get("maxIterations"), 5, 10),
    maxOutputTokens: boundedInteger(config.get("maxOutputTokens"), 4096, 8096),
    totalTokenBudget: boundedInteger(
      config.get("totalTokenBudget"), 32_000, 100_000,
    ),
    timeoutMs: boundedInteger(config.get("timeoutMs"), 120_000, 600_000),
  };
}

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

async function loadApiKey(context: vscode.ExtensionContext): Promise<string> {
  const stored = (await context.secrets.get("anthropicApiKey"))?.trim();
  if (stored) return stored;
  return process.env.ANTHROPIC_API_KEY?.trim() ?? "";
}

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

async function runPipeline(
  code: string,
  apiKey: string,
  progress: vscode.Progress<{ message?: string }>,
  token: vscode.CancellationToken,
  config: PipelineConfig,
): Promise<{
  code: string;
  approved: boolean;
  usage: { inputTokens: number; outputTokens: number };
}> {
  const client = new Anthropic({ apiKey });
  const controller = new AbortController();
  const cancellation = token.onCancellationRequested(() => controller.abort());
  const timeout = setTimeout(() => controller.abort(), config.timeoutMs);

  let current = code;
  let feedback: string | null = null;
  let inputTokens = 0;
  let outputTokens = 0;

  try {
    for (let i = 1; i <= config.maxIterations; i++) {
      if (token.isCancellationRequested) throw new vscode.CancellationError();
      progress.report({
        message: `Iteration ${i}/${config.maxIterations}: Writer improving code...`,
      });

    const writerPrompt = feedback
      ? `Original code:\n${code}\n\nIssues found:\n${feedback}\n\nPrevious attempt:\n${current}\n\nFix all issues. Return only raw code.`
      : `Improve this code — fix any bugs, edge cases, or correctness issues:\n\n${code}`;

      const writer = await callClaude(
        client, config.writerModel, WRITER_SYSTEM, writerPrompt, controller.signal,
        nextTokenAllowance(
          config.totalTokenBudget, inputTokens + outputTokens,
          config.maxOutputTokens,
        ),
      );
      inputTokens += writer.inputTokens;
      outputTokens += writer.outputTokens;
      if (inputTokens + outputTokens > config.totalTokenBudget) {
        throw new Error("Operation token budget exceeded");
      }
      current = writer.text;

    // Strip accidental markdown fences
    current = current.replace(/^```[\w]*\n?/gm, "").replace(/^```\s*$/gm, "").trim();

      progress.report({
        message: `Iteration ${i}/${config.maxIterations}: Critic reviewing...`,
      });
      const critic = await callClaude(
        client, config.criticModel, CRITIC_SYSTEM, current, controller.signal,
        nextTokenAllowance(
          config.totalTokenBudget, inputTokens + outputTokens,
          config.maxOutputTokens,
        ),
      );
      inputTokens += critic.inputTokens;
      outputTokens += critic.outputTokens;
      if (inputTokens + outputTokens > config.totalTokenBudget) {
        throw new Error("Operation token budget exceeded");
      }
      feedback = critic.text;

      if (isExactApproval(feedback)) {
        return {
          code: current, approved: true, usage: { inputTokens, outputTokens },
        };
      }
      if (!feedback.startsWith("ISSUES:")) throw new Error("Critic returned a malformed response");
    }
    return {
      code: current, approved: false, usage: { inputTokens, outputTokens },
    };
  } catch (error) {
    if (token.isCancellationRequested) throw new vscode.CancellationError();
    throw error;
  } finally {
    clearTimeout(timeout);
    cancellation.dispose();
  }
}

export function activate(context: vscode.ExtensionContext) {
  const setApiKeyCommand = vscode.commands.registerCommand(
    "code-pipeline.setApiKey",
    async () => {
      const apiKey = await vscode.window.showInputBox({
        prompt: "Enter your Anthropic API key",
        password: true,
        ignoreFocusOut: true,
        validateInput: (value) => value.trim() ? null : "An API key is required.",
      });
      if (apiKey === undefined) return;
      await context.secrets.store("anthropicApiKey", apiKey.trim());
      vscode.window.showInformationMessage("Code Pipeline API key stored securely.");
    },
  );
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
    try {
      validateCodeSize(selectedText);
    } catch {
      vscode.window.showErrorMessage("Selected code exceeds the 100,000-character limit.");
      return;
    }
    const originalDocumentVersion = editor.document.version;

    const apiKey = await loadApiKey(context);

    if (!apiKey) {
      vscode.window.showErrorMessage(
        "ANTHROPIC_API_KEY not found. Run “Code Pipeline: Set Anthropic API Key” or configure the process environment."
      );
      return;
    }
    let pipelineConfig: PipelineConfig;
    try {
      pipelineConfig = loadPipelineConfig();
      if (!pipelineConfig.writerModel || !pipelineConfig.criticModel) {
        throw new Error("Writer and critic models must be configured.");
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      vscode.window.showErrorMessage(`Invalid Code Pipeline settings: ${message}`);
      return;
    }

    const result = await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: "Code Pipeline",
        cancellable: true,
      },
      async (progress, token) => {
        progress.report({ message: "Starting writer/critic loop..." });
        try {
          return await runPipeline(
            selectedText, apiKey, progress, token, pipelineConfig,
          );
        } catch (err: unknown) {
          if (err instanceof vscode.CancellationError) {
            vscode.window.showInformationMessage("Code Pipeline cancelled.");
            return null;
          }
          const msg = err instanceof Error ? err.message : String(err);
          vscode.window.showErrorMessage(`Code Pipeline failed: ${msg}`);
          return null;
        }
      }
    );

    if (!result) return;

    const action = await vscode.window.showWarningMessage(
      result.approved
        ? `Code Pipeline approved. Usage: ${result.usage.inputTokens} input and ${result.usage.outputTokens} output tokens.`
        : `UNAPPROVED output. Usage: ${result.usage.inputTokens} input and ${result.usage.outputTokens} output tokens.`,
      "Replace Selection",
      "Open in New Tab"
    );

    if (action === "Replace Selection") {
      if (editor.document.version !== originalDocumentVersion) {
        vscode.window.showErrorMessage(
          "The document changed while Code Pipeline was running; replacement was cancelled."
        );
        return;
      }
      await editor.edit((eb) => eb.replace(selection, result.code));
    } else if (action === "Open in New Tab") {
      const lang = editor.document.languageId;
      const doc = await vscode.workspace.openTextDocument({ content: result.code, language: lang });
      await vscode.window.showTextDocument(doc, vscode.ViewColumn.Beside);
    }
  });

  context.subscriptions.push(setApiKeyCommand, command);
}

export function deactivate() {}
