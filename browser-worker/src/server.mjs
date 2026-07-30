import http from "node:http";
import crypto from "node:crypto";
import { readFile, unlink } from "node:fs/promises";
import { chromium, firefox, webkit } from "playwright";
import AxeBuilder from "@axe-core/playwright";
import { passiveFindings } from "./passive-policy.mjs";
import {
  REQUIRED_ISOLATION,
  sha256,
  signAttestation,
  stableJson,
  validateJob,
} from "./policy.mjs";

const port = Number.parseInt(process.env.PORT || "8080", 10);
const token = process.env.BROWSER_SANDBOX_TOKEN || "";
const secret = process.env.BROWSER_SANDBOX_ATTESTATION_SECRET || "";
const configuredHosts = new Set(
  (process.env.WEB_ALLOWED_HOSTS || "").split(",").map((value) => value.trim()).filter(Boolean),
);
const egressProxy = process.env.WEB_EGRESS_PROXY_URL || "";
const requireEgressGateway = process.env.REQUIRE_WEB_EGRESS_GATEWAY === "true";
const engines = { chromium, firefox, webkit };
const MAX_BODY_BYTES = 2 * 1024 * 1024;

if (token.length < 32 || secret.length < 32 || configuredHosts.size === 0) {
  throw new Error("Worker credentials and WEB_ALLOWED_HOSTS are required");
}
if (requireEgressGateway && !egressProxy) {
  throw new Error("An infrastructure egress gateway is required");
}

function xmlEscape(value) {
  return String(value).replaceAll("&", "&amp;").replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;").replaceAll('"', "&quot;");
}

function junit(results) {
  const failures = results.filter((item) => item.status === "FAILED").length;
  const errors = results.filter((item) => item.status === "INFRASTRUCTURE_FAILURE").length;
  const skipped = results.filter((item) => item.status === "SKIPPED").length;
  const cases = results.map((item) => {
    let child = "";
    if (item.status === "FAILED") child = `<failure message="${xmlEscape(item.detail)}"/>`;
    if (item.status === "INFRASTRUCTURE_FAILURE") {
      child = `<error message="${xmlEscape(item.detail)}"/>`;
    }
    if (item.status === "SKIPPED") child = "<skipped/>";
    return `<testcase classname="${xmlEscape(item.requirement_id)}" name="${
      xmlEscape(item.test_id)
    }" time="${item.duration_ms / 1000}">${child}</testcase>`;
  }).join("");
  return `<testsuite name="Crucible Web" tests="${results.length}" failures="${
    failures
  }" errors="${errors}" skipped="${skipped}">${cases}</testsuite>`;
}

async function runBrowser(browserName, job) {
  const browser = await engines[browserName].launch({
    headless: true,
    proxy: egressProxy ? { server: egressProxy } : undefined,
  });
  const context = await browser.newContext({
    acceptDownloads: false,
    ignoreHTTPSErrors: false,
    serviceWorkers: "block",
    recordVideo: job.plan.capture_video ? { dir: "/tmp" } : undefined,
  });
  let requestCount = 0;
  let requestBudgetExceeded = false;
  await context.route("**/*", async (route) => {
    requestCount += 1;
    if (requestCount > 500) {
      requestBudgetExceeded = true;
      await route.abort("blockedbyclient");
      return;
    }
    const requestUrl = new URL(route.request().url());
    if (
      !["https:", "data:", "blob:"].includes(requestUrl.protocol)
      || (requestUrl.protocol === "https:" && !job.requestedHosts.has(requestUrl.hostname))
    ) {
      await route.abort("blockedbyclient");
      return;
    }
    await route.continue();
  });
  const page = await context.newPage();
  page.setDefaultTimeout(10000);
  const tracePath = `/tmp/${crypto.randomUUID()}-${browserName}.zip`;
  if (job.plan.capture_trace) {
    await context.tracing.start({ screenshots: true, snapshots: true, sources: false });
  }
  let activeEvents = null;
  const observedApis = new Set();
  const observedWebSockets = new Set();
  page.on("request", (request) => {
    if (["xhr", "fetch"].includes(request.resourceType())) {
      const requestUrl = new URL(request.url());
      if (job.requestedHosts.has(requestUrl.hostname)) {
        observedApis.add(`${request.method()} ${requestUrl.origin}${requestUrl.pathname}`);
      }
    }
  });
  page.on("websocket", (socket) => {
    const socketUrl = new URL(socket.url());
    if (job.requestedHosts.has(socketUrl.hostname)) {
      observedWebSockets.add(`${socketUrl.origin}${socketUrl.pathname}`);
    }
  });
  page.on("console", (message) => {
    if (message.type() === "error" && activeEvents) {
      activeEvents.consoleErrors.push(message.text().slice(0, 1000));
    }
  });
  page.on("requestfailed", (request) => {
    if (activeEvents) {
      activeEvents.networkFailures.push(
        `${request.resourceType()} ${request.method()} ${request.url()}`.slice(0, 1000),
      );
    }
  });
  page.on("pageerror", (error) => {
    if (activeEvents) activeEvents.pageErrors.push(String(error.message || error).slice(0, 1000));
  });
  page.on("response", (response) => {
    if (!activeEvents || response.status() < 500) return;
    const responseUrl = new URL(response.url());
    if (job.requestedHosts.has(responseUrl.hostname)) {
      activeEvents.serverErrors.push(
        `${response.status()} ${response.request().resourceType()} ${responseUrl.origin}${responseUrl.pathname}`.slice(0, 1000),
      );
    }
  });
  let entryResponse;
  const accessibility = [];
  const results = [];
  for (const test of job.tests) {
    const started = Date.now();
    let status = "PASSED";
    let detail = "";
    const observations = [];
    const artifacts = [];
    activeEvents = {
      consoleErrors: [],
      networkFailures: [],
      pageErrors: [],
      serverErrors: [],
    };
    try {
      for (const step of test.steps) {
        if (step.action === "navigate") {
          entryResponse = await page.goto(step.target || job.target.href, {
            waitUntil: "domcontentloaded",
            timeout: 15000,
          });
          if (!entryResponse?.ok()) throw new Error(`HTTP ${entryResponse?.status() || 0}`);
        } else if (step.action === "assert_page_loaded") {
          await page.locator("body").waitFor({ state: "visible", timeout: 10000 });
        } else if (step.action === "assert_visible_text") {
          await page.getByText(step.value, { exact: false }).first().waitFor({
            state: "visible", timeout: 10000,
          });
        } else if (step.action === "discover_surface") {
          const limits = {
            maxPages: 50,
            maxDepth: 4,
            maxDurationMs: 120000,
            maxLinksPerPage: 50,
          };
          const startedCrawl = Date.now();
          const queue = [{ url: page.url(), depth: 0 }];
          const visited = new Set();
          const pages = [];
          const forms = [];
          const scripts = new Set();
          const manifests = new Set();
          const forbiddenControls = [];
          let truncated = false;
          while (queue.length && pages.length < limits.maxPages) {
            if (Date.now() - startedCrawl >= limits.maxDurationMs) {
              truncated = true;
              break;
            }
            const candidate = queue.shift();
            const normalized = new URL(candidate.url);
            normalized.hash = "";
            const key = `${normalized.origin}${normalized.pathname}?${[
              ...normalized.searchParams.keys(),
            ].sort().join("&")}`;
            if (visited.has(key)) continue;
            visited.add(key);
            const response = await page.goto(normalized.href, {
              waitUntil: "domcontentloaded",
              timeout: 15000,
            });
            const surface = await page.evaluate(() => ({
              title: document.title,
              links: [...document.querySelectorAll("a[href]")]
                .map((element) => element.href),
              forms: [...document.forms].map((form, index) => ({
                id: form.id || `form-${index}`,
                action: form.action,
                method: (form.method || "get").toUpperCase(),
                fields: [...form.elements].map((element) => ({
                  name: element.name || "",
                  type: element.type || element.tagName.toLowerCase(),
                })).slice(0, 50),
              })),
              scripts: [...document.scripts].map((element) => element.src).filter(Boolean),
              manifests: [...document.querySelectorAll('link[rel="manifest"]')]
                .map((element) => element.href),
              dangerous: [...document.querySelectorAll("button,a,input[type=submit]")]
                .filter((element) => /(logout|delete|remove|purchase|pay|upload|resign|abort)/i.test(
                  element.textContent || element.value || element.getAttribute("aria-label") || "",
                ))
                .map((element) => (element.textContent || element.value || "").trim())
                .filter(Boolean)
                .slice(0, 50),
            }));
            pages.push({
              url: `${normalized.origin}${normalized.pathname}`,
              depth: candidate.depth,
              status_code: response?.status() || 0,
              title: surface.title.slice(0, 300),
              content_type: (await response?.headerValue("content-type")) || "",
            });
            forms.push(...surface.forms.map((form) => ({
              ...form,
              page_url: `${normalized.origin}${normalized.pathname}`,
            })));
            surface.scripts.forEach((value) => scripts.add(value));
            surface.manifests.forEach((value) => manifests.add(value));
            forbiddenControls.push(...surface.dangerous.map((label) => ({
              page_url: `${normalized.origin}${normalized.pathname}`,
              label,
              execution: "FORBIDDEN",
            })));
            if (candidate.depth < limits.maxDepth) {
              const links = [...new Set(surface.links)]
                .map((value) => new URL(value))
                .filter((value) => value.protocol === "https:"
                  && job.requestedHosts.has(value.hostname)
                  && !/(logout|signout|delete|remove|purchase|checkout|pay|upload|resign|abort)/i.test(
                    `${value.pathname}?${value.searchParams.toString()}`,
                  ))
                .slice(0, limits.maxLinksPerPage);
              queue.push(...links.map((value) => ({
                url: value.href,
                depth: candidate.depth + 1,
              })));
            }
          }
          if (
            queue.length
            || pages.length >= limits.maxPages
            || requestBudgetExceeded
          ) truncated = true;
          const applicationModel = {
            pages,
            forms,
            api_endpoints: [...observedApis].sort(),
            websockets: [...observedWebSockets].sort(),
            scripts: [...scripts].sort(),
            manifests: [...manifests].sort(),
            source_maps: [],
            forbidden_controls: forbiddenControls,
            crawl_truncated: truncated,
            requests_observed: requestCount,
            request_budget_exceeded: requestBudgetExceeded,
            limits,
          };
          const modelJson = stableJson(applicationModel);
          artifacts.push({
            kind: "application_model",
            name: `${browserName}-application-model.json`,
            sha256: sha256(modelJson),
            media_type: "application/json",
            size_bytes: Buffer.byteLength(modelJson),
            download_url: null,
            data_base64: Buffer.from(modelJson).toString("base64"),
          });
          observations.push(
            `Discovered ${pages.length} rendered pages, ${forms.length} forms, `
            + `${observedApis.size} APIs, and ${scripts.size} scripts.`
            + (truncated ? " Coverage budget was exhausted." : ""),
          );
          if (truncated) {
            throw new Error("Rendered crawl coverage is partial because a budget was exhausted");
          }
        } else if (step.action === "run_axe") {
          const report = await new AxeBuilder({ page }).analyze();
          const serious = report.violations.filter(
            (item) => ["serious", "critical"].includes(item.impact),
          );
          accessibility.push(...report.violations);
          if (serious.length) throw new Error(`${serious.length} serious accessibility violations`);
        } else if (step.action === "inspect_response" && !entryResponse) {
          throw new Error("No entry response available");
        } else if (step.action === "review_required") {
          status = "SKIPPED";
          detail = step.value || "Requirement could not be mapped to a discovered control.";
          break;
        }
      }
      const policyFailures = status === "SKIPPED" ? [] : [
        ...activeEvents.pageErrors.map((item) => `Unhandled page error: ${item}`),
        ...activeEvents.serverErrors.map((item) => `First-party HTTP 5xx: ${item}`),
      ];
      if (policyFailures.length) throw new Error(policyFailures.join("; "));
      if (status !== "SKIPPED") detail = observations.join(" ");
    } catch (error) {
      status = "FAILED";
      detail = String(error.message || error).slice(0, 2000);
      if (job.plan.capture_screenshots) {
        const image = await page.screenshot({ fullPage: true }).catch(() => null);
        if (image) {
          artifacts.push({
            kind: "screenshot",
            name: `${browserName}-${test.test_id}.png`,
            sha256: sha256(image),
            media_type: "image/png",
            size_bytes: image.length,
            download_url: null,
            data_base64: image.toString("base64"),
          });
        }
      }
    }
    results.push({
      test_id: test.test_id,
      requirement_id: test.requirement_id,
      status,
      severity: status === "FAILED" ? "MEDIUM" : "INFO",
      confidence: 1,
      detail: `[${browserName}] ${detail}`.trim(),
      duration_ms: Date.now() - started,
      artifacts,
      console_errors: [...activeEvents.consoleErrors],
      network_failures: [
        ...activeEvents.networkFailures,
        ...activeEvents.serverErrors,
        ...activeEvents.pageErrors.map((item) => `pageerror ${item}`),
      ],
    });
    activeEvents = null;
  }
  const headers = entryResponse ? await entryResponse.allHeaders() : {};
  const cookies = await context.cookies();
  if (job.plan.capture_trace) {
    await context.tracing.stop({ path: tracePath });
    const trace = await readFile(tracePath);
    await unlink(tracePath).catch(() => {});
    if (trace.length <= 5 * 1024 * 1024 && results.length) {
      results[0].artifacts.push({
        kind: "playwright_trace",
        name: `${browserName}-trace.zip`,
        sha256: sha256(trace),
        media_type: "application/zip",
        size_bytes: trace.length,
        download_url: null,
        data_base64: trace.toString("base64"),
      });
    }
  }
  await context.close();
  await browser.close();
  return {
    results,
    accessibility,
    passive: passiveFindings(headers, cookies, entryResponse?.url() || job.target.href),
  };
}

async function execute(body) {
  const validated = validateJob(body, configuredHosts);
  const job = { ...validated, plan: body.plan };
  const perBrowser = [];
  for (const browserName of validated.browsers) {
    perBrowser.push(await runBrowser(browserName, job));
  }
  const results = body.plan.tests.map((test) => {
    const outcomes = perBrowser.map((run) => run.results.find(
      (item) => item.test_id === test.test_id && item.requirement_id === test.requirement_id,
    ));
    const failed = outcomes.find((item) => item.status !== "PASSED");
    return {
      ...outcomes[0],
      status: failed ? failed.status : "PASSED",
      detail: outcomes.map((item) => item.detail).filter(Boolean).join(" | "),
      duration_ms: outcomes.reduce((total, item) => total + item.duration_ms, 0),
      artifacts: outcomes.flatMap((item) => item.artifacts),
      console_errors: [...new Set(outcomes.flatMap((item) => item.console_errors))],
      network_failures: [...new Set(outcomes.flatMap((item) => item.network_failures))],
    };
  });
  const junitXml = junit(results);
  const passiveByKey = new Map();
  for (const finding of perBrowser.flatMap((run) => run.passive)) {
    passiveByKey.set(stableJson(finding), finding);
  }
  const response = {
    job_id: crypto.randomUUID(),
    job_status: "COMPLETED",
    request_nonce: body.request_nonce,
    target_url: body.target.url,
    plan_sha256: body.plan_sha256,
    junit_xml: junitXml,
    junit_sha256: sha256(junitXml),
    results,
    evidence_sha256: sha256(stableJson(results)),
    isolation: REQUIRED_ISOLATION,
    accessibility_findings: perBrowser.flatMap((run) => run.accessibility),
    passive_findings: [...passiveByKey.values()],
  };
  response.attestation = signAttestation(response, secret);
  return response;
}

const server = http.createServer((request, response) => {
  if (request.method === "GET" && request.url === "/health") {
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({ status: "ok" }));
    return;
  }
  if (
    request.method !== "POST"
    || request.url !== "/v1/playwright"
    || request.headers.authorization !== `Bearer ${token}`
  ) {
    response.writeHead(404);
    response.end();
    return;
  }
  let size = 0;
  const chunks = [];
  request.on("data", (chunk) => {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) request.destroy();
    else chunks.push(chunk);
  });
  request.on("end", async () => {
    try {
      const result = await execute(JSON.parse(Buffer.concat(chunks).toString("utf8")));
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify(result));
    } catch {
      response.writeHead(400, { "content-type": "application/json" });
      response.end(JSON.stringify({ error: "job rejected" }));
    }
  });
});

server.listen(port, "0.0.0.0");
