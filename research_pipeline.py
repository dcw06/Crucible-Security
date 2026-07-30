"""
Multi-Agent Research Pipeline
------------------------------
Architecture:
  User → Orchestrator → [Researcher A, Researcher B, ...] (parallel)
                      ↓
                  Synthesizer → Final Report

Agents:
  1. Orchestrator  – breaks the question into subtopics (structured JSON output)
  2. Researcher    – investigates one subtopic using a web_search tool
  3. Synthesizer   – combines all research into a coherent report
"""

import anthropic
import json
import asyncio
import os
from datetime import datetime, timezone
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from dotenv import load_dotenv

load_dotenv(override=False)

client = anthropic.Anthropic()
MAX_TOOL_TURNS = 8

# ---------------------------------------------------------------------------
# Live search execution
# ---------------------------------------------------------------------------

def web_search(query: str) -> str:
    """Search Brave and return bounded, structured results with provenance."""
    if not isinstance(query, str) or not query.strip():
        raise ValueError("Search query must be a nonempty string")
    api_key = os.environ.get("BRAVE_SEARCH_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError(
            "BRAVE_SEARCH_API_KEY is required; simulated search is not supported"
        )

    endpoint = os.environ.get(
        "BRAVE_SEARCH_URL", "https://api.search.brave.com/res/v1/web/search",
    ).strip()
    if not endpoint.startswith("https://"):
        raise RuntimeError("BRAVE_SEARCH_URL must use HTTPS")
    url = f"{endpoint}?{urlencode({'q': query.strip(), 'count': 10})}"
    request = Request(
        url,
        headers={
            "Accept": "application/json",
            "X-Subscription-Token": api_key,
            "User-Agent": "multi-agent-research-pipeline/1.0",
        },
    )
    try:
        with urlopen(request, timeout=20) as response:
            raw = response.read(2 * 1024 * 1024 + 1)
    except HTTPError as exc:
        raise RuntimeError(f"Search provider returned HTTP {exc.code}") from exc
    except (URLError, TimeoutError) as exc:
        raise RuntimeError("Search provider request failed") from exc
    if len(raw) > 2 * 1024 * 1024:
        raise RuntimeError("Search provider response exceeded 2 MiB")
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("Search provider returned invalid JSON") from exc

    candidates = payload.get("web", {}).get("results", [])
    if not isinstance(candidates, list):
        raise RuntimeError("Search provider returned an invalid result schema")
    seen_urls: set[str] = set()
    results: list[dict[str, str]] = []
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        source_url = candidate.get("url")
        title = candidate.get("title")
        description = candidate.get("description")
        if (
            not isinstance(source_url, str)
            or not source_url.startswith(("https://", "http://"))
            or source_url in seen_urls
            or not isinstance(title, str)
            or not title.strip()
        ):
            continue
        seen_urls.add(source_url)
        result = {
            "title": title.strip()[:500],
            "url": source_url[:2048],
            "description": (
                description.strip()[:2000]
                if isinstance(description, str) else ""
            ),
        }
        published = candidate.get("age") or candidate.get("page_age")
        if isinstance(published, str) and published.strip():
            result["published"] = published.strip()[:100]
        results.append(result)
        if len(results) == 10:
            break
    if not results:
        raise RuntimeError("Search provider returned no usable results")
    return json.dumps(
        {
            "query": query.strip(),
            "retrieved_at": datetime.now(timezone.utc).isoformat(),
            "provider": "Brave Search",
            "results": results,
        },
        ensure_ascii=False,
    )

TOOLS = [
    {
        "name": "web_search",
        "description": "Search the web for up-to-date information on a topic.",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "The search query"}
            },
            "required": ["query"],
        },
    }
]

def execute_tool(name: str, inputs: dict[str, Any]) -> str:
    if name == "web_search":
        return web_search(inputs["query"])
    raise ValueError(f"Unknown tool: {name}")


# ---------------------------------------------------------------------------
# Core agent runner with agentic loop
# ---------------------------------------------------------------------------

def run_agent(system: str, user_message: str, use_tools: bool = False) -> str:
    """Run a single agent turn, looping until stop_reason == 'end_turn'."""
    messages: list[Any] = [{"role": "user", "content": user_message}]
    kwargs: dict[str, Any] = {
        "model": "claude-opus-4-7",
        "max_tokens": 4096,
        "system": system,
        "messages": messages,
    }
    if use_tools:
        kwargs["tools"] = TOOLS

    for _turn in range(MAX_TOOL_TURNS):
        response = client.messages.create(**kwargs)

        if response.stop_reason == "end_turn":
            text = next(
                (
                    block.text.strip()
                    for block in response.content
                    if isinstance(getattr(block, "text", None), str)
                    and block.text.strip()
                ),
                None,
            )
            if text is None:
                raise RuntimeError("Research agent returned no text content")
            return text

        if response.stop_reason == "tool_use":
            tool_results = []
            for block in response.content:
                if block.type == "tool_use":
                    print(f"      [tool] {block.name}({block.input})")
                    result = execute_tool(block.name, block.input)
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": result,
                    })

            messages.append({"role": "assistant", "content": response.content})
            messages.append({"role": "user", "content": tool_results})
            kwargs["messages"] = messages
            continue
        raise RuntimeError(f"Unexpected model stop reason: {response.stop_reason}")
    raise RuntimeError("Research agent exceeded its tool-loop limit")


# ---------------------------------------------------------------------------
# Agent 1: Orchestrator
# ---------------------------------------------------------------------------

ORCHESTRATOR_SYSTEM = """
You are a research orchestrator. Given a research question, break it into 2-4
focused subtopics that together cover the question comprehensively.

Respond ONLY with valid JSON in this exact format — no markdown, no explanation:
{
  "subtopics": [
    {"id": "1", "title": "short title", "query": "specific research question for this subtopic"},
    {"id": "2", "title": "short title", "query": "specific research question for this subtopic"}
  ]
}
"""

def orchestrate(research_question: str) -> list[dict]:
    print("\n[Orchestrator] Breaking question into subtopics...")
    raw = run_agent(ORCHESTRATOR_SYSTEM, research_question, use_tools=False)
    try:
        plan = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("Orchestrator returned invalid JSON") from exc
    if not isinstance(plan, dict) or set(plan) != {"subtopics"}:
        raise ValueError("Orchestrator returned an invalid plan schema")
    subtopics = plan["subtopics"]
    if not isinstance(subtopics, list) or not 2 <= len(subtopics) <= 4:
        raise ValueError("Orchestrator must return between 2 and 4 subtopics")
    for item in subtopics:
        if (
            not isinstance(item, dict)
            or set(item) != {"id", "title", "query"}
            or not all(isinstance(item[key], str) and item[key].strip()
                       for key in ("id", "title", "query"))
        ):
            raise ValueError("Orchestrator returned a malformed subtopic")
    for s in subtopics:
        print(f"  → [{s['id']}] {s['title']}: {s['query']}")
    return subtopics


# ---------------------------------------------------------------------------
# Agent 2: Researcher (one instance per subtopic, run in parallel)
# ---------------------------------------------------------------------------

RESEARCHER_SYSTEM = """
You are a focused research agent. You receive a specific research question and
must use the web_search tool to gather information. After searching, write a
concise but thorough summary (3-5 paragraphs) of what you found. Include key
facts, statistics, and insights. Cite factual claims using the source URLs from
the tool results. Do not invent sources, URLs, publication dates, or facts that
are absent from those results. Do not editorialize — stick to the evidence.
"""

def research_subtopic(subtopic: dict) -> dict:
    print(f"\n[Researcher {subtopic['id']}] Investigating: {subtopic['title']}")
    findings = run_agent(RESEARCHER_SYSTEM, subtopic["query"], use_tools=True)
    return {"subtopic": subtopic, "status": "success", "findings": findings}


async def research_all_parallel(subtopics: list[dict]) -> list[dict]:
    """Run all researcher agents concurrently using asyncio + a thread pool."""
    loop = asyncio.get_running_loop()
    tasks = [
        loop.run_in_executor(None, research_subtopic, subtopic)
        for subtopic in subtopics
    ]
    raw_results = await asyncio.gather(*tasks, return_exceptions=True)
    results: list[dict] = []
    for subtopic, result in zip(subtopics, raw_results):
        if isinstance(result, BaseException):
            results.append({
                "subtopic": subtopic,
                "status": "failed",
                "error_code": "RESEARCHER_FAILED",
            })
        else:
            results.append(result)
    return results


# ---------------------------------------------------------------------------
# Agent 3: Synthesizer
# ---------------------------------------------------------------------------

SYNTHESIZER_SYSTEM = """
You are a synthesis agent. You receive research findings from multiple specialist
agents and must combine them into a single, well-structured research report.

Structure your report as:
1. Executive Summary (2-3 sentences)
2. Key Findings (one section per subtopic with a clear heading)
3. Synthesis & Implications (cross-cutting themes, tensions, or conclusions)

Write in clear, professional prose. Do not use bullet points for the main content.
"""

def synthesize(question: str, all_findings: list[dict]) -> str:
    print("\n[Synthesizer] Combining findings into final report...")
    successful = [result for result in all_findings if result["status"] == "success"]
    minimum_successes = max(1, (len(all_findings) + 1) // 2)
    if len(successful) < minimum_successes:
        raise RuntimeError(
            f"Insufficient research results: {len(successful)}/{len(all_findings)} succeeded"
        )
    findings_text = "\n\n".join(
        f"=== {r['subtopic']['title']} ===\n{r['findings']}"
        for r in successful
    )
    incomplete_note = (
        f"Only {len(successful)} of {len(all_findings)} researchers succeeded. "
        "State prominently that this report is incomplete.\n\n"
        if len(successful) != len(all_findings) else ""
    )
    prompt = (
        f"Research Question: {question}\n\n"
        "The findings below came from live search results. Preserve their source "
        "URLs as citations and clearly distinguish sourced facts from inference. "
        "Search snippets are discovery evidence, not substitutes for full-source "
        "verification; state that limitation.\n\n"
        f"{incomplete_note}"
        f"Findings from specialist agents:\n\n{findings_text}"
    )
    return run_agent(SYNTHESIZER_SYSTEM, prompt, use_tools=False)


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def run_pipeline(research_question: str) -> str:
    print("=" * 60)
    print(f"Research Question: {research_question}")
    print("=" * 60)

    # Stage 1: Plan
    subtopics = orchestrate(research_question)

    # Stage 2: Research (parallel)
    print("\n[Pipeline] Launching researcher agents in parallel...")
    all_findings = asyncio.run(research_all_parallel(subtopics))

    # Stage 3: Synthesize
    report = synthesize(research_question, all_findings)

    return report


if __name__ == "__main__":
    question = "What are the major challenges and recent breakthroughs in solid-state battery technology?"
    report = run_pipeline(question)

    print("\n" + "=" * 60)
    print("FINAL REPORT")
    print("=" * 60)
    print(report)

    with open("report.md", "w") as f:
        f.write(f"# Research Report\n\n**Question:** {question}\n\n{report}\n")
    print("\n[Done] Report saved to report.md")
