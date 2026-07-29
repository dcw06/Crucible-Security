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
from typing import Any
from dotenv import load_dotenv

load_dotenv(override=True)

client = anthropic.Anthropic()

# ---------------------------------------------------------------------------
# Simulated tool execution
# In a real system, wire this to an actual search API (Brave, Tavily, etc.)
# ---------------------------------------------------------------------------

def web_search(query: str) -> str:
    """Stub — replace with a real search API call."""
    return (
        f"[Simulated search results for: '{query}']\n"
        f"- Source 1: Overview of {query} with key statistics and trends.\n"
        f"- Source 2: Recent developments in {query} as of 2025.\n"
        f"- Source 3: Expert analysis on the implications of {query}.\n"
        f"(Replace this stub with a real search API to get live results.)"
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
    messages = [{"role": "user", "content": user_message}]
    kwargs = {
        "model": "claude-opus-4-7",
        "max_tokens": 4096,
        "system": system,
        "messages": messages,
    }
    if use_tools:
        kwargs["tools"] = TOOLS

    while True:
        response = client.messages.create(**kwargs)

        if response.stop_reason == "end_turn":
            return next(
                (block.text for block in response.content if hasattr(block, "text")),
                "",
            )

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
    plan = json.loads(raw)
    subtopics = plan["subtopics"]
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
facts, statistics, and insights. Do not editorialize — stick to the evidence.
"""

def research_subtopic(subtopic: dict) -> dict:
    print(f"\n[Researcher {subtopic['id']}] Investigating: {subtopic['title']}")
    findings = run_agent(RESEARCHER_SYSTEM, subtopic["query"], use_tools=True)
    return {"subtopic": subtopic, "findings": findings}


async def research_all_parallel(subtopics: list[dict]) -> list[dict]:
    """Run all researcher agents concurrently using asyncio + a thread pool."""
    loop = asyncio.get_event_loop()
    tasks = [
        loop.run_in_executor(None, research_subtopic, subtopic)
        for subtopic in subtopics
    ]
    return await asyncio.gather(*tasks)


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
    findings_text = "\n\n".join(
        f"=== {r['subtopic']['title']} ===\n{r['findings']}"
        for r in all_findings
    )
    prompt = (
        f"Research Question: {question}\n\n"
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
