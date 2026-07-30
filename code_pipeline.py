"""
Code Writer + Critic Loop
--------------------------
Architecture:
  You → Writer → Critic → (issues?) → Writer → Critic → ... → Approved code

Agents:
  1. Writer  – generates or fixes code based on the request + any critic feedback
  2. Critic  – reviews code adversarially, returns APPROVED or a list of issues

The loop runs until the critic approves or max_iterations is reached.

To swap in a different model for the critic, change CRITIC_MODEL below.
"""

from dotenv import load_dotenv
import anthropic

load_dotenv(override=False)

client = anthropic.Anthropic()

WRITER_MODEL = "claude-opus-4-7"
CRITIC_MODEL = "claude-opus-4-7"  # swap to a different model here if desired

MAX_ITERATIONS = 5


def is_approved(feedback: str) -> bool:
    return feedback == "APPROVED"


def _first_text(response: object, agent_name: str) -> str:
    """Return the first nonempty model text block with a controlled failure."""
    for block in getattr(response, "content", []):
        text = getattr(block, "text", None)
        if isinstance(text, str) and text.strip():
            return text.strip()
    raise RuntimeError(f"{agent_name} returned no text content")

# ---------------------------------------------------------------------------
# System prompts
# ---------------------------------------------------------------------------

WRITER_SYSTEM = """
You are an expert Python developer. When given a coding request, write clean,
correct, production-quality Python code. Follow these rules:
- Handle edge cases and validate inputs where appropriate
- Use clear variable names
- Keep code concise but readable
- Return ONLY raw Python code — no explanation, no markdown, no ```python fences
"""

CRITIC_SYSTEM = """
You are an adversarial senior code reviewer. Your job is to find every bug,
edge case, security issue, and logical error in the code you are given.
Be thorough and skeptical — assume the code is broken until proven otherwise.

Respond in one of two ways ONLY:

1. If the code is correct and production-ready:
   APPROVED

2. If there are any issues:
   ISSUES:
   - <specific issue 1>
   - <specific issue 2>
   ...

Do not explain what the code does. Do not suggest style improvements.
Only report concrete bugs or correctness problems.
"""

# ---------------------------------------------------------------------------
# Agent calls
# ---------------------------------------------------------------------------

def write_code(
    request: str,
    previous_code: str | None = None,
    feedback: str | None = None,
) -> str:
    if previous_code and feedback:
        prompt = (
            f"Original request: {request}\n\n"
            f"Your previous attempt had the following issues:\n{feedback}\n\n"
            f"Previous code:\n{previous_code}\n\n"
            f"Fix all the issues and return the corrected code."
        )
    else:
        prompt = request

    response = client.messages.create(
        model=WRITER_MODEL,
        max_tokens=4096,
        system=WRITER_SYSTEM,
        messages=[{"role": "user", "content": prompt}],
    )
    code = _first_text(response, "Writer")
    compile(code, "<generated-code>", "exec")
    return code


def critique_code(code: str) -> str:
    response = client.messages.create(
        model=CRITIC_MODEL,
        max_tokens=1024,
        system=CRITIC_SYSTEM,
        messages=[{"role": "user", "content": code}],
    )
    return _first_text(response, "Critic")


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def run_code_pipeline(request: str) -> str:
    print(f"\nRequest: {request}")
    print("=" * 60)

    code = None
    feedback = None

    for iteration in range(1, MAX_ITERATIONS + 1):
        print(f"\n[Iteration {iteration}] Writer generating code...")
        code = write_code(request, previous_code=code, feedback=feedback)
        print(f"[Writer] Generated {len(code.splitlines())} lines")

        print(f"\n[Iteration {iteration}] Critic reviewing...")
        feedback = critique_code(code)
        print(f"Critic: {feedback}")

        if is_approved(feedback):
            print(f"\n✓ Approved after {iteration} iteration(s).")
            return code

    raise RuntimeError(
        f"Critic did not approve generated code after {MAX_ITERATIONS} iterations"
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    request = """
    Write a Python function called safe_divide(a, b) that:
    - Divides a by b
    - Handles division by zero
    - Handles non-numeric inputs
    - Returns a float result or raises a clear ValueError
    Include a few example calls at the bottom showing it works.
    """

    final_code = run_code_pipeline(request)

    with open("generated_code.py", "w") as f:
        f.write(final_code)
    print("\n[Done] Final code saved to generated_code.py")
