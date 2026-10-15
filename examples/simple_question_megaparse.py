import logging
import os
import time
import uuid
import re

from langchain_openai import ChatOpenAI, OpenAIEmbeddings
from quivr_core import Brain
from quivr_core.llm.llm_endpoint import LLMEndpoint
from quivr_core.rag.entities.config import LLMEndpointConfig
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
import base64

# Patterns that indicate dynamic code execution primitives
_DANGEROUS_PATTERNS = re.compile(
    r"""
    \beval\s*\(                          # Python/JS eval(
    | \bexec\s*\(                         # Python exec(
    | \bsubprocess\s*\..*shell\s*=\s*True  # subprocess(shell=True)
    | \bos\.system\s*\(                   # os.system(
    | \bos\.popen\s*\(                    # os.popen(
    | \bcommands\.getoutput\s*\(           # commands.getoutput(
    | \beval\s+["'`]                       # bash eval "..."
    | `[^`]*`                              # bash backtick execution
    | \$\(.*\)                             # bash $(...) substitution
    """,
    re.VERBOSE | re.IGNORECASE,
)


def sanitize_llm_output(text: str) -> str:
    """Remove lines containing dynamic code execution primitives from LLM output."""
    if not isinstance(text, str):
        return text
    sanitized_lines = [
        line for line in text.splitlines()
        if not _DANGEROUS_PATTERNS.search(line)
    ]
    return "\n".join(sanitized_lines)

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# ---------------------------------------------------------------------------
# Prompt-injection scanner
# ---------------------------------------------------------------------------
_INJECTION_PATTERNS = [
    # Direct instruction overrides
    re.compile(r"ignore (all )?(previous|prior|above) instructions?", re.I),
    re.compile(r"disregard (all )?(previous|prior|above) instructions?", re.I),
    re.compile(r"forget (everything|all|what) (you (were|have been) told|above)", re.I),
    re.compile(r"you are now", re.I),
    re.compile(r"act as (a |an )?(different|new|unrestricted)", re.I),
    re.compile(r"new (system |)prompt", re.I),
    re.compile(r"system\s*:\s*you", re.I),
    re.compile(r"<\s*system\s*>", re.I),
    re.compile(r"\[system\]", re.I),
    re.compile(r"###\s*instruction", re.I),
    # Jailbreak keywords
    re.compile(r"jailbreak", re.I),
    re.compile(r"DAN mode", re.I),
    re.compile(r"developer mode", re.I),
    re.compile(r"unrestricted mode", re.I),
    # Exfiltration / SSRF attempts
    re.compile(r"(fetch|curl|wget|http[s]?://)\s*", re.I),
    re.compile(r"exfiltrate", re.I),
    # Leetspeak variants of "ignore" / "prompt"
    re.compile(r"[i1][g9][n][o0][r][e3]", re.I),
    re.compile(r"[p][r][o0][m][p][t7]", re.I),
]

_LEETSPEAK_MAP = str.maketrans("013456789", "oieashgbq")


def _decode_leet(text: str) -> str:
    """Naively normalise common leetspeak substitutions."""
    return text.translate(_LEETSPEAK_MAP)


def _extract_base64_payloads(text: str) -> list[str]:
    """Return decoded strings for every plausible base64 blob found in *text*."""
    decoded: list[str] = []
    # Base64 tokens are typically 20+ chars of [A-Za-z0-9+/=]
    for token in re.findall(r"[A-Za-z0-9+/]{20,}={0,2}", text):
        try:
            decoded.append(base64.b64decode(token + "==").decode("utf-8", errors="ignore"))
        except Exception:
            pass
    return decoded


def scan_file_for_prompt_injection(file_path: str) -> None:
    """
    Read *file_path* as raw bytes, extract visible text, and raise ValueError
    if any prompt-injection pattern is detected (direct, leetspeak, or
    base64-encoded).
    """
    try:
        with open(file_path, "rb") as fh:
            raw = fh.read()
    except OSError as exc:
        raise ValueError(f"Cannot read file for scanning: {file_path}") from exc

    # Decode bytes to text, ignoring undecodable bytes
    text = raw.decode("utf-8", errors="ignore")

    candidates = [text, _decode_leet(text)]
    candidates.extend(_extract_base64_payloads(text))

    for candidate in candidates:
        for pattern in _INJECTION_PATTERNS:
            if pattern.search(candidate):
                raise ValueError(
                    f"Potential prompt-injection content detected in '{file_path}' "
                    f"(matched pattern: {pattern.pattern!r}). "
                    "File rejected before being sent to the LLM."
                )


# ---------------------------------------------------------------------------

if __name__ == "__main__":
    _file_paths = ["./tests/processor/pdf/sample.pdf"]
    for _fp in _file_paths:
        scan_file_for_prompt_injection(_fp)

    brain = Brain.from_files(
        name="test_brain",
        file_paths=_file_paths,
        llm=LLMEndpoint(
            llm_config=LLMEndpointConfig(model="gpt-4o-mini"),
            llm=ChatOpenAI(model="gpt-4o-mini", api_key=str(os.getenv("OPENAI_API_KEY"))),  # GPAI model card: MODEL_CARD_URL
        ),
    )
    # GPAI model card: MODEL_CARD_URL
    embedder = embeddings = OpenAIEmbeddings(
        model="text-embedding-3-large",
    )
    # Check brain info
    brain.print_info()

    console = Console()
    console.print(Panel.fit("Ask your brain !", style="bold magenta"))

    while True:
        # Get user input
        question = Prompt.ask("[bold cyan]Question[/bold cyan]")

        # Check if user wants to exit
        if question.lower() == "exit":
            console.print(Panel("Goodbye!", style="bold yellow"))
            break

        answer = brain.ask(question)
        # Sanitize LLM output: remove lines with dynamic code execution primitives
        sanitized_answer = sanitize_llm_output(answer.answer)
        # Print the answer with typing effect
        console.print(f"[bold green]Quivr Assistant[/bold green]: {sanitized_answer}")

        console.print("-" * console.width)

    brain.print_info()
