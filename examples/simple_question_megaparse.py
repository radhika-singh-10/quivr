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
# Model registry guard — block disapproved models
# ---------------------------------------------------------------------------
_ai_app_sec_006_DISAPPROVED_MODELS = [
    "deepseekchat",
    "deepseekr1",
    "deepseekr1distillllama70b",
    "deepseekreasoner",
    "customllmclientnull",
    "deepseekchatnull",
    "openrouternull",
    "usdeepseekr1v10null",
]


def _ai_app_sec_006_normalize(model_id: str) -> str:
    """Normalize a model identifier for comparison by lowercasing and removing separators."""
    return re.sub(r"[\s\-_\.:\u0000]", "", model_id).lower()


def _ai_app_sec_006_check_model(model_id: str) -> None:
    """Raise ValueError if *model_id* matches a disapproved model."""
    normalized = _ai_app_sec_006_normalize(model_id)
    for disapproved in _ai_app_sec_006_DISAPPROVED_MODELS:
        if normalized == disapproved:
            raise ValueError(
                f"Model '{model_id}' is on the organization's disapproved model list "
                "and cannot be used."
            )
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# Prompt-injection sanitizer for interactive user input
# ---------------------------------------------------------------------------
_ai_app_sec_070_patterns = [
    # 1. instruction_override
    (re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?", re.I), "instruction_override"),
    (re.compile(r"disregard\s+(all\s+)?(previous|prior|above)\s+instructions?", re.I), "instruction_override"),
    (re.compile(r"forget\s+(everything|all|what)\s+(you\s+(were|have\s+been)\s+told|above)", re.I), "instruction_override"),
    # 2. role_hijack
    (re.compile(r"you\s+are\s+now\s+(DAN|an?\s+unrestricted)", re.I), "role_hijack"),
    (re.compile(r"act\s+as\s+(a\s+|an\s+)?(different|new|unrestricted)", re.I), "role_hijack"),
    # 3. delimiter_escape
    (re.compile(r"</?\s*system\s*>", re.I), "delimiter_escape"),
    (re.compile(r"\[/?system\]", re.I), "delimiter_escape"),
    (re.compile(r"###\s*instruction", re.I), "delimiter_escape"),
    # 4. encoded_payload — base64 blobs (20+ chars)
    (re.compile(r"[A-Za-z0-9+/]{20,}={0,2}"), "encoded_payload"),
    # 5. hidden_text — zero-width characters
    (re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060\ufeff]+"), "hidden_text"),
    # 6. fake_system_message
    (re.compile(r"system\s*:\s*you", re.I), "fake_system_message"),
    (re.compile(r"new\s+(system\s+)?prompt", re.I), "fake_system_message"),
    # 7. exfiltration_attempt
    (re.compile(r"(fetch|curl|wget|https?://)\s*", re.I), "exfiltration_attempt"),
    (re.compile(r"exfiltrate", re.I), "exfiltration_attempt"),
    (re.compile(r"leak\s+(the\s+)?(system\s+prompt|prompt|instructions?)", re.I), "exfiltration_attempt"),
    # 8. context_poisoning
    (re.compile(r"context\s+poison", re.I), "context_poisoning"),
    # 12. jailbreak_attempt
    (re.compile(r"jailbreak", re.I), "jailbreak_attempt"),
    (re.compile(r"DAN\s+mode", re.I), "jailbreak_attempt"),
    (re.compile(r"developer\s+mode", re.I), "jailbreak_attempt"),
    (re.compile(r"unrestricted\s+mode", re.I), "jailbreak_attempt"),
    # 10. command_injection — real execution primitives
    (re.compile(r"\beval\s*\(", re.I), "command_injection"),
    (re.compile(r"\bexec\s*\(", re.I), "command_injection"),
    (re.compile(r"\bos\.system\s*\(", re.I), "command_injection"),
    (re.compile(r"\bsubprocess\b", re.I), "command_injection"),
]


def _ai_app_sec_070_sanitize_user_input(text: str) -> str:
    """Replace prompt-injection attack phrases in user input with safe markers."""
    if not isinstance(text, str):
        return text
    for pattern, category in _ai_app_sec_070_patterns:
        text = pattern.sub(f"<prompt_injection_removed: {category}>", text)
    return text

# Prefix used for all names added by this remediation
_ai_app_sec_067_BLOCKED_REQUEST_ID_PREFIX = "blocked-injection"


def _ai_app_sec_067_sanitize_question(question: str) -> str:
    """
    Validate and sanitize user-supplied question before it reaches the LLM.

    Steps:
      1. Reject inputs that match known prompt-injection patterns (direct,
         leetspeak-normalised, or base64-encoded variants).
      2. Wrap the validated input in structural XML delimiters so the model
         can distinguish the fixed instruction context from user data.

    Raises ValueError (and logs a warning) if injection is detected.
    Returns the delimited, safe question string.
    """
    if not isinstance(question, str):
        raise ValueError("Question must be a string.")

    candidates = [
        question,
        _decode_leet(question),
    ]
    candidates.extend(_extract_base64_payloads(question))

    for candidate in candidates:
        for pattern in _INJECTION_PATTERNS:
            if pattern.search(candidate):
                request_id = f"{_ai_app_sec_067_BLOCKED_REQUEST_ID_PREFIX}-{uuid.uuid4()}"
                logger.warning(
                    "Prompt-injection attempt detected and blocked. "
                    "request_id=%s pattern=%r input_length=%d",
                    request_id,
                    pattern.pattern,
                    len(question),
                )
                raise ValueError(
                    f"Input rejected: potential prompt-injection detected "
                    f"(request_id={request_id})."
                )

    # Wrap in structural delimiters so the LLM treats this as user data only
    safe_question = f"<user_question>\n{question}\n</user_question>"
    return safe_question


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

    _ai_app_sec_006_check_model("gpt-4o-mini")
    brain = Brain.from_files(
        name="test_brain",
        file_paths=_file_paths,
        llm=LLMEndpoint(
            llm_config=LLMEndpointConfig(model="gpt-4o-mini"),
            llm=ChatOpenAI(model="gpt-4o-mini", api_key=str(os.getenv("OPENAI_API_KEY"))),  # GPAI model card: MODEL_CARD_URL
        ),
    )
    # GPAI model card: MODEL_CARD_URL
    _ai_app_sec_006_check_model("text-embedding-3-large")
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

        _ai_app_sec_035_request_id = str(uuid.uuid4())
        _ai_app_sec_035_start = time.time()
        logger.info(
            "LLM request",
            extra={
                "event": "llm_request",
                "operation": "brain.ask",
                "request_id": _ai_app_sec_035_request_id,
                "input_length": len(question),
            },
        )
        try:
            safe_question = _ai_app_sec_067_sanitize_question(question)
        except ValueError as _ai_app_sec_067_exc:
            console.print(f"[bold red]Request blocked:[/bold red] {_ai_app_sec_067_exc}")
            console.print("-" * console.width)
            continue

        answer = brain.ask(safe_question)
        _ai_app_sec_035_duration = time.time() - _ai_app_sec_035_start
        logger.info(
            "LLM response",
            extra={
                "event": "llm_response",
                "operation": "brain.ask",
                "request_id": _ai_app_sec_035_request_id,
                "duration_seconds": _ai_app_sec_035_duration,
                "output_length": len(answer.answer) if answer and answer.answer else 0,
                "success": True,
            },
        )
        # Sanitize LLM output: remove lines with dynamic code execution primitives
        sanitized_answer = sanitize_llm_output(answer.answer)
        # Print the answer with typing effect
        console.print(f"[bold green]Quivr Assistant[/bold green]: {sanitized_answer}")

        console.print("-" * console.width)

    brain.print_info()
