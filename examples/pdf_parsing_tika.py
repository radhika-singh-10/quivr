from langchain_openai import ChatOpenAI, OpenAIEmbeddings
from quivr_core import Brain
from quivr_core.rag.entities.config import LLMEndpointConfig
from quivr_core.llm.llm_endpoint import LLMEndpoint
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt

import re

# Model card / technical documentation references for GPAI models used in this module.
# See: https://openai.com/research/ for OpenAI model cards and technical reports.
_ai_iac_024_MODEL_CARD_URL = "https://openai.com/research/"  # TODO: replace with the exact model card URL before deployment
import base64
import unicodedata
import logging
import time
import uuid

logger = logging.getLogger(__name__)


_AI_APP_SEC_032_LEET_MAP = {
    '4': 'a', '@': 'a', '8': 'b', '(': 'c', '3': 'e',
    '6': 'g', '#': 'h', '1': 'i', '!': 'i', '|': 'i',
    '0': 'o', '9': 'g', '$': 's', '5': 's', '7': 't',
    '+': 't', '%': 'x', '2': 'z',
}

_AI_APP_SEC_032_LEET_TRIGGER_PATTERN = re.compile(
    r'(?:[4@][c(][t+]|[1!|][g9][n][0o][r3][e3]|[3e][x%][e3][c(]'
    r'|[3e][v][4a][|1!][\s]*[\(]'
    r'|[0o][s5][\s]*[\.]'
    r'|[s5][y][s5][t+][e3][m]'
    r'|[s5][u][b][p][r][0o][c(][e3][s5][s5]'
    r'|[p][0o][w][e3][r][s5][h][e3][|1!][|1!]'
    r'|[c(][m][d]'
    r'|[b][4a][s5][h]'
    r'|[s5][h][e3][|1!][|1!]'
    r'|[i1!][g9][n][0o][r3][e3].*[i1!][n][s5][t+][r][u][c(][t+][i1!][0o][n][s5]'
    r'|[d][i1!][s5][r][e3][g9][4a][r][d]'
    r'|[f][0o][r][g9][e3][t+].*[i1!][n][s5][t+][r][u][c(][t+][i1!][0o][n][s5]'
    r'|[j][4a][i1!][|1!][b][r][e3][4a][k]'
    r'|[p][r][e3][t+][e3][n][d]'
    r'|[4a][c(][t+].*[4a][s5]'
    r'|[y][0o][u].*[4a][r][e3].*[n][0o][w])',
    re.IGNORECASE,
)


def _ai_app_sec_032_decode_leet(text: str) -> str:
    """Translate common leetspeak substitutions to plain ASCII for pattern matching."""
    return ''.join(_AI_APP_SEC_032_LEET_MAP.get(ch, ch) for ch in text)


def _ai_app_sec_032_sanitize_leetspeak(text: str) -> str:
    """Replace leetspeak-obfuscated prompts/commands with a safe placeholder."""
    if _AI_APP_SEC_032_LEET_TRIGGER_PATTERN.search(text):
        return '<leetspeak_prompts_removed>'
    decoded = _ai_app_sec_032_decode_leet(text)
    _DECODED_INJECTION_PATTERNS = [
        r'ignore\s+(all\s+|previous\s+|above\s+|prior\s+)?instructions',
        r'disregard\s+(all\s+|previous\s+|above\s+|prior\s+)?instructions',
        r'forget\s+(all\s+|previous\s+|above\s+|prior\s+)?instructions',
        r'you\s+are\s+now',
        r'act\s+as',
        r'pretend\s+(to\s+be|you\s+are)',
        r'jailbreak',
        r'do\s+anything\s+now',
        r'override\s+(your\s+|all\s+)?(previous\s+|prior\s+)?instructions',
        r'system\s+prompt',
        r'eval\s*\(',
        r'exec\s*\(',
        r'os\.system\s*\(',
        r'os\.popen\s*\(',
        r'subprocess',
        r'powershell',
        r'\bcmd\b',
        r'\bbash\b',
        r'\bshell\b',
    ]
    for pat in _DECODED_INJECTION_PATTERNS:
        if re.search(pat, decoded, re.IGNORECASE):
            return '<leetspeak_prompts_removed>'
    return text



_AI_APP_SEC_006_DISAPPROVED_MODELS = [
    "deepseekchat",
    "deepseekr1",
    "deepseekr1distillllama70b",
    "deepseekreasoner",
    "customllmclient",
    "deepseekchаtnull",
    "opеnrouternull",
    "usdeepseekr1v10",
]


def _ai_app_sec_006_normalize(model_id: str) -> str:
    """Normalize a model identifier for registry comparison."""
    return re.sub(r"[\s\-_\.:\u0000-\u001f]", "", model_id).lower()


def _ai_app_sec_006_check_model(model_id: str) -> None:
    """Raise ValueError if the model is in the organization's disapproved list."""
    normalized = _ai_app_sec_006_normalize(model_id)
    for disapproved in _AI_APP_SEC_006_DISAPPROVED_MODELS:
        if normalized == _ai_app_sec_006_normalize(disapproved):
            raise ValueError(
                f"Model '{model_id}' is on the organization's disapproved model list "
                f"and cannot be used."
            )


_ai_dat_sec_012_PII_PATTERNS = [
    # Social Security Number
    (r'\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b', '[SSN REDACTED]'),
    # Taxpayer Identification Number (EIN format)
    (r'\b\d{2}-\d{7}\b', '[TIN REDACTED]'),
    # Credit Card Number (Visa, MC, Amex, Discover)
    (r'\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6011)[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{2,4}\b', '[CREDIT CARD REDACTED]'),
    # Financial Account Number (generic 8-17 digit)
    (r'\b(?:account\s*(?:number|#|no\.?)?\s*:?\s*)?\d{8,17}\b', '[ACCOUNT NUMBER REDACTED]'),
    # IP Address (v4)
    (r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '[IP ADDRESS REDACTED]'),
    # MAC Address
    (r'\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b', '[MAC ADDRESS REDACTED]'),
    # Email
    (r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b', '[EMAIL REDACTED]'),
    # Personal Phone Number (US and international)
    (r'\b(?:\+?1[\s\-.]?)?(?:\(?\d{3}\)?[\s\-.]?)\d{3}[\s\-.]?\d{4}\b', '[PHONE REDACTED]'),
    # Passport Number (generic alphanumeric 6-9 chars)
    (r'\b(?:passport\s*(?:number|#|no\.?)?\s*:?\s*)?[A-Z]{1,2}\d{6,7}\b', '[PASSPORT REDACTED]'),
    # Driver License Number (generic)
    (r'\b(?:driver[\s\']?s?\s*license\s*(?:number|#|no\.?)?\s*:?\s*)[A-Z0-9\-]{5,20}\b', '[DL REDACTED]'),
    # Vehicle Identification Number
    (r'\b[A-HJ-NPR-Z0-9]{17}\b', '[VIN REDACTED]'),
    # Year of Birth (context-based)
    (r'\b(?:born|birth\s*year|year\s*of\s*birth|dob|date\s*of\s*birth)\s*:?\s*(?:in\s*)?\d{4}\b', '[BIRTH YEAR REDACTED]'),
    # Home Address (street address pattern)
    (r'\b\d{1,5}\s+(?:[A-Za-z0-9]+\s){1,4}(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl|Circle|Cir)\b\.?', '[ADDRESS REDACTED]'),
    # Employee ID
    (r'\b(?:employee\s*(?:id|#|no\.?)|emp\s*id)\s*:?\s*[A-Z0-9\-]{3,15}\b', '[EMPLOYEE ID REDACTED]'),
    # School ID
    (r'\b(?:student\s*(?:id|#|no\.?)|school\s*(?:id|#|no\.?))\s*:?\s*[A-Z0-9\-]{3,15}\b', '[SCHOOL ID REDACTED]'),
    # Ethnicity keywords
    (r'\b(?:ethnicity|ethnic\s*background|race)\s*:?\s*[A-Za-z\s]{3,30}\b', '[ETHNICITY REDACTED]'),
    # Sexual Orientation
    (r'\b(?:sexual\s*orientation|sexuality)\s*:?\s*[A-Za-z\s]{3,30}\b', '[SEXUAL ORIENTATION REDACTED]'),
]


def _ai_dat_sec_012_mask_pii(text: str) -> str:
    """Mask zero-tolerance PII categories in text before display on user interface."""
    masked = text
    for pattern, replacement in _ai_dat_sec_012_PII_PATTERNS:
        masked = re.sub(pattern, replacement, masked, flags=re.IGNORECASE)
    return masked


def sanitize_llm_response(response: str) -> str:
    """Remove lines containing dynamic code execution primitives from LLM output."""
    dangerous_patterns = [
        r'\beval\s*\(',           # Python/JS eval(
        r'\bexec\s*\(',           # Python exec(
        r'\bsubprocess\s*\..*shell\s*=\s*True',  # subprocess(shell=True)
        r'\bos\.system\s*\(',     # os.system(
        r'\bos\.popen\s*\(',      # os.popen(
        r'\beval\s+["\']',        # bash eval "..." or eval '...'
        r'^\s*eval\s+\S',         # bash eval <arg>
        r'\bFunction\s*\(',       # JS new Function(
        r'\bsetTimeout\s*\(\s*["\']',   # JS setTimeout with string
        r'\bsetInterval\s*\(\s*["\']',  # JS setInterval with string
    ]
    combined = re.compile('|'.join(dangerous_patterns), re.IGNORECASE)
    sanitized_lines = [
        line for line in response.splitlines()
        if not combined.search(line)
    ]
    return '\n'.join(sanitized_lines)


# --- ai_app_sec_040: patterns for scanning untrusted file content ---
_ai_app_sec_040_SHELL_PATTERNS = [
    r"\beval\s*\(",
    r"\bexec\s*\(",
    r"\bos\.system\s*\(",
    r"\bos\.popen\s*\(",
    r"\bsubprocess\s*\.",
    r"\brm\s+-rf\b",
    r"\bcurl\s+http",
    r"\bwget\s+http",
    r"\bpowershell\b",
    r"\bcmd\.exe\b",
    r"\b/bin/sh\b",
    r"\b/bin/bash\b",
]

_ai_app_sec_040_INJECTION_FILE_PATTERNS = [
    r"ignore (all |previous |above |prior )?instructions",
    r"disregard (all |previous |above |prior )?instructions",
    r"forget (all |previous |above |prior )?instructions",
    r"you are now",
    r"act as",
    r"pretend (to be|you are)",
    r"jailbreak",
    r"do anything now",
    r"override (your |all )?(previous |prior )?instructions",
    r"system prompt",
    r"<\s*system\s*>",
    r"\[system\]",
    r"###\s*instruction",
    r"\{\{.*\}\}",
]

# Leetspeak substitution map for normalization
_ai_app_sec_040_LEET_MAP = str.maketrans(
    "013456789@$!",
    "oieaasbtggas",
)

# Zero-width and invisible Unicode characters
_ai_app_sec_040_INVISIBLE_CHARS = re.compile(
    r"[\u200b\u200c\u200d\u200e\u200f\u202a-\u202e\u2060-\u2064\ufeff\u00ad]"
)


def _ai_app_sec_040_decode_base64_segments(text: str) -> str:
    """Find and decode any base64-looking segments in text, return decoded content appended."""
    b64_pattern = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
    decoded_parts = []
    for match in b64_pattern.finditer(text):
        candidate = match.group(0)
        try:
            decoded = base64.b64decode(candidate + "==").decode("utf-8", errors="ignore")
            if decoded.isprintable() and len(decoded) > 4:
                decoded_parts.append(decoded)
        except Exception:
            pass
    return " ".join(decoded_parts)


def _ai_app_sec_040_normalize_leet(text: str) -> str:
    """Normalize leetspeak substitutions to plain ASCII for pattern matching."""
    return text.translate(_ai_app_sec_040_LEET_MAP)


def _ai_app_sec_040_scan_pdf_for_injections(file_path: str) -> None:
    """
    Extract text from a PDF and scan for prompt injections, base64 payloads,
    leetspeak obfuscation, invisible characters, and shell commands.
    Raises ValueError if any suspicious content is detected.
    """
    try:
        import pypdf  # type: ignore
        reader = pypdf.PdfReader(file_path)
        pages_text = []
        for page in reader.pages:
            extracted = page.extract_text() or ""
            pages_text.append(extracted)
        full_text = "\n".join(pages_text)
    except ImportError:
        # pypdf not available; skip deep scan but warn
        import warnings
        warnings.warn(
            f"pypdf not installed; skipping deep content scan of '{file_path}'. "
            "Install pypdf to enable full prompt-injection scanning of PDF files.",
            stacklevel=2,
        )
        return
    except Exception as exc:
        raise ValueError(
            f"Failed to read PDF '{file_path}' for security scanning: {exc}"
        ) from exc

    # 1. Check for invisible/zero-width characters (hidden text)
    if _ai_app_sec_040_INVISIBLE_CHARS.search(full_text):
        raise ValueError(
            f"File '{file_path}' contains invisible/zero-width Unicode characters "
            "that may be used to hide prompt injections."
        )

    # 2. Build candidate texts: raw, leet-normalized, and base64-decoded segments
    candidates = [
        full_text,
        _ai_app_sec_040_normalize_leet(full_text),
        _ai_app_sec_040_decode_base64_segments(full_text),
    ]

    all_patterns = _ai_app_sec_040_INJECTION_FILE_PATTERNS + _ai_app_sec_040_SHELL_PATTERNS

    for candidate_text in candidates:
        normalized = candidate_text.lower()
        for pattern in all_patterns:
            if re.search(pattern, normalized, re.IGNORECASE):
                raise ValueError(
                    f"File '{file_path}' contains potentially malicious content. "
                    f"Matched injection/shell pattern: '{pattern}'"
                )


INJECTION_PATTERNS = [
    r"ignore (all |previous |above |prior )?instructions",
    r"disregard (all |previous |above |prior )?instructions",
    r"forget (all |previous |above |prior )?instructions",
    r"you are now",
    r"act as",
    r"pretend (to be|you are)",
    r"jailbreak",
    r"do anything now",
    r"override (your |all )?(previous |prior )?instructions",
    r"system prompt",
    r"<\s*system\s*>",
    r"\[system\]",
    r"###\s*instruction",
    r"\{\{.*\}\}",
]


def sanitize_input(text: str) -> str:
    """Detect and block prompt injection attempts in user input."""
    import re
    normalized = text.lower()
    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, normalized, re.IGNORECASE):
            raise ValueError(
                f"Prompt injection attempt detected and blocked. "
                f"Matched pattern: '{pattern}'"
            )
    # Strip null bytes and other control characters that may be used to obfuscate injections
    sanitized = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
    return sanitized


if __name__ == "__main__":
    _ai_app_sec_040_pdf_paths = ["tests/processor/data/dummy.pdf"]
    for _ai_app_sec_040_fp in _ai_app_sec_040_pdf_paths:
        _ai_app_sec_040_scan_pdf_for_injections(_ai_app_sec_040_fp)

    brain = Brain.from_files(
        name="test_brain",
        file_paths=_ai_app_sec_040_pdf_paths,
        llm=LLMEndpoint(
            llm=(_ai_app_sec_006_check_model("gpt-4o") or ChatOpenAI(model="gpt-4o")),
            llm_config=LLMEndpointConfig(model="gpt-4o"),
        ),
        embedder=(_ai_app_sec_006_check_model("text-embedding-3-small") or OpenAIEmbeddings(model="text-embedding-3-small")),
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

        try:
            sanitized_question = sanitize_input(question)
        except ValueError as e:
            console.print(f"[bold red]Blocked:[/bold red] {e}")
            console.print("-" * console.width)
            continue
        sanitized_question = _ai_app_sec_032_sanitize_leetspeak(sanitized_question)
        answer = brain.ask(sanitized_question)
        # Sanitize LLM response to remove dynamic code execution primitives
        sanitized_answer = sanitize_llm_response(
            _ai_app_sec_032_sanitize_leetspeak(answer.answer)
        )
        # Print the answer with typing effect
        display_answer = _ai_dat_sec_012_mask_pii(sanitized_answer)
        console.print(f"[bold green]Quivr Assistant[/bold green]: {display_answer}")

        console.print("-" * console.width)

    brain.print_info()
