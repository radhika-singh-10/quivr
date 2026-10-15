import os
import re
import tempfile
from uuid import uuid4

import chainlit as cl
from langchain_community.embeddings import OllamaEmbeddings
from quivr_core import Brain, register_processor
from quivr_core.files.file import FileExtension
from quivr_core.llm import LLMEndpoint
from quivr_core.processor.implementations.simple_txt_processor import SimpleTxtProcessor
from quivr_core.rag.entities.config import LLMEndpointConfig, RetrievalConfig
import base64
import logging

def sanitize_content(text: str) -> str:
    """Replace hidden/invisible prompt content with a safe placeholder."""
    if not isinstance(text, str):
        return text

    # Remove zero-width and other invisible Unicode characters
    invisible_chars = (
        "\u200b"  # zero-width space
        "\u200c"  # zero-width non-joiner
        "\u200d"  # zero-width joiner
        "\u200e"  # left-to-right mark
        "\u200f"  # right-to-left mark
        "\u202a"  # left-to-right embedding
        "\u202b"  # right-to-left embedding
        "\u202c"  # pop directional formatting
        "\u202d"  # left-to-right override
        "\u202e"  # right-to-left override
        "\u2060"  # word joiner
        "\u2061"  # function application
        "\u2062"  # invisible times
        "\u2063"  # invisible separator
        "\u2064"  # invisible plus
        "\ufeff"  # zero-width no-break space / BOM
        "\u00ad"  # soft hyphen
        "\u034f"  # combining grapheme joiner
        "\u115f"  # hangul choseong filler
        "\u1160"  # hangul jungseong filler
        "\u3164"  # hangul filler
        "\uffa0"  # halfwidth hangul filler
    )
    invisible_pattern = "[" + re.escape(invisible_chars) + "]"
    result = re.sub(invisible_pattern, "", text)

    # Detect runs of whitespace-only content that may hide injected instructions
    # (e.g. white-on-white: large blocks of spaces/newlines hiding text)
    # Replace sequences of 10+ consecutive whitespace-only lines with placeholder
    result = re.sub(r"([ \t]*\n){10,}", "\n<hidden_prompts_removed>\n", result)

    # Remove HTML/CSS-based hiding: color:white, color:#fff, color:#ffffff
    result = re.sub(
        r"<[^>]*style=[^>]*color\s*:\s*(?:white|#fff(?:fff)?)[^>]*>.*?</[^>]+>",
        "<hidden_prompts_removed>",
        result,
        flags=re.IGNORECASE | re.DOTALL,
    )

    # Remove tiny font-size tricks (font-size: 0, 1px, 0px, 0pt, 0em, 0rem)
    result = re.sub(
        r"<[^>]*style=[^>]*font-size\s*:\s*(?:0|[01]px|0pt|0em|0rem)[^>]*>.*?</[^>]+>",
        "<hidden_prompts_removed>",
        result,
        flags=re.IGNORECASE | re.DOTALL,
    )

    # Remove display:none and visibility:hidden elements
    result = re.sub(
        r"<[^>]*style=[^>]*(?:display\s*:\s*none|visibility\s*:\s*hidden)[^>]*>.*?</[^>]+>",
        "<hidden_prompts_removed>",
        result,
        flags=re.IGNORECASE | re.DOTALL,
    )

    return result


# Patterns that indicate dynamic code execution primitives that must be removed.
_DANGEROUS_PATTERNS = re.compile(
    r"(?:"
    r"\beval\s*\("
    r"|\bexec\s*\("
    r"|\bsubprocess\.(?:call|run|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True"
    r"|\bos\.system\s*\("
    r"|\bos\.popen\s*\("
    r"|\bcommands\.getoutput\s*\("
    r"|\b__import__\s*\("
    r"|\bcompile\s*\("
    r"|\bexecfile\s*\("
    r"|\binput\s*\(.*eval"
    r"|\$\(.*\)"
    r"|`[^`]+`"
    r"|\beval\s+[\"'`$]"
    r")",
    re.IGNORECASE,
)


def sanitize_llm_output(text: str) -> str:
    """Remove lines containing dynamic code execution primitives from LLM output."""
    if not text:
        return text
    sanitized_lines = []
    for line in text.splitlines(keepends=True):
        if _DANGEROUS_PATTERNS.search(line):
            # Replace the dangerous line with a safety notice
            sanitized_lines.append("[Line removed: contains disallowed dynamic code execution primitive]\n")
        else:
            sanitized_lines.append(line)
    return "".join(sanitized_lines)


# ---------------------------------------------------------------------------
# Leetspeak sanitiser
# ---------------------------------------------------------------------------
_LEET_MAP = str.maketrans("013456789@$!|", "oieashgbqasl")

# Heuristic: a token is considered leetspeak when it contains at least two
# leet substitutions (digits/symbols standing in for letters).
_LEET_TOKEN_RE = re.compile(
    r"\b(?=[a-zA-Z0-9@$!|]*[013456789@$!|][a-zA-Z0-9@$!|]*"
    r"[013456789@$!|][a-zA-Z0-9@$!|]*)\S+\b"
)
# Broader pattern: sequences that look like obfuscated shell/prompt commands
# (e.g.  /b1n/sh,  3ch0,  1gnor3  pr3v10us  1nstruct10ns …)
_LEET_PHRASE_RE = re.compile(
    r"(?i)"
    r"(?:"
    r"1[g9][n][o0][r][e3]\s+(?:pr[e3]v[i1][o0][u][s]\s+)?[i1]n[s5]tr[u][c][t][i1][o0]n[s5]"
    r"|[a4][c][t]\s+[a4][s5]\s+"
    r"|[y][o0][u]\s+[a4]r[e3]\s+n[o0][w]"
    r"|[s5][y][s5]t[e3]m\s+[c][o0]mm[a4]n[d]"
    r"|[e3][x][e3][c][u][t][e3]"
    r"|[/\\][b][1i][n][/\\]"
    r"|[s5][h][e3][l1][l1]"
    r")"
)


def remove_leetspeak_prompts(text: str) -> str:
    """Replace leetspeak-obfuscated prompts/commands with a safe placeholder."""
    # First pass: replace whole phrases that match known obfuscated patterns.
    text = _LEET_PHRASE_RE.sub("<leetspeak_prompts_removed>", text)
    # Second pass: replace individual tokens that look like leet substitutions.
    def _replace_token(m: re.Match) -> str:
        token = m.group(0)
        translated = token.translate(_LEET_MAP)
        # Count how many characters were actually substituted.
        subs = sum(1 for a, b in zip(token, translated) if a != b)
        if subs >= 2:
            return "<leetspeak_prompts_removed>"
        return token
    text = _LEET_TOKEN_RE.sub(_replace_token, text)
    return text


logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# Known prompt injection / role-override patterns to block
_INJECTION_PATTERNS_2 = re.compile(
    r"(ignore (previous|above|all) instructions"
    r"|system\s*:"
    r"|assistant\s*:"
    r"|<\s*/?system\s*>"
    r"|\[INST\]"
    r"|###\s*(system|instruction|prompt)"
    r"|you are now"
    r"|disregard (all|any|previous)"
    r"|forget (everything|all|your instructions))",
    re.IGNORECASE,
)


def sanitize_user_input(text: str) -> str:
    """Sanitize user input before passing it to the LLM.

    Raises ValueError if the input contains known prompt-injection patterns.
    Returns the input wrapped in structural XML delimiters so the model can
    clearly distinguish user data from system instructions.
    """
    if not isinstance(text, str):
        raise ValueError("User input must be a string.")

    # Reject inputs that match known injection patterns
    if _INJECTION_PATTERNS_2.search(text):
        logger.warning(
            "Prompt injection attempt detected and blocked. "
            "Input snippet: %.120s",
            text,
        )
        raise ValueError(
            "Your message contains patterns that are not allowed. "
            "Please rephrase your question."
        )

    # Wrap user data in structural delimiters so the model treats it as data
    return f"<user_query>\n{text}\n</user_query>"


# Parse .txt locally. Megaparse is the default and tries Quivr's hosted NATS,
# which fails with "nodename nor servname provided" when that host is down.
register_processor(FileExtension.txt, SimpleTxtProcessor, override=True)

# ---------------------------------------------------------------------------
# Prompt-injection guardrail
# ---------------------------------------------------------------------------
_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)", re.IGNORECASE),
    re.compile(r"disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)", re.IGNORECASE),
    re.compile(r"forget\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(?:a\s+)?(?:an?\s+)?(?:new|different|another|evil|unrestricted)", re.IGNORECASE),
    re.compile(r"act\s+as\s+(?:a\s+)?(?:an?\s+)?(?:different|new|evil|unrestricted|jailbroken)", re.IGNORECASE),
    re.compile(r"pretend\s+(you\s+are|to\s+be)\s+(?:a\s+)?(?:an?\s+)?(?:different|new|evil|unrestricted)", re.IGNORECASE),
    re.compile(r"system\s*:\s*you\s+are", re.IGNORECASE),
    re.compile(r"<\s*system\s*>", re.IGNORECASE),
    re.compile(r"\[\s*system\s*\]", re.IGNORECASE),
    re.compile(r"###\s*instruction", re.IGNORECASE),
    re.compile(r"jailbreak", re.IGNORECASE),
    re.compile(r"prompt\s+injection", re.IGNORECASE),
    re.compile(r"bypass\s+(your\s+)?(safety|filter|restriction|guideline|policy)", re.IGNORECASE),
    re.compile(r"reveal\s+(your\s+)?(system\s+prompt|instructions?|prompt)", re.IGNORECASE),
    re.compile(r"print\s+(your\s+)?(system\s+prompt|instructions?|prompt)", re.IGNORECASE),
    re.compile(r"output\s+(your\s+)?(system\s+prompt|instructions?|prompt)", re.IGNORECASE),
]


def enforce(text: str, label: str = "input") -> str:
    """Raise ValueError if *text* contains prompt-injection patterns.

    Returns the original text unchanged when no injection is detected,
    so it can be used inline:  safe = enforce(raw)
    """
    for pattern in _INJECTION_PATTERNS:
        if pattern.search(text):
            raise ValueError(
                f"Prompt injection detected in {label}: "
                f"matched pattern '{pattern.pattern}'"
            )
    return text
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Prompt-injection sanitiser for uploaded text files
# ---------------------------------------------------------------------------
_INVISIBLE_CHARS = re.compile(
    r"[\u00ad\u200b-\u200f\u202a-\u202e\u2060-\u2064\u206a-\u206f\ufeff]"
)

# Patterns that strongly suggest an injection attempt
_INJECTION_PATTERNS = [
    # Classic prompt-injection phrases
    re.compile(
        r"(ignore|disregard|forget)\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(you\s+are\s+now|act\s+as|pretend\s+(to\s+be|you\s+are)|your\s+new\s+(role|persona|instructions?))",
        re.IGNORECASE,
    ),
    re.compile(
        r"(system\s*:|<\s*system\s*>|\[\s*system\s*\]|###\s*system)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(jailbreak|dan\s+mode|developer\s+mode|unrestricted\s+mode)",
        re.IGNORECASE,
    ),
    # Shell / code execution
    re.compile(
        r"(\$\(|`[^`]+`|\bexec\s*\(|\beval\s*\(|\bos\.system\s*\(|\bsubprocess\b)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(\brm\s+-rf\b|\bchmod\s+[0-7]{3,4}\b|\bcurl\s+http|\bwget\s+http)",
        re.IGNORECASE,
    ),
]

# Leetspeak substitution table (expand as needed)
_LEET_TABLE = str.maketrans("013456789", "oieaasbtg")


def _decode_leet(text: str) -> str:
    """Return a rough plain-text version of a leetspeak string."""
    return text.translate(_LEET_TABLE)


def _looks_like_base64(token: str) -> bool:
    """Return True when *token* decodes to a non-trivial UTF-8 string."""
    if len(token) < 20 or len(token) % 4 != 0:
        return False
    if not re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", token):
        return False
    try:
        decoded = base64.b64decode(token).decode("utf-8", errors="strict")
        # Only flag it when the decoded payload contains printable text
        return len(decoded.strip()) > 10
    except Exception:
        return False


def sanitize_uploaded_text(text: str) -> str:
    """Sanitise *text* read from an uploaded file.

    Raises ``ValueError`` if the content looks like a prompt-injection attempt.
    Returns the cleaned text otherwise.
    """
    # 1. Strip invisible / zero-width characters
    cleaned = _INVISIBLE_CHARS.sub("", text)

    # 2. Reject suspiciously large base64 blobs
    for token in re.split(r"\s+", cleaned):
        if _looks_like_base64(token):
            raise ValueError(
                "File contains base64-encoded content that may hide malicious prompts."
            )

    # 3. Check both the raw text and a de-leetspoken version
    for variant in (cleaned, _decode_leet(cleaned)):
        for pattern in _INJECTION_PATTERNS:
            if pattern.search(variant):
                raise ValueError(
                    f"File contains a potential prompt-injection pattern: "
                    f"{pattern.pattern!r}"
                )

    return cleaned

# ChatOpenAI requires a key even when the backend is Ollama.
os.environ.setdefault("OPENAI_API_KEY", "ollama")

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_CHAT_MODEL = os.getenv("OLLAMA_CHAT_MODEL", "gpt-4o")
OLLAMA_EMBED_MODEL = os.getenv("OLLAMA_EMBED_MODEL", "text-embedding-3-small")


# Regex patterns for zero-tolerance PII categories
_PII_PATTERNS = [
    # Social Security Number
    (re.compile(r'\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b'), '[REDACTED_SSN]'),
    # Taxpayer Identification Number (EIN format)
    (re.compile(r'\b\d{2}-\d{7}\b'), '[REDACTED_TIN]'),
    # Credit Card Number (Visa, MC, Amex, Discover)
    (re.compile(r'\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13}|6(?:011|5\d{2})\d{12})\b'), '[REDACTED_CC]'),
    # Financial Account Number (generic 8-17 digit)
    (re.compile(r'\b\d{8,17}\b'), '[REDACTED_ACCOUNT]'),
    # Passport Number (US-style)
    (re.compile(r'\b[A-Z]{1,2}\d{6,9}\b'), '[REDACTED_PASSPORT]'),
    # Driver's License (common US formats)
    (re.compile(r'\b[A-Z]{1,2}\d{5,8}\b'), '[REDACTED_DL]'),
    # Email address
    (re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'), '[REDACTED_EMAIL]'),
    # Personal Phone Number
    (re.compile(r'\b(?:\+?1[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}\b'), '[REDACTED_PHONE]'),
    # IP Address (IPv4)
    (re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'), '[REDACTED_IP]'),
    # MAC Address
    (re.compile(r'\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b'), '[REDACTED_MAC]'),
    # Vehicle Identification Number (VIN)
    (re.compile(r'\b[A-HJ-NPR-Z0-9]{17}\b'), '[REDACTED_VIN]'),
    # Year of Birth (standalone 4-digit year 1900-2099 near birth keywords)
    (re.compile(r'(?i)\b(?:born|birth(?:day|date)?|dob|year of birth)[:\s]+(?:19|20)\d{2}\b'), '[REDACTED_YOB]'),
    # Home Address (street address pattern)
    (re.compile(r'\b\d{1,5}\s+[A-Za-z0-9\s,\.]+(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl)\b', re.IGNORECASE), '[REDACTED_ADDRESS]'),
    # Employee ID
    (re.compile(r'(?i)\b(?:emp(?:loyee)?[\s._-]?(?:id|no|num(?:ber)?))[:\s]+[A-Z0-9\-]{3,15}\b'), '[REDACTED_EMP_ID]'),
    # School ID
    (re.compile(r'(?i)\b(?:student[\s._-]?(?:id|no|num(?:ber)?))[:\s]+[A-Z0-9\-]{3,15}\b'), '[REDACTED_SCHOOL_ID]'),
    # Ethnicity keywords
    (re.compile(r'(?i)\b(?:ethnicity|race)[:\s]+[A-Za-z\s]{2,30}\b'), '[REDACTED_ETHNICITY]'),
    # Sexual Orientation keywords
    (re.compile(r'(?i)\b(?:sexual orientation|sexuality)[:\s]+[A-Za-z\s]{2,30}\b'), '[REDACTED_ORIENTATION]'),
]


def redact_pii(text: str) -> str:
    """Redact zero-tolerance PII categories from the given text."""
    for pattern, replacement in _PII_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


# ---------------------------------------------------------------------------
# PII / secrets redaction
# ---------------------------------------------------------------------------
_REDACT_PATTERNS: list[tuple[str, str]] = [
    # Social Security Number  (e.g. 123-45-6789 / 123 45 6789)
    (r'\b\d{3}[\s\-]\d{2}[\s\-]\d{4}\b', '[REDACTED_SSN]'),
    # Taxpayer Identification Number (same format as SSN but kept explicit)
    (r'\bTIN[:\s]*\d{3}[\s\-]\d{2}[\s\-]\d{4}\b', '[REDACTED_TIN]'),
    # Credit card numbers (13-16 digits, optionally separated by spaces/dashes)
    (r'\b(?:\d[ \-]?){13,15}\d\b', '[REDACTED_CC]'),
    # Email addresses
    (r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b', '[REDACTED_EMAIL]'),
    # Personal phone numbers (various formats)
    (r'\b(?:\+?1[\s\-.])?\(?\d{3}\)?[\s\-.]\d{3}[\s\-.]\d{4}\b', '[REDACTED_PHONE]'),
    # Passport numbers (generic: letter(s) + 6-9 digits)
    (r'\b[A-Z]{1,2}\d{6,9}\b', '[REDACTED_PASSPORT]'),
    # Driver's license (US common patterns: 1-2 letters + 5-8 digits)
    (r'\b[A-Z]{1,2}\d{5,8}\b', '[REDACTED_DL]'),
    # IP addresses (IPv4)
    (r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '[REDACTED_IP]'),
    # MAC addresses
    (r'\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b', '[REDACTED_MAC]'),
    # Financial account numbers (8-17 digit standalone numbers)
    (r'\b\d{8,17}\b', '[REDACTED_ACCOUNT]'),
    # Home address indicators (street address pattern)
    (r'\b\d{1,5}\s+(?:[A-Za-z]+\s){1,4}(?:St|Street|Ave|Avenue|Blvd|Boulevard|Rd|Road|Dr|Drive|Ln|Lane|Ct|Court|Way|Pl|Place)\.?\b',
     '[REDACTED_ADDRESS]'),
    # AWS access key IDs
    (r'\b(?:AKIA|AIPA|ASIA|AROA|ANPA|ANVA|AIDA)[A-Z0-9]{16}\b', '[REDACTED_AWS_KEY]'),
    # AWS secret access keys (40-char base64-ish after keyword)
    (r'(?i)(?:aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key|aws[_\-\s]?token)[\s:=]+[A-Za-z0-9/+]{40}',
     '[REDACTED_AWS_SECRET]'),
    # GCP / service-account private keys (PEM blocks)
    (r'-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----',
     '[REDACTED_PRIVATE_KEY]'),
    # Azure SAS tokens / connection strings
    (r'(?i)(?:AccountKey|SharedAccessSignature|sig)=[A-Za-z0-9%/+]{20,}', '[REDACTED_AZURE_TOKEN]'),
    # Generic Bearer / API tokens
    (r'(?i)(?:bearer|token|api[_\-]?key|auth[_\-]?token|access[_\-]?token|secret)[\s:=]+[A-Za-z0-9\-_.~+/]{16,}',
     '[REDACTED_TOKEN]'),
    # Passwords in key=value style
    (r'(?i)(?:password|passwd|pwd)[\s:=]+\S+', '[REDACTED_PASSWORD]'),
    # Vehicle Identification Numbers (17 alphanumeric, no I/O/Q)
    (r'\b[A-HJ-NPR-Z0-9]{17}\b', '[REDACTED_VIN]'),
]


def redact_pii_2(text: str) -> str:
    """Return *text* with zero-tolerance PII and secrets replaced by redaction tokens."""
    for pattern, replacement in _REDACT_PATTERNS:
        text = re.sub(pattern, replacement, text)
    return text


def mask_pii(text: str) -> str:
    """Mask zero-tolerance PII categories before displaying content on the UI."""
    # Social Security Number (SSN)
    text = re.sub(r'\b(?!000|666|9\d{2})\d{3}[- ]?(?!00)\d{2}[- ]?(?!0000)\d{4}\b', '[SSN REDACTED]', text)
    # Taxpayer Identification Number (same pattern as SSN / EIN variants)
    text = re.sub(r'\b\d{2}-\d{7}\b', '[TIN REDACTED]', text)
    # Credit Card Number (Visa, MC, Amex, Discover)
    text = re.sub(r'\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{3,4}\b', '[CREDIT CARD REDACTED]', text)
    # Financial Account Number (generic 8-17 digit sequences not already matched)
    text = re.sub(r'\bACCT\.?\s*#?\s*\d{8,17}\b', '[ACCOUNT NUMBER REDACTED]', text, flags=re.IGNORECASE)
    # Email address
    text = re.sub(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b', '[EMAIL REDACTED]', text)
    # Personal Phone Number (US and international formats)
    text = re.sub(r'(?:\+?1[\s\-.]?)?(?:\(?\d{3}\)?[\s\-.]?)\d{3}[\s\-.]\d{4}\b', '[PHONE REDACTED]', text)
    # IP Address (IPv4)
    text = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '[IP ADDRESS REDACTED]', text)
    # MAC Address
    text = re.sub(r'\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b', '[MAC ADDRESS REDACTED]', text)
    # Passport Number (generic: letter(s) followed by 6-9 digits)
    text = re.sub(r'\b[A-Z]{1,2}\d{6,9}\b', '[PASSPORT/ID REDACTED]', text)
    # Driver's License Number (common US formats)
    text = re.sub(r'\b[A-Z]{1,2}\d{5,8}\b', '[DL NUMBER REDACTED]', text)
    # Vehicle Identification Number (VIN: 17 alphanumeric chars)
    text = re.sub(r'\b[A-HJ-NPR-Z0-9]{17}\b', '[VIN REDACTED]', text)
    # Year of Birth (standalone 4-digit year between 1900-2009 preceded by DOB/born keywords)
    text = re.sub(r'(?i)(?:born|dob|date of birth|birth\s*year)[:\s]+(?:19|20)\d{2}\b', '[BIRTH YEAR REDACTED]', text)
    # Home Address (street address pattern)
    text = re.sub(r'\b\d{1,5}\s+[A-Za-z0-9\s]{3,40}(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl)\.?\b', '[ADDRESS REDACTED]', text, flags=re.IGNORECASE)
    # Employee ID / School ID (common prefixes)
    text = re.sub(r'(?i)\b(?:emp(?:loyee)?|school|student)[\s\-]?(?:id|#|no\.?)[:\s]+[A-Z0-9\-]{4,12}\b', '[ID REDACTED]', text)
    return text


def ollama_llm() -> LLMEndpoint:
    # Model card: see LLAMA_MODEL_CARD_URL for technical documentation.
    llm = LLMEndpoint.from_config(
        LLMEndpointConfig(
            model=OLLAMA_CHAT_MODEL,
            llm_api_key="ollama",
            llm_base_url=f"{OLLAMA_HOST.rstrip('/')}/v1",
            max_output_tokens=8192,
            temperature=0.7,
        )
    )
    # Local models usually cannot satisfy cited_answer tool calls.
    llm._supports_func_calling = False
    return llm


def ollama_embedder() -> OllamaEmbeddings:
    # Model card: see NOMIC_EMBED_MODEL_CARD_URL for technical documentation.
    return OllamaEmbeddings(model=OLLAMA_EMBED_MODEL, base_url=OLLAMA_HOST)


@cl.on_chat_start
async def on_chat_start():
    files = None

    # Wait for the user to upload a file
    while files is None:
        files = await cl.AskFileMessage(
            content="Please upload a text .txt file to begin!",
            accept=["text/plain"],
            max_size_mb=20,
            timeout=180,
        ).send()

    file = files[0]

    msg = cl.Message(content=f"Processing `{file.name}`...")
    await msg.send()

    with open(file.path, "r", encoding="utf-8") as f:
        text = f.read()

    try:
        enforce(text, label=f"uploaded file '{file.name}'")
    except ValueError as exc:
        msg.content = f"⚠️ File rejected: {exc}"
        await msg.update()
        return

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=file.name, delete=False
    ) as temp_file:
        temp_file.write(text)
        temp_file.flush()
        temp_file_path = temp_file.name

    brain = await Brain.afrom_files(
        name="user_brain",
        file_paths=[temp_file_path],
        llm=ollama_llm(),
        embedder=ollama_embedder(),
    )

    # Store the file path in the session
    cl.user_session.set("file_path", temp_file_path)

    # Let the user know that the system is ready
    msg.content = f"Processing `{file.name}` done. You can now ask questions!"
    await msg.update()

    cl.user_session.set("brain", brain)


@cl.on_message
async def main(message: cl.Message):
    brain = cl.user_session.get("brain")  # type: Brain
    path_config = "basic_rag_workflow.yaml"
    retrieval_config = RetrievalConfig.from_yaml(path_config)
    if brain is not None:
        # Keep the YAML workflow, but do not let it fall back to OpenAI.
        retrieval_config.llm_config = brain.llm.get_config()

    if brain is None:
        await cl.Message(content="Please upload a file first.").send()
        return

    # Prepare the message for streaming
    msg = cl.Message(content="", elements=[])
    await msg.send()

    saved_sources = set()
    saved_sources_complete = []
    elements = []

    # Sanitize and structurally delimit user input before sending to the LLM
    try:
        safe_query = sanitize_user_input(message.content)
    except ValueError as exc:
        msg.content = str(exc)
        await msg.update()
        return

    # Use the ask_stream method for streaming responses
    try:
        safe_message = enforce(message.content, label="user message")
    except ValueError as exc:
        msg.content = f"⚠️ Message rejected: {exc}"
        await msg.update()
        return

    async for chunk in brain.ask_streaming(
        safe_message,
        run_id=uuid4(),
        retrieval_config=retrieval_config,
    ):
        await msg.stream_token(sanitize_content(chunk.answer))
        for source in chunk.metadata.sources:
            if source.page_content not in saved_sources:
                saved_sources.add(source.page_content)
                saved_sources_complete.append(source)
                redacted_content = redact_pii(source.page_content)
                print(f"Source file: {source.metadata.get('original_file_name', 'unknown')} | Content: {redacted_content}")
                elements.append(cl.Text(name=source.metadata["original_file_name"], content=sanitize_content(source.page_content), display="side"))

    
    await msg.send()
    sources = ""
    for source in saved_sources_complete:
        sources += f"- {source.metadata['original_file_name']}\n"
    msg.elements = elements
    msg.content = sanitize_llm_output(msg.content) + f"\n\nSources:\n{sources}"
    await msg.update()
