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

HIDDEN_PROMPT_REPLACEMENT = "<hidden_prompts_removed>"

# Patterns that indicate hidden/invisible prompt injection attempts
_HIDDEN_PROMPT_PATTERNS = [
    # Zero-width and invisible Unicode characters
    re.compile(r'[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u206a-\u206f\ufeff\u00ad]+'),
    # HTML/CSS style tricks: color white, font-size 0/1px, display none, visibility hidden
    re.compile(
        r'<[^>]*(?:'
        r'style\s*=\s*["\'][^"\'>]*(?:'
        r'color\s*:\s*(?:white|#fff(?:fff)?|rgb\(\s*255\s*,\s*255\s*,\s*255\s*\))'
        r'|font-size\s*:\s*[01](?:\.\d+)?px'
        r'|display\s*:\s*none'
        r'|visibility\s*:\s*hidden'
        r'|opacity\s*:\s*0'
        r')[^"\'>]*["\']'
        r')[^>]*>.*?</[^>]+>',
        re.IGNORECASE | re.DOTALL,
    ),
    # HTML comments (can hide instructions)
    re.compile(r'<!--.*?-->', re.DOTALL),
    # Markdown/HTML font tags with size=1
    re.compile(r'<font[^>]*size\s*=\s*["\']?1["\']?[^>]*>.*?</font>', re.IGNORECASE | re.DOTALL),
    # Repeated whitespace used to push content off-screen
    re.compile(r'[ \t]{200,}'),
    # Null bytes
    re.compile(r'\x00+'),
]


def sanitize_content(text: str) -> str:
    """Replace hidden/invisible prompt patterns with a safe placeholder."""
    if not text:
        return text
    sanitized = text
    for pattern in _HIDDEN_PROMPT_PATTERNS:
        sanitized = pattern.sub(HIDDEN_PROMPT_REPLACEMENT, sanitized)
    return sanitized


# Patterns for dynamic code execution primitives that must be stripped from LLM output.
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
    r"|bash\s+-c"
    r"|\$\(.*\)"
    r")",
    re.IGNORECASE,
)


def sanitize_llm_output(text: str) -> str:
    """Remove lines containing dynamic code execution primitives from LLM output."""
    if not text:
        return text
    sanitized_lines = [
        line for line in text.splitlines(keepends=True)
        if not _DANGEROUS_PATTERNS.search(line)
    ]
    return "".join(sanitized_lines)


logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# Known prompt injection patterns: role overrides, delimiter abuse, instruction keywords
_INJECTION_PATTERNS = re.compile(
    r"(system\s*:|user\s*:|assistant\s*:|<\s*/?\s*(system|user|assistant|prompt|instruction)\s*>|\[INST\]|\[/INST\]|"
    r"ignore (previous|above|all) instructions?|disregard|jailbreak|you are now|act as|pretend (you are|to be)|\\n---\\n)",
    re.IGNORECASE,
)


def sanitize_user_input(text: str) -> str:
    """Sanitize user input to prevent prompt injection.

    Raises ValueError if the input matches known injection patterns.
    Returns the input wrapped in structural delimiters.
    """
    if not isinstance(text, str):
        raise ValueError("User input must be a string.")
    # Reject inputs that are excessively long (basic DoS guard)
    if len(text) > 4000:
        logger.warning("Prompt injection guard: input exceeds maximum length.")
        raise ValueError("Input is too long.")
    match = _INJECTION_PATTERNS.search(text)
    if match:
        logger.warning(
            "Prompt injection attempt detected and blocked. "
            "Matched pattern: %r at position %d.",
            match.group(),
            match.start(),
        )
        raise ValueError("Input contains disallowed content and has been blocked.")
    # Wrap in structural delimiters so the model can distinguish user data from instructions
    return f"<user_query>\n{text}\n</user_query>"


# Prompt-injection guardrail -----------------------------------------------
_INJECTION_PATTERNS = re.compile(
    r"(ignore\s+(all\s+)?(previous|prior|above)\s+instructions"
    r"|disregard\s+(all\s+)?(previous|prior|above)\s+instructions"
    r"|you\s+are\s+now\s+in\s+(developer|jailbreak|dan)\s+mode"
    r"|<\s*system\s*>"
    r"|\[\s*system\s*\]"
    r"|###\s*system"
    r"|act\s+as\s+(an?\s+)?unrestricted"
    r"|forget\s+(all\s+)?previous\s+(instructions|context)"
    r"|reveal\s+(your\s+)?(system\s+)?prompt"
    r"|print\s+(your\s+)?(system\s+)?prompt"
    r"|output\s+(your\s+)?(system\s+)?prompt)",
    re.IGNORECASE | re.DOTALL,
)


def sanitize_input(text: str, label: str = "input") -> str:
    """Raise ValueError if *text* contains prompt-injection patterns."""
    if _INJECTION_PATTERNS.search(text):
        raise ValueError(
            f"Prompt injection detected in {label}. Request blocked."
        )
    return text


# ---------------------------------------------------------------------------
# Parse .txt locally. Megaparse is the default and tries Quivr's hosted NATS,
# which fails with "nodename nor servname provided" when that host is down.
register_processor(FileExtension.txt, SimpleTxtProcessor, override=True)


# ---------------------------------------------------------------------------
# PII detection and redaction
# Zero-tolerance PII categories per policy.
# ---------------------------------------------------------------------------
_PII_PATTERNS = [
    # Social Security Number
    (re.compile(r'\b(?!000|666|9\d{2})\d{3}[- ]?(?!00)\d{2}[- ]?(?!0000)\d{4}\b'), '[REDACTED_SSN]'),
    # Year of Birth (standalone 4-digit year 1900-2099)
    (re.compile(r'\b(19|20)\d{2}\b'), '[REDACTED_YEAR_OF_BIRTH]'),
    # Email address
    (re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'), '[REDACTED_EMAIL]'),
    # Personal Phone Number (US and international formats)
    (re.compile(r'(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}\b'), '[REDACTED_PHONE]'),
    # Credit Card Number (13-19 digits, optionally separated by spaces/dashes)
    (re.compile(r'\b(?:\d[ -]?){13,19}\b'), '[REDACTED_CREDIT_CARD]'),
    # Passport Number (generic: letter(s) followed by digits)
    (re.compile(r'\b[A-Z]{1,2}\d{6,9}\b'), '[REDACTED_PASSPORT]'),
    # Driver's License Number (alphanumeric, 6-15 chars)
    (re.compile(r'\bDL[#:\s]?[A-Z0-9]{6,15}\b', re.IGNORECASE), '[REDACTED_DL]'),
    # Taxpayer Identification Number (EIN: XX-XXXXXXX)
    (re.compile(r'\b\d{2}-\d{7}\b'), '[REDACTED_TIN]'),
    # Financial Account Number (8-17 digit sequences not already matched)
    (re.compile(r'\b\d{8,17}\b'), '[REDACTED_FINANCIAL_ACCOUNT]'),
    # IP Address (IPv4)
    (re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'), '[REDACTED_IP_ADDRESS]'),
    # MAC Address
    (re.compile(r'\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b'), '[REDACTED_MAC_ADDRESS]'),
    # Vehicle Identification Number (17 alphanumeric chars)
    (re.compile(r'\b[A-HJ-NPR-Z0-9]{17}\b'), '[REDACTED_VIN]'),
    # Home Address (street address pattern)
    (re.compile(r'\b\d{1,5}\s+(?:[A-Za-z]+\s){1,4}(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl)\b', re.IGNORECASE), '[REDACTED_ADDRESS]'),
    # Fine Location (GPS coordinates)
    (re.compile(r'\b[-+]?([1-8]?\d(\.\d+)?|90(\.0+)?),\s*[-+]?(180(\.0+)?|((1[0-7]\d)|([1-9]?\d))(\.\d+)?)\b'), '[REDACTED_LOCATION]'),
    # Ethnicity keywords
    (re.compile(r'\b(ethnicity|ethnic group|race)\s*[:\-]?\s*[A-Za-z]+\b', re.IGNORECASE), '[REDACTED_ETHNICITY]'),
    # Sexual Orientation keywords
    (re.compile(r'\b(sexual orientation|sexuality)\s*[:\-]?\s*[A-Za-z]+\b', re.IGNORECASE), '[REDACTED_SEXUAL_ORIENTATION]'),
    # Medical Records keywords
    (re.compile(r'\b(diagnosis|medical record|patient id|prescription|MRN)\s*[:\-]?\s*[A-Za-z0-9 ]+\b', re.IGNORECASE), '[REDACTED_MEDICAL_RECORD]'),
    # Employee ID
    (re.compile(r'\b(employee id|emp id|employee number)\s*[:\-]?\s*[A-Za-z0-9]+\b', re.IGNORECASE), '[REDACTED_EMPLOYEE_ID]'),
    # School ID
    (re.compile(r'\b(school id|student id|student number)\s*[:\-]?\s*[A-Za-z0-9]+\b', re.IGNORECASE), '[REDACTED_SCHOOL_ID]'),
]


def redact_pii(text: str) -> str:
    """Detect and redact zero-tolerance PII categories from text."""
    for pattern, replacement in _PII_PATTERNS:
        text = pattern.sub(replacement, text)
    return text

# ChatOpenAI requires a key even when the backend is Ollama.
os.environ.setdefault("OPENAI_API_KEY", "ollama")

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_CHAT_MODEL = os.environ["OLLAMA_CHAT_MODEL"]  # Must be set to an approved model from the organization registry
OLLAMA_EMBED_MODEL = os.environ["OLLAMA_EMBED_MODEL"]  # Must be set to an approved model from the organization registry


# Leetspeak character substitution map (leet -> common alpha equivalents)
_LEET_MAP = str.maketrans({
    '0': 'o', '1': 'i', '3': 'e', '4': 'a',
    '5': 's', '6': 'g', '7': 't', '8': 'b', '@': 'a',
    '$': 's', '!': 'i', '+': 't', '|': 'i',
})

# Keywords that, when found after leet-decoding, indicate an injected prompt/command
_LEET_KEYWORDS = re.compile(
    r'\b(ignore|disregard|forget|override|bypass|jailbreak|system|prompt|'
    r'instruction|execute|eval|exec|cmd|bash|sh|powershell|python|perl|ruby|'
    r'wget|curl|chmod|sudo|rm|cat|echo|passwd|shadow|etc|bin|usr|var|tmp|'
    r'admin|root|hack|inject|payload|exploit|malware|virus|trojan|ransomware)\b',
    re.IGNORECASE,
)


def _is_leetspeak(text: str) -> bool:
    """Return True if *text* contains leetspeak-obfuscated prompt/command keywords."""
    # Only bother translating strings that contain at least one leet digit/symbol
    leet_chars = set('013456789@$!+|')
    if not any(c in leet_chars for c in text):
        return False
    decoded = text.translate(_LEET_MAP)
    return bool(_LEET_KEYWORDS.search(decoded))


def remove_leetspeak(text: str) -> str:
    """Replace leetspeak-obfuscated prompts/commands in *text* with a safe placeholder.

    The function splits the input into whitespace-delimited tokens and replaces
    any token (or contiguous run of tokens) that decodes to a known
    prompt-injection / command keyword with '<leetspeak_prompts_removed>'.
    """
    if not text:
        return text
    # Work sentence-by-sentence so we preserve normal prose
    tokens = text.split()
    result = []
    replaced = False
    for token in tokens:
        if _is_leetspeak(token):
            if not replaced:
                result.append('<leetspeak_prompts_removed>')
                replaced = True
            # else: collapse consecutive leet tokens into one placeholder
        else:
            replaced = False
            result.append(token)
    cleaned = ' '.join(result)
    # If the whole string decoded to something suspicious, replace entirely
    if _is_leetspeak(cleaned):
        return '<leetspeak_prompts_removed>'
    return cleaned


# ---------------------------------------------------------------------------
# Prompt-injection guard
# ---------------------------------------------------------------------------
_INJECTION_PATTERNS = [
    # Direct instruction overrides
    re.compile(
        r"(ignore|disregard|forget|override)\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context|rules?)",
        re.IGNORECASE,
    ),
    # Role / persona hijacking
    re.compile(
        r"(you\s+are\s+now|act\s+as|pretend\s+(to\s+be|you\s+are)|your\s+new\s+(role|persona|instructions?))",
        re.IGNORECASE,
    ),
    # System-prompt injection markers
    re.compile(r"<\s*/?\s*system\s*>", re.IGNORECASE),
    re.compile(r"\[\s*INST\s*\]", re.IGNORECASE),
    re.compile(r"###\s*(Instruction|System|Human|Assistant)", re.IGNORECASE),
    # Shell / OS commands
    re.compile(
        r"(\b(rm|del|format|shutdown|reboot|wget|curl|bash|sh|cmd|powershell|exec|eval|os\.system)\b.*[;&|`$])",
        re.IGNORECASE,
    ),
    re.compile(r"`[^`]+`", re.IGNORECASE),  # backtick command substitution
    # Leetspeak variants of "ignore" / "system"
    re.compile(r"[i!1][g9][n][o0][r][e3]", re.IGNORECASE),
    re.compile(r"[s$][y][s$][t][e3][m]", re.IGNORECASE),
]

# Minimum length of a decoded base64 chunk that we treat as suspicious
_B64_MIN_DECODED_LEN = 20
_B64_CHUNK_RE = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")


def _contains_suspicious_base64(text: str) -> bool:
    """Return True if any base64-looking chunk decodes to text that matches
    injection patterns."""
    for match in _B64_CHUNK_RE.finditer(text):
        candidate = match.group(0)
        # Pad to a valid base64 length
        padding = (4 - len(candidate) % 4) % 4
        try:
            decoded = base64.b64decode(candidate + "=" * padding).decode(
                "utf-8", errors="ignore"
            )
        except Exception:
            continue
        if len(decoded) < _B64_MIN_DECODED_LEN:
            continue
        for pattern in _INJECTION_PATTERNS:
            if pattern.search(decoded):
                return True
    return False


def _check_for_prompt_injection(text: str) -> None:
    """Raise ValueError if the text contains prompt-injection indicators."""
    for pattern in _INJECTION_PATTERNS:
        if pattern.search(text):
            raise ValueError(
                "Uploaded file contains potentially malicious content "
                f"(matched pattern: {pattern.pattern!r}). Upload rejected."
            )
    if _contains_suspicious_base64(text):
        raise ValueError(
            "Uploaded file contains base64-encoded content that matches "
            "known prompt-injection patterns. Upload rejected."
        )


# ---------------------------------------------------------------------------
# Regex patterns for zero-tolerance PII categories
_PII_PATTERNS = [
    # Social Security Number
    (re.compile(r'\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b'), '[REDACTED_SSN]'),
    # Taxpayer Identification Number (EIN format)
    (re.compile(r'\b\d{2}-\d{7}\b'), '[REDACTED_TIN]'),
    # Credit Card Number
    (re.compile(r'\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13}|3(?:0[0-5]|[68]\d)\d{11}|6(?:011|5\d{2})\d{12}|(?:2131|1800|35\d{3})\d{11})\b'), '[REDACTED_CC]'),
    # Financial Account Number (generic 8-17 digit)
    (re.compile(r'\b\d{8,17}\b'), '[REDACTED_ACCOUNT]'),
    # Passport Number (US style)
    (re.compile(r'\b[A-Z]{1,2}\d{6,9}\b'), '[REDACTED_PASSPORT]'),
    # Driver's License (common formats)
    (re.compile(r'\b[A-Z]{1,2}\d{5,8}\b'), '[REDACTED_DL]'),
    # IP Address
    (re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'), '[REDACTED_IP]'),
    # MAC Address
    (re.compile(r'\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b'), '[REDACTED_MAC]'),
    # Email
    (re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'), '[REDACTED_EMAIL]'),
    # Personal Phone Number
    (re.compile(r'\b(?:\+?1[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}\b'), '[REDACTED_PHONE]'),
    # Year of Birth (standalone 4-digit year 1900-2099)
    (re.compile(r'\b(?:born|dob|date of birth|year of birth)[^\d]{0,10}((?:19|20)\d{2})\b', re.IGNORECASE), '[REDACTED_YOB]'),
    # Vehicle Identification Number
    (re.compile(r'\b[A-HJ-NPR-Z0-9]{17}\b'), '[REDACTED_VIN]'),
    # Employee/School ID (common patterns)
    (re.compile(r'\b(?:employee|emp|school|student)\s*(?:id|#|no\.?)[:\s]*([A-Z0-9\-]{4,12})\b', re.IGNORECASE), '[REDACTED_ID]'),
]


def redact_pii(text: str) -> str:
    """Redact zero-tolerance PII categories from the given text."""
    for pattern, replacement in _PII_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


# Zero-tolerance PII masking patterns
_PII_PATTERNS = [
    # Social Security Number (SSN)
    (re.compile(r'\b(?!000|666|9\d{2})\d{3}[- ]?(?!00)\d{2}[- ]?(?!0000)\d{4}\b'), '[SSN REDACTED]'),
    # Taxpayer Identification Number (same format as SSN, covered above)
    # Credit Card Number (Visa, MC, Amex, Discover)
    (re.compile(r'\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6011)[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{2,4}\b'), '[CREDIT_CARD REDACTED]'),
    # Financial Account Number (generic 8-17 digit sequences not caught by CC)
    (re.compile(r'\b\d{8,17}\b'), '[ACCOUNT_NUMBER REDACTED]'),
    # Email address
    (re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'), '[EMAIL REDACTED]'),
    # IP Address (IPv4)
    (re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'), '[IP_ADDRESS REDACTED]'),
    # MAC Address
    (re.compile(r'\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b'), '[MAC_ADDRESS REDACTED]'),
    # Personal Phone Number (US and international formats)
    (re.compile(r'\b(?:\+?1[\s.\-]?)?(?:\(?\d{3}\)?[\s.\-]?)\d{3}[\s.\-]?\d{4}\b'), '[PHONE REDACTED]'),
    # Passport Number (generic: letter(s) followed by 6-9 digits)
    (re.compile(r'\b[A-Z]{1,2}\d{6,9}\b'), '[PASSPORT REDACTED]'),
    # Driver License Number (common US formats: letter(s)+digits or all digits 7-12)
    (re.compile(r'\b[A-Z]{1,2}\d{5,8}\b'), '[DL REDACTED]'),
    # Vehicle Identification Number (VIN: 17 alphanumeric chars)
    (re.compile(r'\b[A-HJ-NPR-Z0-9]{17}\b'), '[VIN REDACTED]'),
    # Year of Birth (4-digit year between 1900-2009 preceded by birth-related keywords)
    (re.compile(r'(?i)\b(?:born|birth(?:day|date)?|dob|year of birth)[:\s]+(?:19|20)\d{2}\b'), '[BIRTH_YEAR REDACTED]'),
    # Home Address (street address pattern)
    (re.compile(r'\b\d{1,5}\s+[A-Za-z0-9\s]{3,30}(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl)\.?\b', re.IGNORECASE), '[ADDRESS REDACTED]'),
]


def mask_pii(text: str) -> str:
    """Mask zero-tolerance PII categories before displaying content in the UI."""
    for pattern, replacement in _PII_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def ollama_llm() -> LLMEndpoint:
    # GPAI model card: see LLAMA_MODEL_CARD_URL for documentation on this model.
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
    # GPAI model card: see NOMIC_EMBED_MODEL_CARD_URL for documentation on this model.
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

    # Scan for prompt injection attempts before passing to Brain
    _check_for_prompt_injection(text)

    # Sanitize uploaded file content before indexing into Brain
    text = sanitize_content(text)

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

    # Sanitise user input: replace any leetspeak-obfuscated prompts/commands
    safe_content = remove_leetspeak(message.content)

    # Sanitize user input before passing to the LLM to prevent prompt injection
    try:
        safe_content = sanitize_user_input(message.content)
    except ValueError as exc:
        await cl.Message(content=f"Your message was blocked: {exc}").send()
        return

    # Use the ask_stream method for streaming responses
    try:
        safe_message = sanitize_input(message.content, label="user message")
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
    msg.content = msg.content + f"\n\nSources:\n{sources}"
    await msg.update()
