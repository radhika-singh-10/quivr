from flask import Flask, render_template, request, jsonify, session
import openai
import base64
import os
import re
import requests
from dotenv import load_dotenv
from quivr_core import Brain
from quivr_core.rag.entities.config import RetrievalConfig
from tempfile import NamedTemporaryFile
from werkzeug.utils import secure_filename
from asyncio import to_thread
import asyncio
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
llm_logger = logging.getLogger("llm.interactions")


# Model card / technical documentation references for GPAI integrations used in this module.
# whisper-1 and tts-1: https://openai.com/research/
# quivr_core Brain/RAG: https://github.com/QuivrHQ/quivr (see project documentation)
MODEL_CARD_URL_OPENAI = "https://openai.com/research/"  # whisper-1, tts-1
MODEL_CARD_URL_QUIVR = "https://github.com/QuivrHQ/quivr"  # Brain / RAG via quivr_core

UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"txt"}

# Prompt injection patterns to detect and block
_INJECTION_PATTERNS = [
    r"(?i)ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)",
    r"(?i)disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)",
    r"(?i)forget\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)",
    r"(?i)you\s+are\s+now\s+(a\s+)?(?!assistant)",
    r"(?i)act\s+as\s+(a\s+)?(?!assistant)",
    r"(?i)pretend\s+(you\s+are|to\s+be)",
    r"(?i)new\s+instructions?\s*:",
    r"(?i)system\s*:\s*you\s+(are|must|should|will)",
    r"(?i)<\s*/?\s*(system|user|assistant)\s*>",
    r"(?i)\[\s*(system|user|assistant)\s*\]",
    r"(?i)###\s*(instruction|system|prompt)",
    r"(?i)jailbreak",
    r"(?i)do\s+anything\s+now",
    r"(?i)dan\s+mode",
]

import re as _re


def sanitize_prompt_injection(text: str, source: str = "input") -> str:
    """Detect and block prompt injection attempts in user-supplied text.

    Raises ValueError if injection is detected; otherwise returns the original text.
    """
    if not isinstance(text, str):
        return text
    for pattern in _INJECTION_PATTERNS:
        if _re.search(pattern, text):
            raise ValueError(
                f"Prompt injection attempt detected in {source}. Request blocked."
            )
    return text


def sanitize_file_contents(filepath: str) -> str:
    """Read a file and check its contents for prompt injection before use.

    Returns the filepath unchanged if safe; raises ValueError if injection detected.
    """
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
            contents = fh.read()
        sanitize_prompt_injection(contents, source=f"file '{filepath}'")
    except ValueError:
        raise
    except Exception:
        # If we cannot read the file for inspection, allow it through
        # (binary files, encoding issues, etc.) — adjust policy as needed
        pass
    return filepath

import re

# Patterns that indicate dynamic code execution primitives
_DANGEROUS_PATTERNS = re.compile(
    r"\b(eval|exec|execfile|compile|__import__|subprocess|os\.system|"
    r"os\.popen|os\.spawn|commands\.getoutput|popen|shell\s*=\s*True|"
    r"Runtime\.exec|ProcessBuilder|child_process|require\s*\(\s*['\"]child_process['\"]\s*\)|"
    r"bash\s+-c|sh\s+-c|cmd\.exe|powershell)\b",
    re.IGNORECASE,
)


def sanitize_llm_output(text: str) -> str:
    """Remove lines from LLM output that contain dynamic code execution primitives."""
    if not text:
        return text
    sanitized_lines = [
        line for line in text.splitlines()
        if not _DANGEROUS_PATTERNS.search(line)
    ]
    return "\n".join(sanitized_lines)

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.secret_key = "secret"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["CACHE_TYPE"] = "SimpleCache"  # In-memory cache for development
app.config["CACHE_DEFAULT_TIMEOUT"] = 60 * 60  # 1 hour cache timeout
load_dotenv()

openai.api_key = os.getenv("OPENAI_API_KEY")

# Model names driven by environment variables; set to approved models in deployment
STT_MODEL = os.getenv("APPROVED_STT_MODEL", "whisper-large-v3")
TTS_MODEL = os.getenv("APPROVED_TTS_MODEL", "tts-hd")
LLM_MODEL = os.getenv("APPROVED_LLM_MODEL", "gpt-4o")

# In-memory document store keyed by session_id
doc_store: dict = {}
brains = {}

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# Known prompt-injection patterns to detect and block
_INJECTION_PATTERNS = re.compile(
    r"(ignore (previous|above|all) instructions"
    r"|system\s*:"
    r"|assistant\s*:"
    r"|<\s*/?system\s*>"
    r"|<\s*/?prompt\s*>"
    r"|\[INST\]"
    r"|###\s*(instruction|system|prompt)"
    r"|you are now"
    r"|disregard (all|any|previous)"
    r"|forget (everything|all|your instructions))",
    re.IGNORECASE,
)


def sanitize_transcript(text: str) -> str:
    """Validate and sanitize a user-supplied transcript before sending to the LLM.

    Raises ValueError if the text contains prompt-injection patterns.
    Returns the text wrapped in structural XML delimiters.
    """
    if not isinstance(text, str):
        raise ValueError("Transcript must be a string.")

    # Strip leading/trailing whitespace
    text = text.strip()

    # Reject empty transcripts
    if not text:
        raise ValueError("Transcript is empty.")

    # Detect and block known injection patterns
    match = _INJECTION_PATTERNS.search(text)
    if match:
        logger.warning(
            "Prompt injection attempt detected and blocked. "
            "Matched pattern: %r in input: %r",
            match.group(0),
            text[:200],
        )
        raise ValueError("Input contains disallowed instruction-like patterns.")

    # Wrap user data in structural delimiters so the model distinguishes
    # instructions (system context) from user-supplied data.
    safe_text = f"<user_query>\n{text}\n</user_query>"
    return safe_text


def remove_leetspeak_prompts(text: str) -> str:
    """
    Detect and replace leetspeak-obfuscated prompts, system commands, or
    executables with a safe placeholder.

    Leetspeak substitutions covered:
      4/@ -> a,  3 -> e,  1/! -> i,  0 -> o,  5/$ -> s,  7 -> t,
      |/1 -> l,  ph -> f,  ck -> k  (and common variants)

    After normalising the text we look for patterns that indicate:
      - Prompt-injection phrases (ignore previous instructions, etc.)
      - Shell / system commands  (rm, sudo, chmod, exec, eval, …)
      - Script / executable references (.sh, .exe, .bat, .py, …)
    """
    import re

    def _normalise(t: str) -> str:
        """Return a lowercase, leet-decoded version of *t* for matching."""
        t = t.lower()
        substitutions = [
            (r'ph', 'f'),
            (r'ck', 'k'),
            (r'[4@]', 'a'),
            (r'3',   'e'),
            (r'[1!|]', 'i'),
            (r'0',   'o'),
            (r'[5$]', 's'),
            (r'7',   't'),
            (r'\+',  't'),
        ]
        for pattern, repl in substitutions:
            t = re.sub(pattern, repl, t)
        return t

    # Patterns that indicate malicious / injected content (matched on
    # the *normalised* text; positions are then mapped back to the
    # original via token-level replacement).
    MALICIOUS_PATTERNS = [
        # Prompt-injection phrases
        r'ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)',
        r'disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)',
        r'forget\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)',
        r'you\s+are\s+now\s+(a\s+)?',
        r'act\s+as\s+(a\s+|an\s+)?',
        r'new\s+instructions?\s*:',
        r'system\s*:\s*you',
        r'<\s*system\s*>',
        r'\[\s*system\s*\]',
        # Shell / OS commands
        r'\brm\s+-[rf]',
        r'\bsudo\b',
        r'\bchmod\b',
        r'\bchown\b',
        r'\bmkdir\b',
        r'\bwget\b',
        r'\bcurl\b.*http',
        r'\beval\s*\(',
        r'\bexec\s*\(',
        r'\bos\.system\s*\(',
        r'\bsubprocess\b',
        r'\bpopen\s*\(',
        r'\bpasswd\b',
        r'/etc/shadow',
        r'/etc/passwd',
        # Executable / script references
        r'\S+\.(sh|exe|bat|cmd|ps1|vbs|py|rb|pl)\b',
        r'\bpowershell\b',
        r'\bbash\b',
        r'\b/bin/(sh|bash|zsh|dash)\b',
    ]

    PLACEHOLDER = '<leetspeak_prompts_removed>'

    # We work sentence-by-sentence (split on newlines and sentence
    # boundaries) so that a single malicious sentence does not wipe
    # the entire response.
    segments = re.split(r'(\n+|(?<=[.!?])\s+)', text)
    cleaned = []
    for segment in segments:
        normalised = _normalise(segment)
        flagged = False
        for pat in MALICIOUS_PATTERNS:
            if re.search(pat, normalised):
                flagged = True
                break
        cleaned.append(PLACEHOLDER if flagged else segment)
    return ''.join(cleaned)


@app.route("/")
def index():
    return render_template("index.html")


def run_in_event_loop(func, *args, **kwargs):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    if asyncio.iscoroutinefunction(func):
        result = loop.run_until_complete(func(*args, **kwargs))
    else:
        result = func(*args, **kwargs)
    loop.close()
    return result


def sanitize_hidden_prompts(text: str) -> str:
    """Remove hidden/invisible prompt injection patterns from RAG-retrieved text."""
    import re

    # Replace zero-width and invisible Unicode characters
    invisible_chars = [
        "\u200b",  # zero-width space
        "\u200c",  # zero-width non-joiner
        "\u200d",  # zero-width joiner
        "\u200e",  # left-to-right mark
        "\u200f",  # right-to-left mark
        "\u202a",  # left-to-right embedding
        "\u202b",  # right-to-left embedding
        "\u202c",  # pop directional formatting
        "\u202d",  # left-to-right override
        "\u202e",  # right-to-left override
        "\u2060",  # word joiner
        "\u2061",  # function application
        "\u2062",  # invisible times
        "\u2063",  # invisible separator
        "\u2064",  # invisible plus
        "\ufeff",  # zero-width no-break space / BOM
        "\u00ad",  # soft hyphen
        "\u034f",  # combining grapheme joiner
        "\u115f",  # hangul choseong filler
        "\u1160",  # hangul jungseong filler
        "\u3164",  # hangul filler
        "\uffa0",  # halfwidth hangul filler
    ]
    for ch in invisible_chars:
        if ch in text:
            text = text.replace(ch, "<hidden_prompts_removed>")

    # Remove HTML/CSS-based hidden text patterns (e.g. color:white, font-size:0)
    hidden_html_patterns = [
        # style with color white / visibility hidden / display none / font-size 0
        r'<[^>]*style\s*=\s*["\'][^"\'>]*(color\s*:\s*white|color\s*:\s*#fff(?:fff)?'
        r'|visibility\s*:\s*hidden|display\s*:\s*none|font-size\s*:\s*0'
        r'|opacity\s*:\s*0)[^"\'>]*["\'][^>]*>.*?</[^>]+>',
        # font tag with size=1 or size="1"
        r'<font[^>]*size\s*=\s*["\']?1["\']?[^>]*>.*?</font>',
        # span/div with white color
        r'<(?:span|div|p)[^>]*color\s*:\s*(?:white|#fff(?:fff)?)[^>]*>.*?</(?:span|div|p)>',
    ]
    for pattern in hidden_html_patterns:
        text = re.sub(pattern, "<hidden_prompts_removed>", text,
                      flags=re.IGNORECASE | re.DOTALL)

    # Remove markdown-style hidden content (e.g. <!-- comment --> HTML comments)
    text = re.sub(r'<!--.*?-->', "<hidden_prompts_removed>", text,
                  flags=re.DOTALL)

    # Remove runs of whitespace-only "text" that may carry invisible instructions
    # (lines that contain only whitespace characters beyond a normal blank line)
    text = re.sub(r'([ \t]{20,})', "<hidden_prompts_removed>", text)

    return text


# Zero-tolerance PII redaction patterns
_PII_PATTERNS = [
    # Social Security Number
    (re.compile(r'\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b'), '[REDACTED_SSN]'),
    # Email address
    (re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'), '[REDACTED_EMAIL]'),
    # Personal phone number (US and international formats)
    (re.compile(r'(?:\+?1[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}\b'), '[REDACTED_PHONE]'),
    # Credit card number (13-19 digits, optionally separated by spaces or dashes)
    (re.compile(r'\b(?:\d[ -]?){13,19}\b'), '[REDACTED_CC]'),
    # IP address (IPv4)
    (re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'), '[REDACTED_IP]'),
    # MAC address
    (re.compile(r'\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b'), '[REDACTED_MAC]'),
    # Passport number (generic: letter(s) followed by 6-9 digits)
    (re.compile(r'\b[A-Z]{1,2}\d{6,9}\b'), '[REDACTED_PASSPORT]'),
    # US Driver license (common formats: letter + 7-8 digits or all digits 7-9)
    (re.compile(r'\b[A-Z]\d{7,8}\b'), '[REDACTED_DL]'),
    # Taxpayer Identification Number / EIN (XX-XXXXXXX)
    (re.compile(r'\b\d{2}-\d{7}\b'), '[REDACTED_TIN]'),
    # Financial account number (8-17 consecutive digits not already matched)
    (re.compile(r'\b\d{8,17}\b'), '[REDACTED_ACCOUNT]'),
    # Vehicle Identification Number (17 alphanumeric chars)
    (re.compile(r'\b[A-HJ-NPR-Z0-9]{17}\b'), '[REDACTED_VIN]'),
    # AWS access key
    (re.compile(r'\b(AKIA|ASIA|AROA|AIDA|ANPA|ANVA|APKA)[A-Z0-9]{16}\b'), '[REDACTED_AWS_KEY]'),
    # AWS secret key (40 base64 chars following common patterns)
    (re.compile(r'(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])'), '[REDACTED_SECRET_KEY]'),
    # Generic bearer / auth tokens
    (re.compile(r'\b(?:bearer|token|api[_-]?key|auth)[\s:=]+[A-Za-z0-9\-._~+/]+=*\b', re.IGNORECASE), '[REDACTED_AUTH_TOKEN]'),
    # GCP / Azure service account / JWT tokens (three base64url segments)
    (re.compile(r'\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b'), '[REDACTED_JWT]'),
]


def redact_pii(text: str) -> str:
    """Redact zero-tolerance PII and secrets from text before sending to LLM."""
    for pattern, replacement in _PII_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


# Patterns that indicate potential prompt injection in uploaded text files
import re

_INVISIBLE_CHARS = re.compile(r'[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff\u00ad]')

_SHELL_COMMANDS = re.compile(
    r'(?i)\b(rm\s+-rf|curl\s+|wget\s+|bash\s+|sh\s+|exec\s*\(|eval\s*\(|os\.system|subprocess|__import__)'
)

_INJECTION_PHRASES = re.compile(
    r'(?i)(ignore\s+(all\s+)?(previous|prior|above)\s+instructions'
    r'|disregard\s+(all\s+)?(previous|prior|above)\s+instructions'
    r'|you\s+are\s+now\s+(?:a\s+)?(?:an?\s+)?(?:evil|malicious|unrestricted|jailbroken|DAN)'
    r'|act\s+as\s+(?:if\s+you\s+(?:are|were)\s+)?(?:a\s+)?(?:an?\s+)?(?:evil|malicious|unrestricted|jailbroken|DAN)'
    r'|forget\s+(all\s+)?(previous|prior|above)\s+instructions'
    r'|new\s+instructions?\s*:'
    r'|system\s*:\s*you\s+are'
    r'|\[INST\]|\[/INST\]|<\|im_start\|>|<\|im_end\|>'
    r')'
)

_LEETSPEAK = re.compile(
    r'(?i)\b(1gn0r3|d1sr3g4rd|f0rg3t|3v1l|m4l1c10us|j41lbr0k3n)\b'
)


def _is_base64_prompt(text: str) -> bool:
    """Detect base64-encoded strings that decode to prompt-injection content."""
    # Find candidate base64 blobs (length >= 20, valid base64 alphabet)
    candidates = re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', text)
    for candidate in candidates:
        try:
            decoded = base64.b64decode(candidate + '==').decode('utf-8', errors='ignore')
            if _INJECTION_PHRASES.search(decoded) or _SHELL_COMMANDS.search(decoded):
                return True
        except Exception:
            pass
    return False


def scan_for_prompt_injection(filepath: str) -> str | None:
    """
    Scan a text file for prompt-injection indicators.
    Returns a human-readable reason string if suspicious content is found,
    or None if the file appears clean.
    """
    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as fh:
            content = fh.read()
    except OSError as exc:
        return f"Could not read uploaded file: {exc}"

    if _INVISIBLE_CHARS.search(content):
        return "File contains invisible or zero-width characters that may hide prompt injections."

    if _INJECTION_PHRASES.search(content):
        return "File contains phrases commonly used in prompt-injection attacks."

    if _SHELL_COMMANDS.search(content):
        return "File contains shell commands or code-execution patterns."

    if _LEETSPEAK.search(content):
        return "File contains leetspeak patterns associated with prompt-injection attempts."

    if _is_base64_prompt(content):
        return "File contains base64-encoded content that decodes to prompt-injection patterns."

    return None


@app.route("/upload", methods=["POST"])
async def upload_file():
    if "file" not in request.files:
        return "No file part", 400

    file = request.files["file"]

    if file.filename == "":
        return "No selected file", 400
    if not (file and file.filename and allowed_file(file.filename)):
        return "Invalid file type", 400

    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    file.save(filepath)

    print(f"File uploaded and saved at: {filepath}")

    # --- Prompt-injection scan ---
    injection_reason = scan_for_prompt_injection(filepath)
    if injection_reason:
        os.remove(filepath)  # Delete the suspicious file immediately
        return jsonify({"error": f"File rejected: {injection_reason}"}), 400
    # --- End scan ---

    print("Creating brain instance...")

    # Read document text directly; no external embedding model needed
    with open(filepath, "r", encoding="utf-8", errors="replace") as doc_f:
        doc_text = doc_f.read()

    # Store document text in memory
    session_id = session.sid if hasattr(session, "sid") else os.urandom(16).hex()
    session["session_id"] = session_id
    doc_store[session_id] = doc_text
    print(f"Document stored for session ID: {session_id}")

    return jsonify({"message": "Brain created successfully"})


@app.route("/ask", methods=["POST"])
async def ask():
    if "audio_data" not in request.files:
        return "Missing audio data", 400

    # Retrieve the brain instance from the cache using the session ID
    session_id = session.get("session_id")
    if not session_id:
        return "Session ID not found. Upload a file first.", 400

    doc_text = doc_store.get(session_id)
    if not doc_text:
        return "Document not found. Upload a file first.", 400

    print("Document loaded from store.")

    print("Speech to text...")
    audio_file = request.files["audio_data"]
    transcript = transcribe_audio_file(audio_file)
    print("Transcript result: ", transcript)

    print("Getting response...")
    def _ask_llm(question: str, context: str) -> str:
        messages = [
            {"role": "system", "content": "You are a helpful assistant. Answer the user's question using only the provided document context."},
            {"role": "user", "content": f"Document context:\n{context}\n\nQuestion: {question}"},
        ]
        resp = openai.chat.completions.create(model=LLM_MODEL, messages=messages)
        return resp.choices[0].message.content or ""

    answer = await to_thread(_ask_llm, transcript, doc_text)

    class _Resp:
        def __init__(self, a): self.answer = a
    quivr_response = _Resp(answer)

    print("Text to speech...")
    sanitized_answer = sanitize_llm_output(quivr_response.answer)
    audio_base64 = synthesize_speech(sanitized_answer)

    print("Done")
    return jsonify({"audio_base64": audio_base64})


def transcribe_audio_file(audio_file):
    with NamedTemporaryFile(suffix=".webm", delete=False) as temp_audio_file:
        audio_file.save(temp_audio_file)
        temp_audio_file_path = temp_audio_file.name

    try:
        with open(temp_audio_file_path, "rb") as f:
            transcript_response = openai.audio.transcriptions.create(
                model=STT_MODEL, file=f
            )
        transcript = sanitize_llm_output(transcript_response.text)
    finally:
        os.unlink(temp_audio_file_path)

    return transcript


def synthesize_speech(text):
    llm_logger.info(
        "LLM call: openai.audio.speech.create | input: {model: tts-1, voice: nova, text: %s}",
        text,
    )
    speech_response = openai.audio.speech.create(
        model="tts-1", voice="nova", input=text
    )
    audio_content = speech_response.content
    llm_logger.info(
        "LLM response: openai.audio.speech.create | output: audio content of %d bytes",
        len(audio_content),
    )
    audio_base64 = base64.b64encode(audio_content).decode("utf-8")
    return audio_base64


if __name__ == "__main__":
    app.run(debug=True)
