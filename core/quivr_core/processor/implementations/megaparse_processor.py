import logging
import re

import tiktoken
from langchain_core.documents import Document
from langchain_text_splitters import RecursiveCharacterTextSplitter, TextSplitter
from megaparse_sdk.client import MegaParseNATSClient
from megaparse_sdk.config import ClientNATSConfig
from megaparse_sdk.schema.document import Document as MPDocument

from quivr_core.config import MegaparseConfig
from quivr_core.files.file import QuivrFile
from quivr_core.processor.processor_base import ProcessedDocument, ProcessorBase
from quivr_core.processor.registry import FileExtension
from quivr_core.processor.splitter import SplitterConfig
import base64
import unicodedata

logger = logging.getLogger("quivr_core")


def _sanitize_content(text: str) -> str:
    """Sanitize file content to block prompt injection attempts before LLM ingestion."""
    if not isinstance(text, str):
        text = str(text)
    # Block common prompt injection patterns (case-insensitive)
    injection_patterns = [
        r"(?i)ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)",
        r"(?i)disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)",
        r"(?i)forget\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)",
        r"(?i)(you\s+are\s+now|act\s+as|pretend\s+(to\s+be|you\s+are))\s+.{0,100}",
        r"(?i)(system\s*:|<\s*system\s*>|\[\s*system\s*\])",
        r"(?i)(new\s+instructions?\s*:|override\s+instructions?)",
        r"(?i)\bdo\s+not\s+follow\s+(your\s+)?(previous\s+)?(instructions?|guidelines?|rules?)",
        r"(?i)(reveal|print|output|show|display)\s+(your\s+)?(system\s+)?(prompt|instructions?|context)",
        r"(?i)jailbreak",
        r"(?i)\bDAN\b",
    ]
    for pattern in injection_patterns:
        text = re.sub(pattern, "[REDACTED]", text)
    return text

# ---------------------------------------------------------------------------
# Prompt-injection sanitiser
# ---------------------------------------------------------------------------
_INVISIBLE_CATEGORIES = {"Cf", "Cc", "Zs", "Mn"}  # format / control / space / non-spacing

# Patterns that are strong indicators of injected instructions
_INJECTION_PATTERNS = re.compile(
    r"("
    r"ignore (all )?(previous|prior|above|earlier) instructions?"
    r"|forget (all )?(previous|prior|above|earlier) instructions?"
    r"|you are now"
    r"|act as (a |an )?"
    r"|new (role|persona|identity|instructions?)"
    r"|system prompt"
    r"|<\|.*?\|>"
    r"|\[INST\]"
    r"|\[SYS\]"
    r")",
    re.IGNORECASE,
)

# Shell / code execution patterns
_SHELL_PATTERNS = re.compile(
    r"("
    r"(^|\s)(sudo|rm\s+-rf|chmod|chown|wget|curl|bash|sh|python|perl|ruby|nc\s)\s"
    r"|`[^`]+`"
    r"|\$\([^)]+\)"
    r")",
    re.IGNORECASE | re.MULTILINE,
)

# Leetspeak substitution table (common replacements)
_LEET_TABLE = str.maketrans(
    "4831057@",
    "abeiosat",
)


def _strip_invisible(text: str) -> str:
    """Remove invisible / zero-width / control Unicode characters."""
    return "".join(
        ch
        for ch in text
        if unicodedata.category(ch) not in _INVISIBLE_CATEGORIES
        or ch in ("\n", "\r", "\t", " ")
    )


def _decode_base64_blobs(text: str) -> str:
    """Detect and decode base64 blobs; replace them with their decoded text
    (or remove them if decoding yields non-printable / binary content)."""
    # Base64 tokens of at least 20 chars (long enough to carry a hidden prompt)
    b64_re = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")

    def _replace(m: re.Match) -> str:
        candidate = m.group(0)
        # Must be a valid multiple-of-4 length after padding
        padded = candidate + "=" * (-len(candidate) % 4)
        try:
            decoded = base64.b64decode(padded).decode("utf-8", errors="strict")
            # Only substitute if the decoded text is printable ASCII / UTF-8 prose
            if decoded.isprintable():
                logger.warning(
                    "Prompt-injection guard: replaced base64 blob with decoded text."
                )
                return decoded
        except Exception:
            pass
        return candidate

    return b64_re.sub(_replace, text)


def _normalise_leetspeak(text: str) -> str:
    """Translate common leetspeak digits/symbols back to letters so that
    injection-pattern regexes can match obfuscated instructions."""
    return text.translate(_LEET_TABLE)


def sanitize_content(raw: str) -> str:
    """Apply all prompt-injection defences to *raw* text extracted from an
    uploaded file and return the cleaned string.

    Steps
    -----
    1. Strip invisible / zero-width Unicode characters.
    2. Decode and inline any base64 blobs (so hidden prompts become visible).
    3. Normalise leetspeak substitutions.
    4. Remove lines that match known injection or shell-command patterns.
    """
    text = _strip_invisible(raw)
    text = _decode_base64_blobs(text)
    # Work on a leet-normalised copy for detection, but redact from the original
    normalised = _normalise_leetspeak(text)

    clean_lines: list[str] = []
    for original_line, norm_line in zip(text.splitlines(), normalised.splitlines()):
        if _INJECTION_PATTERNS.search(norm_line):
            logger.warning(
                "Prompt-injection guard: removed line matching injection pattern: %r",
                original_line[:120],
            )
            continue
        if _SHELL_PATTERNS.search(norm_line):
            logger.warning(
                "Prompt-injection guard: removed line matching shell-command pattern: %r",
                original_line[:120],
            )
            continue
        clean_lines.append(original_line)

    return "\n".join(clean_lines)


def remove_leetspeak_prompts(text: str) -> str:
    """
    Detect and replace leetspeak-obfuscated prompts, system commands, or
    executables with the placeholder '<leetspeak_prompts_removed>'.

    Leetspeak substitutions covered:
        a -> 4 or @,  e -> 3,  i -> 1 or !,  o -> 0,  s -> 5 or $,
        t -> 7,  l -> 1,  g -> 9,  b -> 8

    The function looks for common prompt-injection / command keywords written
    in leetspeak and replaces the entire matched token.
    """
    # Map of leetspeak characters to their latin equivalents for normalisation
    leet_map = str.maketrans("4@31!057981", "aaeiiotsqbl")

    # Keywords that are suspicious when found in document content
    suspicious_keywords = [
        # prompt-injection verbs
        r"ignor[e]?",
        r"forget",
        r"disregard",
        r"override",
        r"bypass",
        r"jailbreak",
        r"prompt",
        r"instruct",
        r"system",
        r"execute",
        r"eval",
        r"exec",
        r"run",
        r"shell",
        r"cmd",
        r"bash",
        r"powershell",
        r"python",
        r"script",
        r"sudo",
        r"chmod",
        r"chown",
        r"passwd",
        r"rm\s*-rf",
        r"wget",
        r"curl",
        r"nc",
        r"netcat",
        r"nmap",
        r"exploit",
        r"payload",
        r"malware",
        r"ransomware",
        r"rootkit",
        r"backdoor",
        r"trojan",
        r"virus",
        r"worm",
        r"keylogger",
        r"spyware",
        r"adware",
        r"botnet",
        r"ddos",
        r"phishing",
        r"sql\s*injection",
        r"xss",
        r"csrf",
        r"lfi",
        r"rfi",
        r"rce",
        r"rop",
        r"heap\s*spray",
        r"buffer\s*overflow",
        r"format\s*string",
        r"use\s*after\s*free",
        r"zero\s*day",
        r"0day",
    ]

    # Build a regex that matches a word composed of leet + normal characters
    # We tokenise on word boundaries and normalise each token before checking.
    leet_token_re = re.compile(
        r"[a-zA-Z0-9@!$4317950]+",
        re.IGNORECASE,
    )

    keyword_re = re.compile(
        r"^(?:" + "|".join(suspicious_keywords) + r")$",
        re.IGNORECASE,
    )

    def _replace_if_leet(match: re.Match) -> str:
        token = match.group(0)
        normalised = token.translate(leet_map).lower()
        if keyword_re.match(normalised):
            # Only flag if the original token actually contains leet chars
            if re.search(r"[4@31!057981]", token):
                logger.warning(
                    "Leetspeak-obfuscated prompt/command detected and removed: %r",
                    token,
                )
                return "<leetspeak_prompts_removed>"
        return token

    return leet_token_re.sub(_replace_if_leet, text)

# Regex patterns that match common hidden/invisible prompt injection techniques:
# - Zero-width and invisible Unicode characters
# - Homoglyph / tag-block Unicode (U+E0000 range)
# - Runs of whitespace-coloured or font-size-zero CSS-style spans (plain text heuristic)
_HIDDEN_PROMPT_PATTERNS = re.compile(
    r"["
    r"\u00ad"          # soft hyphen
    r"\u200b-\u200f"   # zero-width space / non-joiners / LTR-RTL marks
    r"\u202a-\u202e"   # directional formatting
    r"\u2060-\u2064"   # word joiner, invisible operators
    r"\u206a-\u206f"   # deprecated formatting characters
    r"\ufeff"          # BOM / zero-width no-break space
    r"\U000e0000-\U000e007f"  # Unicode tag block (used in prompt injection)
    r"]+",
    re.UNICODE,
)


def _sanitize_hidden_prompts(text: str) -> str:
    """Replace hidden/invisible prompt injection sequences with a safe placeholder."""
    sanitized = _HIDDEN_PROMPT_PATTERNS.sub("<hidden_prompts_removed>", text)
    return sanitized


class MegaparseProcessor(ProcessorBase[MPDocument]):
    """
    Megaparse processor for PDF files.

    It can be used to parse PDF files and split them into chunks.

    It comes from the megaparse library.

    ## Installation
    ```bash
    pip install megaparse
    ```

    """

    supported_extensions = [
        FileExtension.txt,
        FileExtension.pdf,
        FileExtension.docx,
        FileExtension.doc,
        FileExtension.pptx,
        FileExtension.xls,
        FileExtension.xlsx,
        FileExtension.csv,
        FileExtension.epub,
        FileExtension.bib,
        FileExtension.odt,
        FileExtension.html,
        FileExtension.markdown,
        FileExtension.md,
        FileExtension.mdx,
    ]

    def __init__(
        self,
        splitter: TextSplitter | None = None,
        splitter_config: SplitterConfig = SplitterConfig(),
        megaparse_config: MegaparseConfig = MegaparseConfig(),
    ) -> None:
        self.enc = tiktoken.get_encoding("cl100k_base")
        self.splitter_config = splitter_config
        self.megaparse_config = megaparse_config

        if splitter:
            self.text_splitter = splitter
        else:
            self.text_splitter = RecursiveCharacterTextSplitter.from_tiktoken_encoder(
                chunk_size=splitter_config.chunk_size,
                chunk_overlap=splitter_config.chunk_overlap,
            )

    @property
    def processor_metadata(self):
        return {
            "chunk_overlap": self.splitter_config.chunk_overlap,
        }

    async def process_file_inner(
        self, file: QuivrFile
    ) -> ProcessedDocument[MPDocument | str]:
        logger.info(f"Uploading file {file.path} to MegaParse")
        async with MegaParseNATSClient(ClientNATSConfig()) as client:
            response = await client.parse_file(file=file.path)

        document = Document(
            page_content=_sanitize_hidden_prompts(str(response)),
        )

        chunks = self.text_splitter.split_documents([document])
        for chunk in chunks:
            chunk.metadata = {"chunk_size": len(self.enc.encode(chunk.page_content))}
        return ProcessedDocument(
            chunks=chunks,
            processor_cls="MegaparseProcessor",
            processor_response=response,
        )
