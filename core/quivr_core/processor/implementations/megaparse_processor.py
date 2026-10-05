import logging
import re
import unicodedata

import time
import uuid

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

logger = logging.getLogger("quivr_core")

# Patterns that indicate prompt injection attempts
_INJECTION_PATTERNS = [
    # Direct instruction overrides
    re.compile(
        r"(ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context))",
        re.IGNORECASE,
    ),
    re.compile(
        r"(disregard\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context))",
        re.IGNORECASE,
    ),
    re.compile(
        r"(forget\s+(everything|all|what)\s*(you\s*(were|have|know))?)",
        re.IGNORECASE,
    ),
    re.compile(r"(you\s+are\s+now\s+(a\s+)?(?!an?\s+assistant))", re.IGNORECASE),
    re.compile(r"(act\s+as\s+(if\s+you\s+(are|were)|a\s+))", re.IGNORECASE),
    re.compile(r"(new\s+(role|persona|instructions?|prompt|task)\s*:)", re.IGNORECASE),
    re.compile(r"(system\s*:\s*(you\s+are|your\s+role))", re.IGNORECASE),
    re.compile(r"(<\s*system\s*>|\[\s*system\s*\])", re.IGNORECASE),
    re.compile(r"(###\s*(instruction|system|prompt|override))", re.IGNORECASE),
    # Shell command injection
    re.compile(r"(\$\(|`[^`]+`|;\s*(rm|wget|curl|bash|sh|python|perl|ruby|nc|ncat)\b)"),
    re.compile(r"\b(rm\s+-rf|chmod\s+777|sudo\s+|passwd\s+|/etc/shadow|/etc/passwd)\b"),
    re.compile(r"(\|\s*(bash|sh|python|perl|ruby|nc)\b)"),
    # Leetspeak patterns for common injection phrases
    re.compile(
        r"(1gn[o0]r[e3]\s+[a4]ll|[i1]gn[o0]r[e3]\s+pr[e3]v[i1][o0]us)",
        re.IGNORECASE,
    ),
    re.compile(r"(d[i1][s5]r[e3]g[a4]rd|[o0]v[e3]rr[i1]d[e3])", re.IGNORECASE),
]

# Regex to detect base64-encoded strings of meaningful length
_BASE64_RE = re.compile(r"(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")

# Injection keywords to look for inside decoded base64 payloads
_DECODED_INJECTION_KEYWORDS = re.compile(
    r"(ignore|disregard|forget|system|override|instruction|prompt|act as|you are now)",
    re.IGNORECASE,
)


def _contains_injection(text: str) -> bool:
    """Return True if *text* appears to contain a prompt-injection attempt."""
    for pattern in _INJECTION_PATTERNS:
        if pattern.search(text):
            return True
    # Check base64-encoded payloads
    for match in _BASE64_RE.finditer(text):
        candidate = match.group(0)
        # Only bother decoding if the candidate is long enough to carry a payload
        if len(candidate) < 32:
            continue
        try:
            decoded = base64.b64decode(candidate + "==").decode("utf-8", errors="ignore")
            if _DECODED_INJECTION_KEYWORDS.search(decoded):
                return True
        except Exception:
            pass
    return False


def _sanitize_content(text: str) -> str:
    """Raise ValueError if *text* contains a prompt-injection attempt."""
    if _contains_injection(text):
        raise ValueError(
            "Uploaded file content contains potential prompt-injection patterns "
            "and has been rejected for safety reasons."
        )
    return text


def _ai_app_sec_023_sanitize_mcp_output(text: str) -> str:
    """Validate and sanitize output returned by an MCP server tool.

    Applies hidden-prompt removal (already done by the caller) and then
    checks for prompt-injection patterns.  Raises ValueError if any
    injection attempt is detected.
    """
    if not isinstance(text, str):
        raise TypeError(
            "MCP server tool output must be a string; "
            f"got {type(text).__name__!r} instead."
        )
    # Re-apply hidden-prompt removal defensively in case this helper is
    # called directly without a prior _remove_hidden_prompts pass.
    cleaned = _remove_hidden_prompts(text)
    return _sanitize_content(cleaned)

# Invisible / zero-width Unicode codepoints commonly used for hidden prompt injection
_INVISIBLE_CHARS_RE = re.compile(
    r"["
    r"\u00ad"          # soft hyphen
    r"\u034f"          # combining grapheme joiner
    r"\u061c"          # arabic letter mark
    r"\u115f\u1160"    # hangul fillers
    r"\u17b4\u17b5"    # khmer vowel inherent
    r"\u180b-\u180e"   # mongolian free variation selectors / vowel separator
    r"\u200b-\u200f"   # zero-width space/non-joiner/joiner/LRM/RLM
    r"\u202a-\u202e"   # directional formatting
    r"\u2060-\u2064"   # word joiner, invisible operators
    r"\u2066-\u206f"   # additional directional / invisible formatting
    r"\ufeff"          # zero-width no-break space / BOM
    r"\ufff0-\uffff"   # specials
    r"]",
    re.UNICODE,
)

# Patterns that look like injected system/hidden instructions embedded in content
_HIDDEN_PROMPT_PATTERNS = [
    # HTML/CSS tricks: white text, font-size 0, display none, visibility hidden
    re.compile(
        r"<[^>]*(?:color\s*:\s*(?:white|#fff{1,3}|rgba?\([^)]*,\s*0\s*\))"
        r"|font-size\s*:\s*0"
        r"|display\s*:\s*none"
        r"|visibility\s*:\s*hidden"
        r"|opacity\s*:\s*0)[^>]*>.*?</[^>]+>",
        re.IGNORECASE | re.DOTALL,
    ),
    # Markdown / plain-text hidden instruction blocks
    re.compile(
        r"<!--.*?-->",
        re.DOTALL,
    ),
    # Sequences of many zero-width / invisible characters (≥2 consecutive)
    re.compile(r"(?:[\u200b-\u200f\u2060-\u2064\ufeff]){2,}"),
]


def _remove_hidden_prompts(text: str) -> str:
    """Replace hidden/invisible prompt injection patterns with a safe placeholder."""
    replacement = "<hidden_prompts_removed>"

    # 1. Strip lone invisible Unicode control characters
    cleaned = _INVISIBLE_CHARS_RE.sub("", text)

    # 2. Apply each structural hidden-prompt pattern
    for pattern in _HIDDEN_PROMPT_PATTERNS:
        cleaned = pattern.sub(replacement, cleaned)

    # 3. Normalise Unicode to NFC to surface any remaining composed trickery
    cleaned = unicodedata.normalize("NFC", cleaned)

    return cleaned


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
        _ai_app_sec_035_request_id = str(uuid.uuid4())
        _ai_app_sec_035_input_size = file.path.stat().st_size if file.path.exists() else -1
        logger.info(
            "MegaParse request",
            extra={
                "operation": "parse_file",
                "request_id": _ai_app_sec_035_request_id,
                "input_size_bytes": _ai_app_sec_035_input_size,
            },
        )
        _ai_app_sec_035_start = time.monotonic()
        _ai_app_sec_035_success = False
        try:
            async with MegaParseNATSClient(ClientNATSConfig()) as client:
                response = await client.parse_file(file=file.path)
            _ai_app_sec_035_success = True
        finally:
            _ai_app_sec_035_duration = time.monotonic() - _ai_app_sec_035_start
            _ai_app_sec_035_output_len = len(str(response)) if _ai_app_sec_035_success else -1
            logger.info(
                "MegaParse response",
                extra={
                    "operation": "parse_file",
                    "request_id": _ai_app_sec_035_request_id,
                    "duration_seconds": round(_ai_app_sec_035_duration, 4),
                    "output_length_chars": _ai_app_sec_035_output_len,
                    "success": _ai_app_sec_035_success,
                },
            )

        raw_content = str(response)
        safe_content = _remove_hidden_prompts(raw_content)
        sanitized_content = _sanitize_content(safe_content)
        document = Document(
            page_content=sanitized_content,
        )

        chunks = self.text_splitter.split_documents([document])
        for chunk in chunks:
            chunk.metadata = {"chunk_size": len(self.enc.encode(chunk.page_content))}
        return ProcessedDocument(
            chunks=chunks,
            processor_cls="MegaparseProcessor",
            processor_response=response,
        )
