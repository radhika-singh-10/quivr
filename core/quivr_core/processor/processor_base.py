import base64
import logging
import re
from abc import ABC, abstractmethod
from importlib.metadata import PackageNotFoundError, version
from typing import Any, Generic, List, TypeVar

from attr import dataclass
from langchain_core.documents import Document

from quivr_core.files.file import FileExtension, QuivrFile
from quivr_core.language.utils import detect_language

logger = logging.getLogger("quivr_core")

# ---------------------------------------------------------------------------
# Prompt-injection sanitization helpers (policy ai_app_sec_040)
# ---------------------------------------------------------------------------

# Invisible / zero-width Unicode characters commonly used to hide injections
_ai_app_sec_040_INVISIBLE_CHARS = (
    "\u200b\u200c\u200d\u200e\u200f"
    "\u202a\u202b\u202c\u202d\u202e"
    "\u2060\u2061\u2062\u2063\u2064"
    "\ufeff"
)

# Patterns that indicate prompt-injection attempts
_ai_app_sec_040_INJECTION_PATTERNS: list[re.Pattern] = [
    # Classic instruction-override phrases
    re.compile(
        r"(ignore|disregard|forget|override)\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context|rules?)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(you\s+are\s+now|act\s+as|pretend\s+(you\s+are|to\s+be)|your\s+new\s+(role|persona|instructions?))",
        re.IGNORECASE,
    ),
    re.compile(
        r"(system\s*:\s*|<\s*system\s*>|\[\s*system\s*\])",
        re.IGNORECASE,
    ),
    # Shell command injection
    re.compile(
        r"(\$\(|`[^`]*`|;\s*(rm|curl|wget|bash|sh|python|perl|ruby|nc|ncat|netcat)\b)",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(eval|exec|os\.system|subprocess\.(call|run|Popen))\s*\(",
        re.IGNORECASE,
    ),
]

# Minimum length of a base64 block worth inspecting
_ai_app_sec_040_B64_MIN_LEN = 40
_ai_app_sec_040_B64_RE = re.compile(
    r"(?:[A-Za-z0-9+/]{4}){" + str(_ai_app_sec_040_B64_MIN_LEN // 4) + r",}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"
)


def _ai_app_sec_040_decode_b64_safe(token: str) -> str:
    """Return the decoded string if token is valid base64, else empty string."""
    try:
        # Pad if necessary
        padded = token + "=" * (-len(token) % 4)
        decoded = base64.b64decode(padded).decode("utf-8", errors="replace")
        return decoded
    except Exception:
        return ""


def _ai_app_sec_040_contains_injection(text: str) -> bool:
    """Return True if *text* matches any known injection pattern."""
    for pattern in _ai_app_sec_040_INJECTION_PATTERNS:
        if pattern.search(text):
            return True
    return False


def _ai_app_sec_040_sanitize_content(text: str) -> str:
    """
    Sanitize *text* against prompt-injection attacks before it is forwarded
    to an LLM.  The function:

    1. Strips invisible / zero-width Unicode characters.
    2. Detects and neutralises base64-encoded payloads that contain injection
       patterns by replacing the encoded block with a placeholder.
    3. Removes or neutralises explicit injection phrases and shell commands.

    The original text structure is preserved as much as possible; only
    confirmed-malicious fragments are replaced with ``[REDACTED]``.
    """
    if not text:
        return text

    # 1. Remove invisible characters
    for ch in _ai_app_sec_040_INVISIBLE_CHARS:
        text = text.replace(ch, "")

    # 2. Inspect base64 blobs – replace those that decode to injection content
    def _replace_b64(match: re.Match) -> str:
        token = match.group(0)
        decoded = _ai_app_sec_040_decode_b64_safe(token)
        if decoded and _ai_app_sec_040_contains_injection(decoded):
            logger.warning(
                "Prompt injection detected in base64-encoded content (len=%d); redacting.",
                len(token),
            )
            return "[REDACTED]"
        return token

    text = _ai_app_sec_040_B64_RE.sub(_replace_b64, text)

    # 3. Neutralise plain-text injection patterns
    for pattern in _ai_app_sec_040_INJECTION_PATTERNS:
        if pattern.search(text):
            logger.warning(
                "Prompt injection pattern '%s' detected in document content; redacting match.",
                pattern.pattern[:60],
            )
            text = pattern.sub("[REDACTED]", text)

    return text


# ---------------------------------------------------------------------------

R = TypeVar("R", covariant=True)


@dataclass
class ProcessedDocument(Generic[R]):
    chunks: List[Document]
    processor_cls: str
    processor_response: R


# TODO: processors should be cached somewhere ?
# The processor should be cached by processor type
# The cache should use a single
class ProcessorBase(ABC, Generic[R]):
    supported_extensions: list[FileExtension | str]

    def check_supported(self, file: QuivrFile) -> None:
        if file.file_extension not in self.supported_extensions:
            raise ValueError(f"can't process a file of type {file.file_extension}")

    @property
    @abstractmethod
    def processor_metadata(self) -> dict[str, Any]:
        raise NotImplementedError

    async def process_file(self, file: QuivrFile) -> ProcessedDocument[R]:
        logger.debug(f"Processing file {file}")
        self.check_supported(file)
        docs = await self.process_file_inner(file)
        # Sanitize every chunk against prompt-injection before further processing
        for _doc in docs.chunks:
            _doc.page_content = _ai_app_sec_040_sanitize_content(_doc.page_content)
        try:
            qvr_version = version("quivr-core")
        except PackageNotFoundError:
            qvr_version = "dev"

        for idx, doc in enumerate(docs.chunks, start=1):
            if "original_file_name" in doc.metadata:
                doc.page_content = f"Filename: {doc.metadata['original_file_name']} Content: {doc.page_content}"
            doc.page_content = doc.page_content.replace("\u0000", "")
            doc.page_content = doc.page_content.encode("utf-8", "replace").decode(
                "utf-8"
            )
            doc.metadata = {
                "chunk_index": idx,
                "quivr_core_version": qvr_version,
                "language": detect_language(
                    text=doc.page_content.replace("\\n", " ").replace("\n", " "),
                    low_memory=True,
                ).value,
                **file.metadata,
                **doc.metadata,
                **self.processor_metadata,
            }
        return docs

    @abstractmethod
    async def process_file_inner(self, file: QuivrFile) -> ProcessedDocument[R]:
        raise NotImplementedError
