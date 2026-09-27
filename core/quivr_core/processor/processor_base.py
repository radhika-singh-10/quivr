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


def sanitize_for_llm(text: str) -> str:
    """Sanitize text to prevent prompt injection attacks before passing to LLM contexts."""
    import re
    if not isinstance(text, str):
        text = str(text)
    # Remove common prompt injection patterns
    injection_patterns = [
        r"(?i)(ignore\s+(previous|above|prior|all)\s+(instructions?|prompts?|context|text))",
        r"(?i)(disregard\s+(previous|above|prior|all)\s+(instructions?|prompts?|context|text))",
        r"(?i)(forget\s+(previous|above|prior|all)\s+(instructions?|prompts?|context|text))",
        r"(?i)(you\s+are\s+now\s+(a|an)?\s*\w+)",
        r"(?i)(act\s+as\s+(a|an)?\s*\w+)",
        r"(?i)(new\s+instructions?\s*:)",
        r"(?i)(system\s*:\s*you)",
        r"(?i)(\[\s*system\s*\])",
        r"(?i)(\<\s*system\s*\>)",
        r"(?i)(override\s+(previous|all)\s+(instructions?|prompts?))",
        r"(?i)(jailbreak)",
        r"(?i)(do\s+anything\s+now)",
        r"(?i)(DAN\s+mode)",
    ]
    for pattern in injection_patterns:
        text = re.sub(pattern, "[REDACTED]", text)
    return text


R = TypeVar("R", covariant=True)

# Invisible / zero-width Unicode characters used to hide injected text
_INVISIBLE_CHARS_RE = re.compile(
    r"[\u00ad\u200b-\u200f\u202a-\u202e\u2060-\u2064\u206a-\u206f\ufeff]"
)

# Patterns that look like prompt-injection attempts
_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    # Classic role-override phrases
    re.compile(
        r"(ignore\s+(all\s+)?(previous|prior|above)\s+instructions?)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(disregard\s+(all\s+)?(previous|prior|above)\s+instructions?)",
        re.IGNORECASE,
    ),
    re.compile(r"(you\s+are\s+now\s+(?:a|an)\s+\w+)", re.IGNORECASE),
    re.compile(r"(act\s+as\s+(?:a|an)\s+\w+)", re.IGNORECASE),
    re.compile(r"(new\s+instructions?\s*:)", re.IGNORECASE),
    re.compile(r"(system\s*:\s*you\s+are)", re.IGNORECASE),
    # Shell command patterns
    re.compile(r"(\$\(|`[^`]+`|;\s*rm\s+-|\|\s*bash|\|\s*sh\b)"),
    re.compile(r"(\beval\s*\(|\bexec\s*\(|\bos\.system\s*\()"),
    # Leetspeak injection markers (e.g. 1gn0r3 pr3v10us)
    re.compile(r"(1gn[o0]r[e3]\s+[a-z0-9\s]+1nstruct)", re.IGNORECASE),
]

# Minimum length of a base64 chunk worth inspecting
_B64_MIN_LEN = 40
_B64_RE = re.compile(r"[A-Za-z0-9+/]{" + str(_B64_MIN_LEN) + r",}={0,2}")


def _decode_b64_if_injection(match: re.Match[str]) -> str:
    """Return a placeholder if the base64 blob decodes to an injection attempt."""
    candidate = match.group(0)
    try:
        decoded = base64.b64decode(candidate + "==").decode("utf-8", errors="ignore")
    except Exception:
        return candidate
    for pattern in _INJECTION_PATTERNS:
        if pattern.search(decoded):
            logger.warning(
                "Removed base64-encoded prompt injection payload from document content."
            )
            return "[REDACTED]"
    return candidate


def sanitize_content(text: str) -> str:
    """Remove or neutralise prompt-injection attempts from untrusted file content.

    Checks performed:
    * Invisible / zero-width Unicode characters
    * Known prompt-override phrases
    * Shell command patterns
    * Leetspeak injection markers
    * Base64-encoded payloads that decode to injection phrases
    """
    # 1. Strip invisible characters
    text = _INVISIBLE_CHARS_RE.sub("", text)

    # 2. Detect and redact base64-encoded injection payloads
    text = _B64_RE.sub(_decode_b64_if_injection, text)

    # 3. Flag plain-text injection patterns
    for pattern in _INJECTION_PATTERNS:
        if pattern.search(text):
            logger.warning(
                "Potential prompt injection detected in uploaded file content; "
                "offending segment redacted."
            )
            text = pattern.sub("[REDACTED]", text)

    return text


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
        try:
            qvr_version = version("quivr-core")
        except PackageNotFoundError:
            qvr_version = "dev"

        for idx, doc in enumerate(docs.chunks, start=1):
            if "original_file_name" in doc.metadata:
                safe_filename = sanitize_for_llm(doc.metadata['original_file_name'])
                safe_content = sanitize_for_llm(doc.page_content)
                doc.page_content = f"Filename: {safe_filename} Content: {safe_content}"
            doc.page_content = sanitize_content(doc.page_content)
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
