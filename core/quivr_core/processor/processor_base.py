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

# Invisible/control Unicode ranges that are commonly used to hide text
_INVISIBLE_CHARS_RE = re.compile(
    r"[\u00ad\u200b-\u200f\u202a-\u202e\u2060-\u2064\u206a-\u206f\ufeff\u2028\u2029]"
)

# Patterns indicative of prompt-injection attempts
_INJECTION_PATTERNS = [
    # Direct instruction overrides
    re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?", re.IGNORECASE),
    re.compile(r"disregard\s+(all\s+)?(previous|prior|above)\s+instructions?", re.IGNORECASE),
    re.compile(r"forget\s+(all\s+)?(previous|prior|above)\s+instructions?", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(a\s+)?(?:an?\s+)?\w+", re.IGNORECASE),
    re.compile(r"act\s+as\s+(a\s+|an\s+)?\w+", re.IGNORECASE),
    re.compile(r"new\s+instructions?\s*:", re.IGNORECASE),
    re.compile(r"system\s*:\s*you", re.IGNORECASE),
    re.compile(r"<\s*system\s*>", re.IGNORECASE),
    re.compile(r"\[\s*system\s*\]", re.IGNORECASE),
    re.compile(r"###\s*instruction", re.IGNORECASE),
    # Shell command patterns
    re.compile(r"(?:^|\s)(?:sudo|bash|sh|cmd|powershell|exec|eval|system)\s+", re.IGNORECASE | re.MULTILINE),
    re.compile(r"`[^`]+`"),  # backtick command substitution
    re.compile(r"\$\([^)]+\)"),  # $(...) command substitution
    # Leetspeak variants of "ignore" / "system"
    re.compile(r"[i!1][g9][n][o0][r][e3]", re.IGNORECASE),
    re.compile(r"[s5][y][s5][t7][e3][m]", re.IGNORECASE),
]


def _decode_base64_segments(text: str) -> str:
    """Return any successfully decoded base64 segments found in text, concatenated."""
    decoded_parts = []
    # Look for base64-like tokens (min length 20 to reduce false positives)
    for token in re.findall(r"[A-Za-z0-9+/]{20,}={0,2}", text):
        try:
            decoded = base64.b64decode(token + "==").decode("utf-8", errors="ignore")
            if decoded.isprintable() and len(decoded) > 8:
                decoded_parts.append(decoded)
        except Exception:
            pass
    return " ".join(decoded_parts)


def sanitize_content(text: str) -> str:
    """
    Scan document text for prompt-injection indicators and raise a ValueError
    if any are detected. Also strips invisible Unicode characters.
    """
    # Strip invisible/control characters
    cleaned = _INVISIBLE_CHARS_RE.sub("", text)

    # Check the cleaned text and any base64-decoded segments
    candidates = [cleaned, _decode_base64_segments(cleaned)]

    for candidate in candidates:
        if not candidate:
            continue
        for pattern in _INJECTION_PATTERNS:
            if pattern.search(candidate):
                raise ValueError(
                    f"Potential prompt injection detected in document content "
                    f"(matched pattern: {pattern.pattern!r}). File rejected."
                )

    return cleaned


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
        # Scan each chunk for prompt-injection content before further processing
        for _doc in docs.chunks:
            _doc.page_content = sanitize_content(_doc.page_content)
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
