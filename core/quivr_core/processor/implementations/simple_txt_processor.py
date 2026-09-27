import base64
import re
from typing import Any

import aiofiles
from langchain_core.documents import Document

from quivr_core.files.file import QuivrFile
from quivr_core.processor.processor_base import ProcessedDocument, ProcessorBase
from quivr_core.processor.registry import FileExtension
from quivr_core.processor.splitter import SplitterConfig


# ---------------------------------------------------------------------------
# Prompt-injection sanitisation
# ---------------------------------------------------------------------------

# Patterns that indicate an attempt to hijack the LLM via the uploaded file.
_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    # Direct instruction overrides
    re.compile(
        r"(ignore|disregard|forget|override)\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context|rules?)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(you\s+are\s+now|act\s+as|pretend\s+(to\s+be|you\s+are)|your\s+new\s+(role|persona|instructions?))",
        re.IGNORECASE,
    ),
    re.compile(
        r"(system\s*prompt|new\s+instructions?|updated\s+instructions?|hidden\s+instructions?)",
        re.IGNORECASE,
    ),
    # Shell / code execution attempts
    re.compile(
        r"(\$\(|`[^`]+`|\bexec\s*\(|\beval\s*\(|\bos\.system\s*\(|\bsubprocess\b)",
        re.IGNORECASE,
    ),
    re.compile(r"(;\s*rm\s+-|&&\s*curl\s+|\|\s*bash|\|\s*sh\b)", re.IGNORECASE),
    # Leetspeak variants of "ignore" / "system"
    re.compile(r"[i!1][g9][n][o0][r][e3]", re.IGNORECASE),
    re.compile(r"[s$][y][s$][t7][e3][m]", re.IGNORECASE),
]

# Minimum length of a token that we attempt to decode as base64.
_B64_MIN_LEN = 20
_B64_RE = re.compile(r"[A-Za-z0-9+/]{" + str(_B64_MIN_LEN) + r",}={0,2}")


def _contains_injection(text: str) -> bool:
    """Return True if *text* matches any known prompt-injection pattern."""
    for pattern in _INJECTION_PATTERNS:
        if pattern.search(text):
            return True
    return False


def _check_base64_blobs(text: str) -> None:
    """Raise ValueError if any base64 blob in *text* decodes to injected content."""
    for match in _B64_RE.finditer(text):
        candidate = match.group(0)
        # Pad to a valid base64 length.
        padding = (4 - len(candidate) % 4) % 4
        try:
            decoded = base64.b64decode(candidate + "=" * padding).decode(
                "utf-8", errors="ignore"
            )
        except Exception:
            continue
        if _contains_injection(decoded):
            raise ValueError(
                "Uploaded file contains a base64-encoded prompt-injection payload."
            )


def sanitize_content(content: str) -> str:
    """
    Scan *content* for prompt-injection attempts and raise ``ValueError`` if
    any are detected.  Returns the original content unchanged when clean.

    Checks performed
    ----------------
    * Direct instruction-override phrases
    * Shell-command injection patterns
    * Leetspeak obfuscation of common injection keywords
    * Base64-encoded payloads that decode to any of the above
    """
    if _contains_injection(content):
        raise ValueError(
            "Uploaded file contains a potential prompt-injection payload "
            "and was rejected for safety reasons."
        )
    _check_base64_blobs(content)
    return content


# ---------------------------------------------------------------------------

def recursive_character_splitter(
    doc: Document, chunk_size: int, chunk_overlap: int
) -> list[Document]:
    assert chunk_overlap < chunk_size, "chunk_overlap is greater than chunk_size"

    if len(doc.page_content) <= chunk_size:
        return [doc]

    chunk = Document(page_content=doc.page_content[:chunk_size], metadata=doc.metadata)
    remaining = Document(
        page_content=doc.page_content[chunk_size - chunk_overlap :],
        metadata=doc.metadata,
    )

    return [chunk] + recursive_character_splitter(remaining, chunk_size, chunk_overlap)


class SimpleTxtProcessor(ProcessorBase):
    """
    SimpleTxtProcessor is a class that implements the ProcessorBase interface.
    It is used to process the files with the Simple Txt parser.
    """

    supported_extensions = [FileExtension.txt]

    def __init__(
        self, splitter_config: SplitterConfig = SplitterConfig(), **kwargs
    ) -> None:
        super().__init__(**kwargs)
        self.splitter_config = splitter_config

    @property
    def processor_metadata(self) -> dict[str, Any]:
        return {
            "processor_cls": "SimpleTxtProcessor",
            "splitter": self.splitter_config.model_dump(),
        }

    async def process_file_inner(self, file: QuivrFile) -> ProcessedDocument[str]:
        async with aiofiles.open(file.path, mode="r") as f:
            content = await f.read()

        sanitized_content = sanitize_content(content)
        doc = Document(page_content=sanitized_content)

        docs = recursive_character_splitter(
            doc, self.splitter_config.chunk_size, self.splitter_config.chunk_overlap
        )

        return ProcessedDocument(
            chunks=docs, processor_cls="SimpleTxtProcessor", processor_response=sanitized_content
        )
