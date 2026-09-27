import base64
import re
from typing import Any

import aiofiles
from langchain_core.documents import Document

from quivr_core.files.file import QuivrFile
from quivr_core.processor.processor_base import ProcessedDocument, ProcessorBase
from quivr_core.processor.registry import FileExtension
from quivr_core.processor.splitter import SplitterConfig


# Patterns that indicate potential prompt injection attempts
_INJECTION_PATTERNS = [
    # Direct instruction overrides
    re.compile(r"ignore (all )?(previous|prior|above) instructions?", re.IGNORECASE),
    re.compile(r"disregard (all )?(previous|prior|above) instructions?", re.IGNORECASE),
    re.compile(r"forget (all )?(previous|prior|above) instructions?", re.IGNORECASE),
    re.compile(r"you are now", re.IGNORECASE),
    re.compile(r"new (role|persona|instructions?|task|objective)", re.IGNORECASE),
    re.compile(r"act as (a |an )?(different|new|another)?", re.IGNORECASE),
    re.compile(r"(system|assistant|user)\s*:", re.IGNORECASE),
    re.compile(r"<\s*(system|instructions?|prompt)\s*>", re.IGNORECASE),
    re.compile(r"\[\s*(system|instructions?|prompt)\s*\]", re.IGNORECASE),
    # Shell command injection
    re.compile(r"`[^`]+`"),
    re.compile(r"\$\([^)]+\)"),
    re.compile(r"\b(rm|wget|curl|bash|sh|python|exec|eval|os\.system)\s*[\.\(\s]", re.IGNORECASE),
    # Jailbreak keywords
    re.compile(r"jailbreak", re.IGNORECASE),
    re.compile(r"DAN\b"),
    re.compile(r"do anything now", re.IGNORECASE),
    re.compile(r"prompt injection", re.IGNORECASE),
]

# Leetspeak substitution map for normalization
_LEET_MAP = str.maketrans({
    "0": "o", "1": "i", "3": "e", "4": "a",
    "5": "s", "6": "g", "7": "t", "@": "a",
    "$": "s", "!": "i",
})


def _decode_base64_segments(text: str) -> list[str]:
    """Extract and decode any base64-encoded segments found in the text."""
    decoded_segments = []
    # Match base64-like strings (min length 20 to avoid false positives)
    pattern = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
    for match in pattern.finditer(text):
        candidate = match.group(0)
        try:
            # Pad if necessary
            padded = candidate + "=" * (-len(candidate) % 4)
            decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
            if decoded.isprintable() and len(decoded) > 5:
                decoded_segments.append(decoded)
        except Exception:
            pass
    return decoded_segments


def sanitize_content(content: str) -> str:
    """
    Scan content for prompt injection attempts including direct instructions,
    leetspeak obfuscation, base64-encoded payloads, and shell commands.
    Raises ValueError if malicious content is detected.
    Returns the original content if it passes all checks.
    """
    # Check raw content against injection patterns
    for pattern in _INJECTION_PATTERNS:
        if pattern.search(content):
            raise ValueError(
                f"Potential prompt injection detected in uploaded file content "
                f"(matched pattern: {pattern.pattern!r}). File rejected."
            )

    # Check leetspeak-normalized content
    normalized = content.translate(_LEET_MAP)
    for pattern in _INJECTION_PATTERNS:
        if pattern.search(normalized):
            raise ValueError(
                "Potential prompt injection detected in uploaded file content "
                "(leetspeak obfuscation). File rejected."
            )

    # Check base64-decoded segments
    for decoded_segment in _decode_base64_segments(content):
        for pattern in _INJECTION_PATTERNS:
            if pattern.search(decoded_segment):
                raise ValueError(
                    "Potential prompt injection detected in uploaded file content "
                    "(base64-encoded payload). File rejected."
                )
        # Also check leetspeak in decoded segment
        normalized_decoded = decoded_segment.translate(_LEET_MAP)
        for pattern in _INJECTION_PATTERNS:
            if pattern.search(normalized_decoded):
                raise ValueError(
                    "Potential prompt injection detected in uploaded file content "
                    "(base64-encoded leetspeak payload). File rejected."
                )

    return content


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

            # Scan for prompt injection before passing to the LLM pipeline
            sanitize_content(content)

            doc = Document(page_content=content)

        docs = recursive_character_splitter(
            doc, self.splitter_config.chunk_size, self.splitter_config.chunk_overlap
        )

        return ProcessedDocument(
            chunks=docs, processor_cls="SimpleTxtProcessor", processor_response=content
        )
