import base64
import re

import pytest
from langchain_core.documents import Document
from quivr_core.files.file import FileExtension
from quivr_core.processor.implementations.simple_txt_processor import (
    SimpleTxtProcessor,
    recursive_character_splitter,
)
from quivr_core.processor.splitter import SplitterConfig

# ---------------------------------------------------------------------------
# Prompt-injection / malicious-content scanner
# ---------------------------------------------------------------------------
_INJECTION_PATTERNS = [
    # Direct prompt-injection keywords
    re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.IGNORECASE),
    re.compile(r"disregard\s+(all\s+)?previous\s+instructions", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(?:a|an|the)\b", re.IGNORECASE),
    re.compile(r"act\s+as\s+(?:a|an|the)\b", re.IGNORECASE),
    re.compile(r"new\s+instructions?\s*:", re.IGNORECASE),
    re.compile(r"system\s*prompt\s*:", re.IGNORECASE),
    re.compile(r"<\s*/?\s*(?:system|user|assistant)\s*>", re.IGNORECASE),
    re.compile(r"\[\s*(?:INST|SYS|SYSTEM)\s*\]", re.IGNORECASE),
    # Shell / command-injection patterns
    re.compile(r"(?:^|\s)(?:rm|wget|curl|bash|sh|python|perl|ruby|nc|ncat|netcat)\s", re.IGNORECASE | re.MULTILINE),
    re.compile(r"`[^`]+`"),          # backtick command substitution
    re.compile(r"\$\([^)]+\)"),      # $(...) command substitution
    re.compile(r";\s*(?:rm|wget|curl|bash|sh)\b", re.IGNORECASE),
    # Leetspeak heuristic: 3+ digit-substituted alpha chars in a row
    re.compile(r"(?:[a-zA-Z0-9])*(?:[013457][a-zA-Z]|[a-zA-Z][013457]){3,}(?:[a-zA-Z0-9])*"),
]

_B64_MIN_LEN = 40  # minimum length to flag a base64 blob
_B64_RE = re.compile(r"[A-Za-z0-9+/]{" + str(_B64_MIN_LEN) + r",}={0,2}")


def _is_valid_base64(s: str) -> bool:
    """Return True if *s* decodes as valid base64 and looks like encoded data."""
    try:
        decoded = base64.b64decode(s, validate=True)
        # Treat it as suspicious only when it contains non-printable bytes
        # (i.e. it is not just a long alphanumeric word that happens to be valid b64)
        return any(b < 0x20 and b not in (0x09, 0x0A, 0x0D) for b in decoded)
    except Exception:
        return False


def scan_documents_for_malicious_content(docs: list) -> None:
    """Raise ValueError if any document contains potentially malicious content.

    Checks performed
    ----------------
    * Known prompt-injection / jailbreak phrases
    * Shell-command patterns
    * Leetspeak heuristics
    * Base64-encoded binary blobs
    """
    for doc in docs:
        content = doc.page_content

        for pattern in _INJECTION_PATTERNS:
            if pattern.search(content):
                raise ValueError(
                    f"Malicious content detected in uploaded file "
                    f"(matched pattern {pattern.pattern!r}): "
                    f"{content[:120]!r}"
                )

        for match in _B64_RE.finditer(content):
            if _is_valid_base64(match.group()):
                raise ValueError(
                    f"Potentially malicious base64-encoded content detected "
                    f"in uploaded file: {match.group()[:60]!r}"
                )


def test_recursive_character_splitter():
    doc = Document(page_content="abcdefgh", metadata={"key": "value"})

    docs = recursive_character_splitter(doc, chunk_size=2, chunk_overlap=1)

    assert [d.page_content for d in docs] == ["ab", "bc", "cd", "de", "ef", "fg", "gh"]
    assert [d.metadata for d in docs] == [doc.metadata] * len(docs)


@pytest.mark.asyncio
async def test_simple_processor(quivr_pdf, quivr_txt):
    proc = SimpleTxtProcessor(
        splitter_config=SplitterConfig(chunk_size=100, chunk_overlap=20)
    )
    assert proc.supported_extensions == [FileExtension.txt]

    with pytest.raises(ValueError):
        await proc.process_file(quivr_pdf)

    docs = await proc.process_file(quivr_txt)
    scan_documents_for_malicious_content(docs)

    assert len(docs) == 1
    assert docs[0].page_content == "This is some test data."
