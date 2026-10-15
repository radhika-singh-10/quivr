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
_SHELL_CMD_RE = re.compile(
    r"(?i)(\b(rm|wget|curl|chmod|chown|sudo|bash|sh|python|perl|ruby|nc|ncat|netcat)\s)"
    r"|(\|\s*\w+)|(;\s*\w+)"
)
_HIDDEN_PROMPT_RE = re.compile(
    r"(?i)(ignore (previous|all|above|prior)|disregard (previous|all|above|prior)"
    r"|you are now|act as|pretend (you are|to be)|system prompt|<\|im_start\|>"
    r"|<\|im_end\|>|\[INST\]|\[/INST\])"
)
_LEETSPEAK_RE = re.compile(r"(?:[a-zA-Z][0-9@$!]{2,}[a-zA-Z]|[0-9@$!]{3,})")  # heuristic


def _is_base64_chunk(token: str) -> bool:
    """Return True if *token* looks like a non-trivial base64-encoded payload."""
    if len(token) < 20:
        return False
    if not re.fullmatch(r"[A-Za-z0-9+/]+=*", token):
        return False
    try:
        decoded = base64.b64decode(token).decode("utf-8", errors="replace")
        # If the decoded text contains printable non-trivial content treat it as suspicious
        printable_ratio = sum(32 <= ord(c) < 127 for c in decoded) / max(len(decoded), 1)
        return printable_ratio > 0.7
    except Exception:
        return False


def _ai_app_sec_032_sanitize_leetspeak(text: str) -> tuple[str, bool]:
    """Replace leetspeak-obfuscated content with a safe placeholder.

    Returns a tuple of (sanitized_text, was_modified).
    """
    sanitized, count = _LEETSPEAK_RE.subn("<leetspeak_prompts_removed>", text)
    return sanitized, count > 0


# Detects invisible / hidden-text tricks: zero-width chars, HTML color/font tricks,
# Unicode tag-block characters, and runs of whitespace-only "words".
_ai_app_sec_040_HIDDEN_TEXT_RE = re.compile(
    r"(?:"
    r"[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff\U000e0000-\U000e007f]"
    r"|color\s*:\s*(?:white|#fff(?:fff)?|rgba?\([^)]*,\s*0\))"
    r"|font-size\s*:\s*(?:0|[01]px)"
    r")",
    re.IGNORECASE,
)


def _ai_app_sec_040_has_hidden_text(text: str) -> bool:
    """Return True if *text* contains invisible/hidden-text injection markers."""
    if _ai_app_sec_040_HIDDEN_TEXT_RE.search(text):
        return True
    # Detect suspiciously long runs of whitespace-only content (padding trick)
    if re.search(r"[ \t]{80,}", text):
        return True
    return False


def scan_for_malicious_content(text: str) -> list[str]:
    """Scan *text* for prompt-injection patterns and return a list of findings.

    Returns an empty list when the content is considered safe.
    """
    findings: list[str] = []

    if _HIDDEN_PROMPT_RE.search(text):
        findings.append("hidden_prompt_injection")

    if _SHELL_CMD_RE.search(text):
        findings.append("shell_command")

    if _LEETSPEAK_RE.search(text):
        findings.append("leetspeak_obfuscation")

    if _ai_app_sec_040_has_hidden_text(text):
        findings.append("hidden_text_injection")

    for token in text.split():
        if _is_base64_chunk(token):
            findings.append("base64_encoded_content")
            break

    return findings


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

    # Security: scan every document's content for malicious / injected material
    # before it would be passed to an LLM or stored downstream.
    for doc in docs:
        findings = scan_for_malicious_content(doc.page_content)
        assert findings == [], (
            f"Malicious content detected in uploaded file: {findings}\n"
            f"Content snippet: {doc.page_content[:200]!r}"
        )

    assert len(docs) == 1
    assert docs[0].page_content == "This is some test data."
