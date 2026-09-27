import base64
import logging
import re
import unicodedata
from typing import Any, List, Type, TypeVar

import tiktoken
from langchain_community.document_loaders import (
    BibtexLoader,
    CSVLoader,
    Docx2txtLoader,
    NotebookLoader,
    PythonLoader,
    UnstructuredEPubLoader,
    UnstructuredExcelLoader,
    UnstructuredHTMLLoader,
    UnstructuredMarkdownLoader,
    UnstructuredODTLoader,
    UnstructuredPDFLoader,
    UnstructuredPowerPointLoader,
)
from langchain_community.document_loaders.base import BaseLoader
from langchain_community.document_loaders.text import TextLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter, TextSplitter

from quivr_core.files.file import FileExtension, QuivrFile
from quivr_core.processor.processor_base import ProcessedDocument, ProcessorBase
from quivr_core.processor.splitter import SplitterConfig

import re

logger = logging.getLogger("quivr_core")


def _sanitize_doc(doc):
    """Sanitize a LangChain Document's page_content against prompt injection.

    Strips or neutralises patterns commonly used to hijack LLM instructions
    (e.g. "Ignore previous instructions", role-override markers, hidden
    directives, etc.) before the content is consumed by an LLM or agent.
    """
    _INJECTION_PATTERNS = [
        # Instruction-override attempts
        r"(?i)ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context|rules?|constraints?)",
        r"(?i)disregard\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context|rules?|constraints?)",
        r"(?i)forget\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context|rules?|constraints?)",
        r"(?i)override\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context|rules?|constraints?)",
        # Role / persona hijacking
        r"(?i)you\s+are\s+now\s+(a\s+|an\s+)?(?:new\s+)?(?:ai|assistant|bot|model|gpt|llm|system)",
        r"(?i)act\s+as\s+(a\s+|an\s+)?(?:new\s+)?(?:ai|assistant|bot|model|gpt|llm|system)",
        r"(?i)pretend\s+(to\s+be|you\s+are)\s+(a\s+|an\s+)?(?:ai|assistant|bot|model|gpt|llm|system)",
        # Jailbreak / DAN-style markers
        r"(?i)\bDAN\b",
        r"(?i)jailbreak",
        r"(?i)do\s+anything\s+now",
        # Hidden / encoded instruction markers
        r"(?i)<\s*/?\s*(system|instruction|prompt|context|user|assistant)\s*>",
        r"(?i)\[\s*(system|instruction|prompt|context|user|assistant)\s*\]",
        r"(?i)###\s*(system|instruction|prompt|context|user|assistant)",
        # Exfiltration / SSRF probes embedded in content
        r"(?i)send\s+(all\s+)?(this|the|my|your)\s+(data|context|conversation|history|prompt)\s+to",
        r"(?i)reveal\s+(your\s+)?(system\s+)?prompt",
        r"(?i)print\s+(your\s+)?(system\s+)?prompt",
        r"(?i)output\s+(your\s+)?(system\s+)?prompt",
        r"(?i)repeat\s+(your\s+)?(system\s+)?prompt",
        r"(?i)what\s+(are|were)\s+your\s+(original\s+)?instructions",
    ]
    content = doc.page_content
    for pattern in _INJECTION_PATTERNS:
        content = re.sub(pattern, "[REDACTED]", content)
    doc.page_content = content
    return doc

P = TypeVar("P", bound=BaseLoader)

# ---------------------------------------------------------------------------
# Prompt-injection sanitisation helpers
# ---------------------------------------------------------------------------

# Invisible / zero-width Unicode codepoints commonly used to hide text
_INVISIBLE_CHARS_RE = re.compile(
    r"[\u00ad\u200b-\u200f\u202a-\u202e\u2060-\u2064\u206a-\u206f\ufeff\u2028\u2029]"
)

# Patterns that look like injected LLM instructions
_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    # Direct instruction overrides
    re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?", re.IGNORECASE),
    re.compile(r"disregard\s+(all\s+)?(previous|prior|above)\s+instructions?", re.IGNORECASE),
    re.compile(r"forget\s+(all\s+)?(previous|prior|above)\s+instructions?", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(?:a|an|the)\b", re.IGNORECASE),
    re.compile(r"act\s+as\s+(?:a|an|the)\b", re.IGNORECASE),
    re.compile(r"new\s+instructions?\s*:", re.IGNORECASE),
    re.compile(r"system\s*:\s*you", re.IGNORECASE),
    re.compile(r"<\s*/?\s*(?:system|user|assistant)\s*>", re.IGNORECASE),
    re.compile(r"\[\s*(?:INST|SYS|SYSTEM|PROMPT)\s*\]", re.IGNORECASE),
    # Shell / code execution attempts
    re.compile(r"(?:^|\s)(?:sudo|bash|sh|cmd|powershell|exec|eval|os\.system|subprocess)\s*[\(\s]", re.IGNORECASE | re.MULTILINE),
    re.compile(r"`[^`]{1,200}`"),  # backtick command substitution
    re.compile(r"\$\([^)]{1,200}\)"),  # $(...) command substitution
]

# Leetspeak substitution table (expand as needed)
_LEET_TABLE = str.maketrans("013456789", "oieashgbq")

# Minimum length of a base64 chunk worth decoding and inspecting
_B64_MIN_LEN = 20
_B64_RE = re.compile(r"[A-Za-z0-9+/]{" + str(_B64_MIN_LEN) + r",}={0,2}")


def _contains_injection(text: str) -> bool:
    """Return True if *text* matches any known injection pattern."""
    for pattern in _INJECTION_PATTERNS:
        if pattern.search(text):
            return True
    return False


def _check_base64_payloads(text: str) -> bool:
    """Decode base64 blobs found in *text* and check them for injections."""
    for match in _B64_RE.finditer(text):
        try:
            decoded = base64.b64decode(match.group() + "==").decode("utf-8", errors="ignore")
            if _contains_injection(decoded):
                return True
        except Exception:
            pass
    return False


def _check_leetspeak(text: str) -> bool:
    """Translate common leetspeak substitutions and re-check for injections."""
    normalised = text.translate(_LEET_TABLE)
    return _contains_injection(normalised)


def sanitize_document_content(content: str) -> str:
    """
    Scan *content* for prompt-injection attempts and return a sanitised copy.

    Raises ``ValueError`` if a definitive injection attempt is detected so
    that the calling processor can reject the document entirely.
    Invisible / zero-width characters are always stripped silently.
    """
    # 1. Strip invisible / zero-width characters
    cleaned = _INVISIBLE_CHARS_RE.sub("", content)

    # 2. Normalise Unicode (catches homoglyph attacks)
    cleaned = unicodedata.normalize("NFKC", cleaned)

    # 3. Direct pattern match
    if _contains_injection(cleaned):
        raise ValueError(
            "Prompt injection attempt detected in document content (direct pattern)."
        )

    # 4. Base64-encoded payload check
    if _check_base64_payloads(cleaned):
        raise ValueError(
            "Prompt injection attempt detected in document content (base64 payload)."
        )

    # 5. Leetspeak check
    if _check_leetspeak(cleaned):
        raise ValueError(
            "Prompt injection attempt detected in document content (leetspeak pattern)."
        )

    return cleaned


class ProcessorInit(ProcessorBase):
    def __init__(self, *args, **loader_kwargs) -> None:
        pass


# FIXME(@aminediro):
# dynamically creates Processor classes. Maybe redo this for finer control over instanciation
# processor classes are opaque as we don't know what params they would have -> not easy to have lsp completion
def _build_processor(
    cls_name: str, load_cls: Type[P], cls_extensions: List[FileExtension | str]
) -> Type[ProcessorInit]:
    enc = tiktoken.get_encoding("cl100k_base")

    class _Processor(ProcessorBase):
        supported_extensions = cls_extensions

        def __init__(
            self,
            splitter: TextSplitter | None = None,
            splitter_config: SplitterConfig = SplitterConfig(),
            **loader_kwargs: dict[str, Any],
        ) -> None:
            self.loader_cls = load_cls
            self.loader_kwargs = loader_kwargs

            self.splitter_config = splitter_config

            if splitter:
                self.text_splitter = splitter
            else:
                self.text_splitter = (
                    RecursiveCharacterTextSplitter.from_tiktoken_encoder(
                        chunk_size=splitter_config.chunk_size,
                        chunk_overlap=splitter_config.chunk_overlap,
                    )
                )

        @property
        def processor_metadata(self) -> dict[str, Any]:
            return {
                "processor_cls": self.loader_cls.__name__,
                "splitter": self.splitter_config.model_dump(),
            }

        async def process_file_inner(self, file: QuivrFile) -> ProcessedDocument[None]:
            if hasattr(self.loader_cls, "__init__"):
                # NOTE: mypy can't correctly type this as BaseLoader doesn't have a constructor method
                loader = self.loader_cls(file_path=str(file.path), **self.loader_kwargs)  # type: ignore
            else:
                loader = self.loader_cls()

            documents = await loader.aload()

            # Sanitise every document's content before splitting to prevent
            # prompt-injection attacks carried inside uploaded files.
            sanitised_documents = []
            for _doc in documents:
                try:
                    _doc.page_content = sanitize_document_content(_doc.page_content)
                    sanitised_documents.append(_doc)
                except ValueError as _exc:
                    logger.warning(
                        "Document chunk rejected due to prompt injection: %s", _exc
                    )
            documents = sanitised_documents

            docs = self.text_splitter.split_documents(documents)

            for doc in docs:
                # TODO: This metadata info should be typed
                doc.metadata = {"chunk_size": len(enc.encode(doc.page_content))}

            return ProcessedDocument(
                chunks=docs, processor_cls=cls_name, processor_response=None
            )

    return type(cls_name, (ProcessorInit,), dict(_Processor.__dict__))


CSVProcessor = _build_processor("CSVProcessor", CSVLoader, [FileExtension.csv])
TikTokenTxtProcessor = _build_processor(
    "TikTokenTxtProcessor", TextLoader, [FileExtension.txt]
)
DOCXProcessor = _build_processor(
    "DOCXProcessor", Docx2txtLoader, [FileExtension.docx, FileExtension.doc]
)
XLSXProcessor = _build_processor(
    "XLSXProcessor", UnstructuredExcelLoader, [FileExtension.xlsx, FileExtension.xls]
)
PPTProcessor = _build_processor(
    "PPTProcessor", UnstructuredPowerPointLoader, [FileExtension.pptx]
)
MarkdownProcessor = _build_processor(
    "MarkdownProcessor",
    UnstructuredMarkdownLoader,
    [FileExtension.md, FileExtension.mdx, FileExtension.markdown],
)
EpubProcessor = _build_processor(
    "EpubProcessor", UnstructuredEPubLoader, [FileExtension.epub]
)
BibTexProcessor = _build_processor("BibTexProcessor", BibtexLoader, [FileExtension.bib])
ODTProcessor = _build_processor(
    "ODTProcessor", UnstructuredODTLoader, [FileExtension.odt]
)
HTMLProcessor = _build_processor(
    "HTMLProcessor", UnstructuredHTMLLoader, [FileExtension.html]
)
PythonProcessor = _build_processor("PythonProcessor", PythonLoader, [FileExtension.py])
NotebookProcessor = _build_processor(
    "NotebookProcessor", NotebookLoader, [FileExtension.ipynb]
)
UnstructuredPDFProcessor = _build_processor(
    "UnstructuredPDFProcessor", UnstructuredPDFLoader, [FileExtension.pdf]
)
