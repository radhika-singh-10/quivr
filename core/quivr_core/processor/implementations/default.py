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

_ai_app_sec_070_patterns: list[tuple[re.Pattern[str], str]] = [
    # instruction_override
    (re.compile(r'ignore\s+previous\s+instructions', re.IGNORECASE), '<prompt_injection_removed: instruction_override>'),
    (re.compile(r'forget\s+everything\s+above', re.IGNORECASE), '<prompt_injection_removed: instruction_override>'),
    # role_hijack
    (re.compile(r'you\s+are\s+now\s+DAN', re.IGNORECASE), '<prompt_injection_removed: role_hijack>'),
    (re.compile(r'act\s+as\s+unrestricted', re.IGNORECASE), '<prompt_injection_removed: role_hijack>'),
    # delimiter_escape - fake </system> or </prompt> tags and injected separators
    (re.compile(r'</?\s*system\s*>', re.IGNORECASE), '<prompt_injection_removed: delimiter_escape>'),
    (re.compile(r'</?\s*prompt\s*>', re.IGNORECASE), '<prompt_injection_removed: delimiter_escape>'),
    (re.compile(r'</?\s*instructions?\s*>', re.IGNORECASE), '<prompt_injection_removed: delimiter_escape>'),
    # fake_system_message
    (re.compile(r'\[\s*system\s*\]\s*:', re.IGNORECASE), '<prompt_injection_removed: fake_system_message>'),
    (re.compile(r'\[\s*tool\s*\]\s*:', re.IGNORECASE), '<prompt_injection_removed: fake_system_message>'),
    # exfiltration_attempt
    (re.compile(r'!\[.*?\]\(https?://[^)]*\)', re.IGNORECASE), '<prompt_injection_removed: exfiltration_attempt>'),
    (re.compile(r'send\s+(this|the)\s+(data|prompt|system\s+prompt|context)\s+to\s+https?://', re.IGNORECASE), '<prompt_injection_removed: exfiltration_attempt>'),
    (re.compile(r'leak\s+(the\s+)?system\s+prompt', re.IGNORECASE), '<prompt_injection_removed: exfiltration_attempt>'),
    # jailbreak_attempt
    (re.compile(r'\bDAN\b', re.IGNORECASE), '<prompt_injection_removed: jailbreak_attempt>'),
    (re.compile(r'developer\s+mode', re.IGNORECASE), '<prompt_injection_removed: jailbreak_attempt>'),
    # hidden_text - zero-width characters
    (re.compile(r'[\u200b\u200c\u200d\u2060\ufeff]'), '<prompt_injection_removed: hidden_text>'),
    # HTML comments
    (re.compile(r'<!--.*?-->', re.DOTALL), '<prompt_injection_removed: hidden_text>'),
    # context_poisoning
    (re.compile(r'(context\s+poisoning|multi[- ]turn\s+manipulation)', re.IGNORECASE), '<prompt_injection_removed: context_poisoning>'),
    # command_injection - shell execution patterns
    (re.compile(r'(?:^|\s)(?:os\.system|subprocess\.(?:call|run|Popen)|eval|exec)\s*\(', re.MULTILINE), '<prompt_injection_removed: command_injection>'),
    # encoded_payload - base64-like blobs (long alphanum+/= strings)
    (re.compile(r'(?:[A-Za-z0-9+/]{40,}={0,2})'), '<prompt_injection_removed: encoded_payload>'),
]


def _ai_app_sec_070_sanitize(text: str) -> str:
    """Neutralize prompt injection patterns in document content before LLM ingestion."""
    for pattern, marker in _ai_app_sec_070_patterns:
        text = pattern.sub(marker, text)
    return text

# ---------------------------------------------------------------------------
# Prompt-injection detection helpers
# ---------------------------------------------------------------------------

# Patterns that indicate an attempt to hijack the LLM via document content
_ai_app_sec_040_patterns = [
    # Direct instruction-override phrases
    re.compile(
        r"(ignore|disregard|forget|override)\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context|rules?)",
        re.IGNORECASE,
    ),
    # "You are now …" / "Act as …" persona hijacking
    re.compile(
        r"(you\s+are\s+now|act\s+as|pretend\s+(to\s+be|you\s+are)|roleplay\s+as|your\s+new\s+role\s+is)",
        re.IGNORECASE,
    ),
    # System / assistant / user role injection markers
    re.compile(
        r"(<\s*/?\s*(system|assistant|user|human|ai)\s*>|\[\s*(system|assistant|user|human|ai)\s*\])",
        re.IGNORECASE,
    ),
    # Shell command injection
    re.compile(
        r"(\$\(|`[^`]*`|\beval\s*\(|\bexec\s*\(|\bos\.system\s*\(|\bsubprocess\.)",
        re.IGNORECASE,
    ),
    # Prompt-delimiter smuggling
    re.compile(r"(###\s*(instruction|system|prompt)|---\s*(instruction|system|prompt))", re.IGNORECASE),
]

# Invisible / zero-width Unicode categories that are used to hide text
_ai_app_sec_040_invisible_categories = {"Cf", "Cc", "Zs", "Zl", "Zp"}
_ai_app_sec_040_invisible_exceptions = {" ", "\t", "\n", "\r"}

# Minimum length of a base64 blob worth decoding and inspecting
_ai_app_sec_040_b64_min_len = 40
_ai_app_sec_040_b64_re = re.compile(r"[A-Za-z0-9+/]{" + str(_ai_app_sec_040_b64_min_len) + r",}={0,2}")

# Leetspeak substitution table (maps leet chars → plain ASCII)
_ai_app_sec_040_leet_table = str.maketrans(
    "013456789@$!",
    "oieasgbpqgas",
)


def _ai_app_sec_040_has_invisible_text(text: str) -> bool:
    """Return True if *text* contains invisible / zero-width Unicode characters."""
    for ch in text:
        if ch in _ai_app_sec_040_invisible_exceptions:
            continue
        cat = unicodedata.category(ch)
        if cat in _ai_app_sec_040_invisible_categories:
            return True
    return False


def _ai_app_sec_040_has_b64_prompt(text: str) -> bool:
    """Return True if any base64 blob in *text* decodes to a known injection phrase."""
    for match in _ai_app_sec_040_b64_re.finditer(text):
        blob = match.group(0)
        # Pad to a valid length
        padded = blob + "=" * (-len(blob) % 4)
        try:
            decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
        except Exception:
            continue
        for pat in _ai_app_sec_040_patterns:
            if pat.search(decoded):
                return True
    return False


def _ai_app_sec_040_has_leet_prompt(text: str) -> bool:
    """Return True if the de-leetspoken version of *text* matches an injection pattern."""
    normalized = text.translate(_ai_app_sec_040_leet_table)
    if normalized == text:
        return False  # no leet chars present – skip to avoid false positives
    for pat in _ai_app_sec_040_patterns:
        if pat.search(normalized):
            return True
    return False


def _ai_app_sec_040_scan_for_prompt_injection(content: str, source: str = "") -> None:
    """Raise *ValueError* when *content* contains a suspected prompt-injection payload.

    Checks performed:
    1. Direct pattern matching (instruction overrides, persona hijacking, shell commands).
    2. Invisible / zero-width Unicode characters.
    3. Base64-encoded payloads that decode to injection phrases.
    4. Leetspeak-obfuscated injection phrases.
    """
    label = f" in '{source}'" if source else ""

    # 1. Direct pattern scan
    for pat in _ai_app_sec_040_patterns:
        if pat.search(content):
            raise ValueError(
                f"Potential prompt-injection detected{label}: content matches pattern '{pat.pattern}'"
            )

    # 2. Invisible text
    if _ai_app_sec_040_has_invisible_text(content):
        raise ValueError(
            f"Potential prompt-injection detected{label}: invisible/zero-width Unicode characters found"
        )

    # 3. Base64-encoded payloads
    if _ai_app_sec_040_has_b64_prompt(content):
        raise ValueError(
            f"Potential prompt-injection detected{label}: base64-encoded injection payload found"
        )

    # 4. Leetspeak obfuscation
    if _ai_app_sec_040_has_leet_prompt(content):
        raise ValueError(
            f"Potential prompt-injection detected{label}: leetspeak-obfuscated injection payload found"
        )

P = TypeVar("P", bound=BaseLoader)


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

            # Scan every loaded document for prompt-injection payloads before
            # splitting and passing content to the LLM.
            for _doc in documents:
                _source = _doc.metadata.get("source", str(file.path))
                _ai_app_sec_040_scan_for_prompt_injection(_doc.page_content, source=_source)

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
