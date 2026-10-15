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

logger = logging.getLogger("quivr_core")

# ---------------------------------------------------------------------------
# Prompt-injection guardrail
# ---------------------------------------------------------------------------
_INJECTION_PATTERNS_2 = [
    re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?", re.IGNORECASE),
    re.compile(r"disregard\s+(all\s+)?(previous|prior|above)\s+instructions?", re.IGNORECASE),
    re.compile(r"forget\s+(all\s+)?(previous|prior|above)\s+instructions?", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(?:a|an|the)\b", re.IGNORECASE),
    re.compile(r"act\s+as\s+(?:a|an|the)\b", re.IGNORECASE),
    re.compile(r"pretend\s+(you\s+are|to\s+be)\b", re.IGNORECASE),
    re.compile(r"<\s*system\s*>", re.IGNORECASE),
    re.compile(r"\[\s*system\s*\]", re.IGNORECASE),
    re.compile(r"###\s*instruction", re.IGNORECASE),
    re.compile(r"jailbreak", re.IGNORECASE),
    re.compile(r"do\s+anything\s+now", re.IGNORECASE),
    re.compile(r"bypass\s+(your\s+)?(safety|content|ethical)\s+(filter|guideline|policy|restriction)", re.IGNORECASE),
]


def _sanitize_doc(doc) -> None:
    """Raise ValueError if *doc* contains a prompt-injection pattern.

    This is the runtime guardrail that prevents injected file contents from
    reaching an LLM or agent context.  It is intentionally strict: any match
    causes the entire document chunk to be rejected so that no partial payload
    can slip through.
    """
    content = doc.page_content or ""
    for pattern in _INJECTION_PATTERNS_2:
        if pattern.search(content):
            raise ValueError(
                f"Prompt injection detected in document chunk "
                f"(source: {doc.metadata.get('source', 'unknown')}): "
                f"matched pattern '{pattern.pattern}'"
            )


P = TypeVar("P", bound=BaseLoader)

# ---------------------------------------------------------------------------
# Prompt-injection scanner
# ---------------------------------------------------------------------------

# Patterns that indicate an attempt to hijack the LLM via injected instructions.
_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    # Direct instruction-override attempts
    re.compile(
        r"(ignore|disregard|forget|override|bypass)\s+(all\s+)?"
        r"(previous|prior|above|earlier|system)\s+(instructions?|prompts?|rules?|context)",
        re.IGNORECASE,
    ),
    # Role / persona hijacking
    re.compile(
        r"(you\s+are\s+now|act\s+as|pretend\s+(to\s+be|you\s+are)|your\s+new\s+role\s+is)",
        re.IGNORECASE,
    ),
    # System-prompt exfiltration
    re.compile(
        r"(print|reveal|show|output|repeat|tell\s+me)\s+(your\s+)?"
        r"(system\s+prompt|instructions?|initial\s+prompt|confidential)",
        re.IGNORECASE,
    ),
    # Shell / OS command injection
    re.compile(
        r"(\$\(|`[^`]+`|;\s*rm\s|\|\s*sh\b|\|\s*bash\b|&&\s*curl|wget\s+http)",
        re.IGNORECASE,
    ),
    # Jailbreak keywords
    re.compile(
        r"\b(jailbreak|DAN\b|do\s+anything\s+now|developer\s+mode|unrestricted\s+mode)",
        re.IGNORECASE,
    ),
]

# Leetspeak substitution table used to normalise text before pattern matching.
_LEET_TABLE = str.maketrans(
    "013456789@$!",
    "oieaasbtggas",
)

# Invisible / zero-width Unicode code-points that are used to hide text.
_INVISIBLE_CATEGORIES = {"Cf"}  # Unicode category: Format characters


def _contains_invisible_text(text: str) -> bool:
    """Return True if *text* contains invisible Unicode format characters."""
    return any(unicodedata.category(ch) in _INVISIBLE_CATEGORIES for ch in text)


def _decode_base64_fragments(text: str) -> list[str]:
    """Extract and decode any plausible base64 fragments found in *text*."""
    decoded: list[str] = []
    # Match runs of base64 characters that are long enough to be meaningful.
    for match in re.finditer(r"[A-Za-z0-9+/]{20,}={0,2}", text):
        candidate = match.group(0)
        try:
            # Pad to a multiple of 4 if necessary.
            padded = candidate + "=" * (-len(candidate) % 4)
            result = base64.b64decode(padded).decode("utf-8", errors="ignore")
            if result.strip():
                decoded.append(result)
        except Exception:
            pass
    return decoded


def _scan_text(text: str) -> str | None:
    """
    Scan *text* for prompt-injection indicators.

    Returns a human-readable description of the first problem found,
    or ``None`` if the text appears clean.
    """
    # 1. Invisible / zero-width characters.
    if _contains_invisible_text(text):
        return "invisible Unicode format characters detected"

    # 2. Direct pattern matching on the raw text.
    for pattern in _INJECTION_PATTERNS:
        if pattern.search(text):
            return f"suspicious pattern matched: {pattern.pattern[:60]}"

    # 3. Leetspeak-normalised matching.
    normalised = text.lower().translate(_LEET_TABLE)
    for pattern in _INJECTION_PATTERNS:
        if pattern.search(normalised):
            return f"leetspeak-encoded suspicious pattern matched: {pattern.pattern[:60]}"

    # 4. Base64-decoded content matching.
    for decoded_fragment in _decode_base64_fragments(text):
        for pattern in _INJECTION_PATTERNS:
            if pattern.search(decoded_fragment):
                return (
                    f"base64-encoded suspicious pattern matched: {pattern.pattern[:60]}"
                )
        if _contains_invisible_text(decoded_fragment):
            return "invisible characters found inside base64-encoded content"

    return None


def scan_documents_for_prompt_injection(documents: list) -> None:  # type: ignore[type-arg]
    """
    Raise ``ValueError`` if any document chunk contains prompt-injection content.

    Parameters
    ----------
    documents:
        A list of LangChain ``Document`` objects whose ``page_content`` will
        be inspected.
    """
    for i, doc in enumerate(documents):
        content = getattr(doc, "page_content", "") or ""
        finding = _scan_text(content)
        if finding is not None:
            raise ValueError(
                f"Prompt injection detected in document chunk {i}: {finding}"
            )



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
            # Guardrail: reject any document whose content contains a
            # prompt-injection pattern before it is split or forwarded to
            # an LLM / agent context.
            for _raw_doc in documents:
                _sanitize_doc(_raw_doc)
            docs = self.text_splitter.split_documents(documents)
            # Also sanitize post-split chunks in case a pattern spans a
            # chunk boundary introduced by the splitter.
            for _chunk in docs:
                _sanitize_doc(_chunk)
            scan_documents_for_prompt_injection(docs)

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
