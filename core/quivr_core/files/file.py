import base64
import hashlib
import mimetypes
import os
import re
import warnings
from contextlib import asynccontextmanager
from enum import Enum
from pathlib import Path
from typing import Any, AsyncGenerator, AsyncIterable, Self
from uuid import UUID, uuid4

import aiofiles
from openai import BaseModel


# ---------------------------------------------------------------------------
# Prompt-injection guard (policy ai_app_sec_040)
# ---------------------------------------------------------------------------

# Patterns that indicate prompt-injection attempts in uploaded file content.
_ai_app_sec_040_patterns: list[re.Pattern[str]] = [
    # Direct instruction overrides
    re.compile(
        r"(ignore|disregard|forget|override)\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context|rules?)",
        re.IGNORECASE,
    ),
    # Role / system prompt hijacking
    re.compile(
        r"(you\s+are\s+now|act\s+as|pretend\s+(to\s+be|you\s+are)|your\s+new\s+(role|persona|instructions?))",
        re.IGNORECASE,
    ),
    # Shell command injection
    re.compile(
        r"(\$\(|`[^`]+`|\bexec\s*\(|\beval\s*\(|\bos\.system\s*\(|\bsubprocess\b)",
        re.IGNORECASE,
    ),
    # Leetspeak variants of "ignore previous instructions"
    re.compile(
        r"[i1][g9][n][o0][r3][e3]\s+[p][r][e3][v][i1][o0][u][s5]",
        re.IGNORECASE,
    ),
    # Prompt / system delimiters used to escape context
    re.compile(
        r"(###\s*(system|user|assistant)|<\|im_start\||\[INST\]|\[SYS\]|<<SYS>>)",
        re.IGNORECASE,
    ),
    # Requests to reveal / exfiltrate the system prompt
    re.compile(
        r"(print|reveal|show|output|repeat|tell\s+me)\s+(the\s+)?(system\s+prompt|original\s+instructions?|confidential)",
        re.IGNORECASE,
    ),
]

# Maximum bytes decoded from base64 candidates to limit CPU usage.
_ai_app_sec_040_b64_max_bytes: int = 4096


def _ai_app_sec_040_scan(content_bytes: bytes, filename: str) -> None:
    """Scan *content_bytes* for prompt-injection patterns.

    Raises ValueError if a suspicious pattern is found.  The function
    attempts to decode the bytes as UTF-8 (ignoring errors) so that it
    works for plain-text, PDF-extracted text, and similar formats.  It
    also decodes any base64-looking tokens and rescans them.

    Binary-only files (e.g. audio/video) that cannot yield meaningful
    text are scanned on a best-effort basis; decoding errors are silently
    ignored so that legitimate binary uploads are never blocked.
    """
    text = content_bytes.decode("utf-8", errors="ignore")

    # 1. Direct pattern scan on decoded text.
    for pattern in _ai_app_sec_040_patterns:
        if pattern.search(text):
            raise ValueError(
                f"Prompt-injection content detected in uploaded file '{filename}'. "
                "Upload rejected."
            )

    # 2. Scan base64-encoded blobs embedded in the text.
    b64_candidates = re.findall(r"[A-Za-z0-9+/]{20,}={0,2}", text)
    for candidate in b64_candidates:
        try:
            decoded = base64.b64decode(candidate + "==")[: _ai_app_sec_040_b64_max_bytes]
            decoded_text = decoded.decode("utf-8", errors="ignore")
            for pattern in _ai_app_sec_040_patterns:
                if pattern.search(decoded_text):
                    raise ValueError(
                        f"Base64-encoded prompt-injection content detected in uploaded "
                        f"file '{filename}'. Upload rejected."
                    )
        except Exception as exc:
            # Re-raise only our own ValueError; ignore base64 decode errors.
            if isinstance(exc, ValueError):
                raise


# ---------------------------------------------------------------------------

class QuivrFileSerialized(BaseModel):
    id: UUID
    brain_id: UUID
    path: Path
    original_filename: str
    file_size: int | None
    file_extension: str
    file_sha1: str
    additional_metadata: dict[str, Any]


class FileExtension(str, Enum):
    txt = ".txt"
    pdf = ".pdf"
    csv = ".csv"
    doc = ".doc"
    docx = ".docx"
    pptx = ".pptx"
    xls = ".xls"
    xlsx = ".xlsx"
    md = ".md"
    mdx = ".mdx"
    markdown = ".markdown"
    bib = ".bib"
    epub = ".epub"
    html = ".html"
    odt = ".odt"
    py = ".py"
    ipynb = ".ipynb"
    m4a = ".m4a"
    mp3 = ".mp3"
    webm = ".webm"
    mp4 = ".mp4"
    mpga = ".mpga"
    wav = ".wav"
    mpeg = ".mpeg"


# PII redaction patterns for zero-tolerance PII categories
_ai_dat_sec_023_PII_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("SSN", re.compile(r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")),
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")),
    ("PHONE", re.compile(r"\b(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b")),
    ("CREDIT_CARD", re.compile(r"\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13}|3(?:0[0-5]|[68]\d)\d{11}|6(?:011|5\d{2})\d{12}|(?:2131|1800|35\d{3})\d{11})\b")),
    ("IP_ADDRESS", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")),
    ("MAC_ADDRESS", re.compile(r"\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b")),
    ("PASSPORT", re.compile(r"\b[A-Z]{1,2}\d{6,9}\b")),
    ("DRIVERS_LICENSE", re.compile(r"\b[A-Z]{1,2}\d{5,8}\b")),
    ("TIN", re.compile(r"\b\d{2}-\d{7}\b")),
    ("FINANCIAL_ACCOUNT", re.compile(r"\b\d{8,17}\b")),
    ("YEAR_OF_BIRTH", re.compile(r"\b(?:born|dob|date of birth|birth year)[^\n]{0,30}\b(19|20)\d{2}\b", re.IGNORECASE)),
    ("HOME_ADDRESS", re.compile(r"\b\d{1,5}\s+(?:[A-Za-z0-9.,'#\-]+\s){1,5}(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl)\b", re.IGNORECASE)),
    ("VIN", re.compile(r"\b[A-HJ-NPR-Z0-9]{17}\b")),
]


def _ai_dat_sec_023_redact_pii(text: str) -> str:
    """Detect and redact zero-tolerance PII categories from text content."""
    for label, pattern in _ai_dat_sec_023_PII_PATTERNS:
        text = pattern.sub(f"[REDACTED-{label}]", text)
    return text


def _ai_dat_sec_023_redact_bytes(data: bytes) -> bytes:
    """Attempt to decode bytes as text, redact PII, and re-encode.
    Falls back to returning original bytes for non-text (binary) content."""
    for encoding in ("utf-8", "latin-1"):
        try:
            text = data.decode(encoding)
            redacted = _ai_dat_sec_023_redact_pii(text)
            return redacted.encode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
    # Binary content (images, audio, etc.) — return as-is
    return data


def get_file_extension(file_path: Path) -> FileExtension | str:
    try:
        mime_type, _ = mimetypes.guess_type(file_path.name)
        if mime_type:
            mime_ext = mimetypes.guess_extension(mime_type)
            if mime_ext:
                return FileExtension(mime_ext)
        return FileExtension(file_path.suffix)
    except ValueError:
        warnings.warn(
            f"File {file_path.name} extension isn't recognized. Make sure you have registered a parser for {file_path.suffix}",
            stacklevel=2,
        )
        return file_path.suffix


async def load_qfile(brain_id: UUID, path: str | Path):
    if not isinstance(path, Path):
        path = Path(path)

    if not path.exists():
        raise FileExistsError(f"file {path} doesn't exist")

    file_size = os.stat(path).st_size

    async with aiofiles.open(path, mode="rb") as f:
        _ai_app_sec_040_raw = await f.read()

    _ai_app_sec_040_scan(_ai_app_sec_040_raw, path.name)

    file_sha1 = hashlib.sha1(_ai_app_sec_040_raw).hexdigest()

    try:
        # NOTE: when loading from existing storage, file name will be uuid
        id = UUID(path.name)
    except ValueError:
        id = uuid4()

    return QuivrFile(
        id=id,
        brain_id=brain_id,
        path=path,
        original_filename=path.name,
        file_extension=get_file_extension(path),
        file_size=file_size,
        file_sha1=file_sha1,
    )


class QuivrFile:
    __slots__ = [
        "id",
        "brain_id",
        "path",
        "original_filename",
        "file_size",
        "file_extension",
        "file_sha1",
        "additional_metadata",
    ]

    def __init__(
        self,
        id: UUID,
        original_filename: str,
        path: Path,
        file_sha1: str,
        file_extension: FileExtension | str,
        brain_id: UUID | None = None,
        file_size: int | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self.id = id
        self.brain_id = brain_id
        self.path = path
        self.original_filename = original_filename
        self.file_size = file_size
        self.file_extension = file_extension
        self.file_sha1 = file_sha1
        self.additional_metadata = metadata if metadata else {}

    def __repr__(self) -> str:
        return f"QuivrFile-{self.id} original_filename:{self.original_filename}"

    @asynccontextmanager
    async def open(self) -> AsyncGenerator[AsyncIterable[bytes], None]:
        # TODO(@aminediro) : match on path type
        f = await aiofiles.open(self.path, mode="rb")
        try:
            yield f
        finally:
            await f.close()

    @property
    def metadata(self) -> dict[str, Any]:
        return {
            "qfile_id": self.id,
            "qfile_path": self.path,
            "original_file_name": self.original_filename,
            "file_sha1": self.file_sha1,
            "file_size": self.file_size,
            **self.additional_metadata,
        }

    def serialize(self) -> QuivrFileSerialized:
        return QuivrFileSerialized(
            id=self.id,
            brain_id=self.brain_id,
            path=self.path.absolute(),
            original_filename=self.original_filename,
            file_size=self.file_size,
            file_extension=self.file_extension,
            file_sha1=self.file_sha1,
            additional_metadata=self.additional_metadata,
        )

    @classmethod
    def deserialize(cls, serialized: QuivrFileSerialized) -> Self:
        return cls(
            id=serialized.id,
            brain_id=serialized.brain_id,
            path=serialized.path,
            original_filename=serialized.original_filename,
            file_size=serialized.file_size,
            file_extension=serialized.file_extension,
            file_sha1=serialized.file_sha1,
            metadata=serialized.additional_metadata,
        )
