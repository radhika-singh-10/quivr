import base64
import re
from typing import Any

import aiofiles
from langchain_core.documents import Document

from quivr_core.files.file import QuivrFile
from quivr_core.processor.processor_base import ProcessedDocument, ProcessorBase
from quivr_core.processor.registry import FileExtension
from quivr_core.processor.splitter import SplitterConfig


# PII patterns for zero-tolerance categories
_ai_dat_sec_023_PII_PATTERNS: dict[str, re.Pattern] = {
    "SSN": re.compile(
        r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"
    ),
    "Year_of_Birth": re.compile(
        r"\b(?:born|birth\s*year|year\s*of\s*birth)[\s:]+(?:19|20)\d{2}\b",
        re.IGNORECASE,
    ),
    "Birthplace": re.compile(
        r"\b(?:born\s+in|birthplace|place\s+of\s+birth)[\s:]+[A-Za-z ,]+",
        re.IGNORECASE,
    ),
    "Phone_Number": re.compile(
        r"\b(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b"
    ),
    "Email": re.compile(
        r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
    ),
    "Mothers_Maiden_Name": re.compile(
        r"\b(?:mother(?:'s)?\s+maiden\s+name|maiden\s+name)[\s:]+[A-Za-z]+\b",
        re.IGNORECASE,
    ),
    "Home_Address": re.compile(
        r"\b\d{1,5}\s+[A-Za-z0-9 .,'#-]+(?:Street|St|Avenue|Ave|Boulevard|Blvd"
        r"|Road|Rd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl)\b",
        re.IGNORECASE,
    ),
    "Passport_Number": re.compile(
        r"\b[A-Z]{1,2}\d{6,9}\b"
    ),
    "Drivers_License": re.compile(
        r"\b(?:driver(?:'s)?\s+licen[sc]e|DL)[\s#:]+[A-Z0-9]{5,15}\b",
        re.IGNORECASE,
    ),
    "TIN": re.compile(
        r"\b\d{2}-\d{7}\b"
    ),
    "Credit_Card": re.compile(
        r"\b(?:4\d{3}|5[1-5]\d{2}|6011|3[47]\d{2})[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b"
    ),
    "Financial_Account": re.compile(
        r"\b(?:account\s*(?:number|no|#)[\s:]+)\d{6,17}\b",
        re.IGNORECASE,
    ),
    "IP_Address": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    ),
    "MAC_Address": re.compile(
        r"\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b"
    ),
    "VIN": re.compile(
        r"\b[A-HJ-NPR-Z0-9]{17}\b"
    ),
    "Employee_ID": re.compile(
        r"\b(?:employee\s*(?:id|no|number|#)[\s:]+)[A-Z0-9]{4,12}\b",
        re.IGNORECASE,
    ),
    "School_ID": re.compile(
        r"\b(?:student\s*(?:id|no|number|#)[\s:]+)[A-Z0-9]{4,12}\b",
        re.IGNORECASE,
    ),
    "Fine_Location": re.compile(
        r"\b(?:GPS|coordinates?|lat(?:itude)?|lon(?:gitude)?)[\s:]+"
        r"-?\d{1,3}\.\d{4,}[\s,]+-?\d{1,3}\.\d{4,}\b",
        re.IGNORECASE,
    ),
    "Ethnicity": re.compile(
        r"\b(?:ethnicity|ethnic\s+origin|race)[\s:]+[A-Za-z ]+\b",
        re.IGNORECASE,
    ),
    "Sexual_Orientation": re.compile(
        r"\b(?:sexual\s+orientation|sexuality)[\s:]+[A-Za-z ]+\b",
        re.IGNORECASE,
    ),
    "Medical_Records": re.compile(
        r"\b(?:diagnosis|medical\s+record(?:\s+number)?|MRN|patient\s+id)[\s:#]+[A-Za-z0-9 ,]+\b",
        re.IGNORECASE,
    ),
}


def _ai_dat_sec_023_redact_pii(text: str) -> str:
    """Detect and redact zero-tolerance PII categories from text.

    Each matched PII span is replaced with a placeholder of the form
    [REDACTED-<CATEGORY>] so that the content remains usable while
    sensitive data is removed.
    """
    for category, pattern in _ai_dat_sec_023_PII_PATTERNS.items():
        text = pattern.sub(f"[REDACTED-{category}]", text)
    return text


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


def _ai_app_sec_032_remove_leetspeak_prompts(text: str) -> str:
    """Replace leetspeak-obfuscated injection patterns with a safe placeholder.

    For every injection pattern that matches the leet-normalized form of a
    token in *text*, the corresponding span in the original text is replaced
    with '<leetspeak_prompts_removed>'.  Operates token-by-token (whitespace-
    split) so that only the offending tokens are redacted while the rest of
    the content is preserved.
    """
    tokens = text.split(" ")
    sanitized_tokens = []
    for token in tokens:
        normalized_token = token.translate(_LEET_MAP)
        matched = False
        for pattern in _INJECTION_PATTERNS:
            if pattern.search(normalized_token):
                sanitized_tokens.append("<leetspeak_prompts_removed>")
                matched = True
                break
        if not matched:
            sanitized_tokens.append(token)
    return " ".join(sanitized_tokens)


# Zero-width and invisible Unicode characters used to hide injected text
_ai_app_sec_040_INVISIBLE_CHARS = re.compile(
    r"[\u00ad\u200b\u200c\u200d\u200e\u200f\u202a-\u202e\u2060-\u2064\u206a-\u206f\ufeff]"
)

# Homoglyph / confusable character ranges (Cyrillic, Greek, etc. lookalikes)
_ai_app_sec_040_HOMOGLYPH_MAP = str.maketrans(
    "\u0430\u0435\u043e\u0440\u0441\u0445\u0443\u0456\u04cf"
    "\u03b1\u03b2\u03b5\u03b9\u03ba\u03bd\u03bf\u03c1\u03c5",
    "aeopexuic"
    "abeiknoru",
)

# Magic bytes / shebangs that indicate binary or shell executables
_ai_app_sec_040_BINARY_SIGNATURES: list[bytes] = [
    b"\x7fELF",          # ELF executable
    b"MZ",               # PE/DOS executable
    b"\xca\xfe\xba\xbe", # Mach-O fat binary
    b"\xfe\xed\xfa\xce", # Mach-O 32-bit
    b"\xfe\xed\xfa\xcf", # Mach-O 64-bit
    b"\xcf\xfa\xed\xfe", # Mach-O 64-bit LE
    b"PK\x03\x04",       # ZIP / JAR / DOCX (unexpected binary)
]
_ai_app_sec_040_SHEBANG = re.compile(r"^#!\s*/\S*(sh|bash|python|perl|ruby|node)", re.IGNORECASE)


def _ai_app_sec_040_check_invisible_text(text: str) -> None:
    """Raise ValueError if the text contains invisible/zero-width Unicode characters
    that could be used to hide injected instructions."""
    match = _ai_app_sec_040_INVISIBLE_CHARS.search(text)
    if match:
        raise ValueError(
            "Potential prompt injection detected in uploaded file content "
            "(invisible/zero-width Unicode characters). File rejected."
        )


def _ai_app_sec_040_check_homoglyphs(text: str) -> None:
    """Raise ValueError if homoglyph-normalised text matches injection patterns."""
    normalised = text.translate(_ai_app_sec_040_HOMOGLYPH_MAP)
    for pattern in _INJECTION_PATTERNS:
        if pattern.search(normalised):
            raise ValueError(
                "Potential prompt injection detected in uploaded file content "
                "(homoglyph/confusable-character obfuscation). File rejected."
            )


def _ai_app_sec_040_check_binary_executable(raw: bytes) -> None:
    """Raise ValueError if the raw bytes look like a binary or shell executable."""
    for sig in _ai_app_sec_040_BINARY_SIGNATURES:
        if raw[:len(sig)] == sig:
            raise ValueError(
                "Uploaded file appears to be a binary executable. File rejected."
            )
    # Check shebang on the first line
    first_line = raw.split(b"\n", 1)[0].decode("utf-8", errors="ignore")
    if _ai_app_sec_040_SHEBANG.match(first_line):
        raise ValueError(
            "Uploaded file contains a shell/script shebang line. File rejected."
        )


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
    # Check for invisible/zero-width characters used to hide injected text
    _ai_app_sec_040_check_invisible_text(content)

    # Check for homoglyph obfuscation
    _ai_app_sec_040_check_homoglyphs(content)

    # Check raw content against injection patterns
    for pattern in _INJECTION_PATTERNS:
        if pattern.search(content):
            raise ValueError(
                f"Potential prompt injection detected in uploaded file content "
                f"(matched pattern: {pattern.pattern!r}). File rejected."
            )

    # Sanitize leetspeak-obfuscated content by replacing matches with placeholder
    content = _ai_app_sec_032_remove_leetspeak_prompts(content)

    # Check base64-decoded segments
    for decoded_segment in _decode_base64_segments(content):
        for pattern in _INJECTION_PATTERNS:
            if pattern.search(decoded_segment):
                raise ValueError(
                    "Potential prompt injection detected in uploaded file content "
                    "(base64-encoded payload). File rejected."
                )
        # Also sanitize leetspeak in decoded segment (informational; original content already sanitized above)
        _ai_app_sec_032_remove_leetspeak_prompts(decoded_segment)

    # Final pass: ensure any remaining leetspeak in the (possibly already sanitized) content is removed
    content = _ai_app_sec_032_remove_leetspeak_prompts(content)
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
        async with aiofiles.open(file.path, mode="rb") as f:
            raw_bytes = await f.read()

        # Check for binary/executable content before decoding
        _ai_app_sec_040_check_binary_executable(raw_bytes)

        content = raw_bytes.decode("utf-8", errors="replace")

        async with aiofiles.open(file.path, mode="r") as _f_unused:
            pass  # kept for structure; content already read above

        if True:
            # Scan for prompt injection before passing to the LLM pipeline
            sanitize_content(content)

            # Redact any PII found in the file content
            content = _ai_dat_sec_023_redact_pii(content)

            doc = Document(page_content=content)

            docs = recursive_character_splitter(
            doc, self.splitter_config.chunk_size, self.splitter_config.chunk_overlap
        )
        # Sanitize leetspeak in every chunk (covers RAG/vector-store retrieved content)
        for _chunk in docs:
            _chunk.page_content = _ai_app_sec_032_remove_leetspeak_prompts(
                _chunk.page_content
            )

        return ProcessedDocument(
            chunks=docs, processor_cls="SimpleTxtProcessor", processor_response=content
        )
