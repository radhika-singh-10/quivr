import base64
import logging
import os
import re
from typing import AsyncIterable

import httpx
import tiktoken
from langchain_core.documents import Document
from langchain_text_splitters import RecursiveCharacterTextSplitter, TextSplitter

from quivr_core.files.file import QuivrFile
from quivr_core.processor.processor_base import ProcessedDocument, ProcessorBase
from quivr_core.processor.registry import FileExtension
from quivr_core.processor.splitter import SplitterConfig

import re

logger = logging.getLogger("quivr_core")

# ---------------------------------------------------------------------------
# Additional prompt-injection / shell-command patterns (ai_app_sec_040)
# ---------------------------------------------------------------------------
_ai_app_sec_040_patterns = [
    # High-risk shell/binary command invocations
    re.compile(
        r"(?i)\b(?:chmod|chown|wget|curl|nc|ncat|netcat|nmap|socat|telnet|ftp|sftp|scp|ssh|rsync)\s+",
    ),
    re.compile(
        r"(?i)\b(?:rm|rmdir|mkfs|dd|shred|truncate)\s+(?:-[a-z]+\s+)*(?:/|\./|\.\.)",
    ),
    re.compile(
        r"(?i)\b(?:sudo|su|doas|pkexec)\s+",
    ),
    re.compile(
        r"(?i)(?:/bin/|/usr/bin/|/sbin/|/usr/sbin/)(?:sh|bash|dash|zsh|ksh|csh|tcsh|python[23]?|perl|ruby|node|php)",
    ),
    re.compile(
        r"(?i)\b(?:import\s+os|import\s+subprocess|import\s+sys|from\s+os\s+import|from\s+subprocess\s+import)",
    ),
    re.compile(
        r"(?i)\b(?:subprocess\.(?:call|run|Popen|check_output)|os\.(?:system|popen|execv?e?p?)|commands\.getoutput)\s*\(",
    ),
    re.compile(
        r"(?i)\b(?:__import__|compile|execfile|open\s*\([^)]*['\"](?:/etc/|/proc/|/sys/|/dev/))",
    ),
    # Prompt-injection instruction patterns (leetspeak-resilient plain forms)
    re.compile(
        r"(?i)\bforget\s+(all\s+)?(?:previous|prior|above|your)\s+(?:instructions?|context|rules?|constraints?)",
    ),
    re.compile(
        r"(?i)\b(?:override|bypass|disable|circumvent)\s+(?:all\s+)?(?:safety|security|content|filter|restriction|policy|guideline|rule)",
    ),
    re.compile(
        r"(?i)\bdo\s+not\s+(?:follow|obey|respect|apply)\s+(?:any\s+)?(?:previous|prior|above|your)\s+(?:instructions?|rules?|constraints?|guidelines?)",
    ),
    re.compile(
        r"(?i)\bpretend\s+(?:you\s+are|to\s+be|that\s+you\s+are)\b",
    ),
    re.compile(
        r"(?i)\byour\s+(?:new\s+)?(?:role|persona|identity|purpose|goal|task|objective)\s+is\b",
    ),
    re.compile(
        r"(?i)\b(?:reveal|leak|expose|print|output|show|display|return|repeat|echo)\s+(?:your\s+)?(?:system\s+prompt|instructions?|context|training\s+data|api\s+key|secret|password|token)",
    ),
    # Null-byte / control-character injection
    re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]"),
]
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Leetspeak prompt sanitisation (ai_app_sec_032)
# ---------------------------------------------------------------------------
_ai_app_sec_032_PLACEHOLDER = "<leetspeak_prompts_removed>"

_ai_app_sec_032_LEET_MAP = str.maketrans(
    "4310578@!",
    "aeiosstal"
)

_ai_app_sec_032_PATTERNS = [
    re.compile(r"(ignore\s+(all\s+)?(previous|prior|above)\s+instructions?)", re.IGNORECASE),
    re.compile(r"(disregard\s+(all\s+)?(previous|prior|above)\s+instructions?)", re.IGNORECASE),
    re.compile(r"(you\s+are\s+now\s+(?:a|an)\b)", re.IGNORECASE),
    re.compile(r"(act\s+as\s+(?:a|an)\b)", re.IGNORECASE),
    re.compile(r"(new\s+instructions?\s*:)", re.IGNORECASE),
    re.compile(r"(system\s*:\s*you\s+are)", re.IGNORECASE),
    re.compile(r"(\[INST\]|\[/INST\]|<\|im_start\|>|<\|im_end\|>)"),
    re.compile(r"(\$\(|`[^`]+`|\beval\s*\(|\bexec\s*\(|\bos\.system\s*\()"),
    re.compile(r"(\b(?:bash|sh|cmd|powershell|python|perl|ruby|node)\s+-[a-z])", re.IGNORECASE),
]


def _ai_app_sec_032_replace_leetspeak_prompts(text: str) -> str:
    """Detect and replace leetspeak-obfuscated prompts/commands with a safe placeholder.

    Translates leetspeak characters to their plain equivalents, then scans for
    prompt-injection and system-command patterns. Any matching token in the
    original text is replaced with ``<leetspeak_prompts_removed>``.
    Applies to uploaded file content as well as RAG/vector-store retrieved chunks.
    """
    decoded = text.translate(_ai_app_sec_032_LEET_MAP)
    result = text
    for pattern in _ai_app_sec_032_PATTERNS:
        for match in pattern.finditer(decoded):
            start, end = match.start(), match.end()
            original_segment = result[start:end]
            result = result[:start] + _ai_app_sec_032_PLACEHOLDER + result[end:]
            # After replacement the offsets shift; re-decode and re-scan the updated result
            decoded = result.translate(_ai_app_sec_032_LEET_MAP)
            break  # restart outer loop with updated text
    return result
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# PII redaction (ai_dat_sec_023)
# ---------------------------------------------------------------------------
_ai_dat_sec_023_PII_PLACEHOLDER = "[REDACTED]"

_ai_dat_sec_023_patterns = [
    # Social Security Number  (e.g. 123-45-6789 / 123 45 6789 / 123456789)
    re.compile(r"\b(?!000|666|9\d{2})\d{3}[\s\-]?(?!00)\d{2}[\s\-]?(?!0000)\d{4}\b"),
    # Year of Birth (standalone 4-digit year 1900-2099 preceded by birth-related keywords)
    re.compile(r"(?i)\b(?:born|birth\s*year|year\s*of\s*birth|dob|date\s*of\s*birth)[^\n]{0,30}\b(19|20)\d{2}\b"),
    # Birthplace (keyword + value on same line)
    re.compile(r"(?i)\b(?:birthplace|place\s*of\s*birth|born\s*in)[^\n]{0,80}"),
    # Personal Phone Number (various formats)
    re.compile(r"(?<![\d])(?:\+?1[\s\-.]?)?(?:\(?\d{3}\)?[\s\-.]?)\d{3}[\s\-.]?\d{4}(?![\d])"),
    # Email address
    re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"),
    # Mother's Maiden Name (keyword + value)
    re.compile(r"(?i)\b(?:mother['\'']?s?\s*maiden\s*name|maiden\s*name)[^\n]{0,80}"),
    # Home Address (street address pattern)
    re.compile(r"(?i)\b\d{1,5}\s+[a-z0-9 .,'#\-]{5,50}\b(?:street|st|avenue|ave|boulevard|blvd|road|rd|lane|ln|drive|dr|court|ct|way|place|pl|circle|cir)\b[^\n]{0,60}"),
    # Passport Number (letter(s) + digits, 6-9 chars)
    re.compile(r"(?i)\b(?:passport\s*(?:no|number|#)?[:\s]*)?[A-Z]{1,2}\d{6,8}\b"),
    # Driver's License Number (keyword + alphanumeric)
    re.compile(r"(?i)\b(?:driver['\'']?s?\s*licen[sc]e|dl|d\.l\.)[^\n]{0,30}[A-Z0-9\-]{5,20}"),
    # Taxpayer Identification Number (EIN: XX-XXXXXXX)
    re.compile(r"\b\d{2}[\-]\d{7}\b"),
    # Credit Card Number (13-19 digits, optionally separated by spaces/dashes)
    re.compile(r"\b(?:\d{4}[\s\-]?){3}\d{4,7}\b"),
    # Financial Account Number (keyword + digits)
    re.compile(r"(?i)\b(?:account\s*(?:no|number|#)?|acct\.?)[:\s]*\d{6,20}\b"),
    # IP Address (IPv4)
    re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"),
    # MAC Address
    re.compile(r"\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b"),
    # Vehicle Identification Number (17 alphanumeric chars)
    re.compile(r"\b[A-HJ-NPR-Z0-9]{17}\b"),
    # Employee ID / School ID (keyword + alphanumeric)
    re.compile(r"(?i)\b(?:employee\s*id|emp\s*id|school\s*id|student\s*id)[^\n]{0,20}[A-Z0-9\-]{3,20}"),
    # Fine Location (GPS coordinates)
    re.compile(r"(?i)\b(?:lat(?:itude)?|lon(?:gitude)?)[^\n]{0,10}[\-]?\d{1,3}\.\d{4,}"),
    # Ethnicity (keyword + value)
    re.compile(r"(?i)\b(?:ethnicity|ethnic\s*origin|race)[^\n]{0,60}"),
    # Sexual Orientation (keyword + value)
    re.compile(r"(?i)\b(?:sexual\s*orientation|sexuality)[^\n]{0,60}"),
    # Medical Records (keyword + value)
    re.compile(r"(?i)\b(?:medical\s*record(?:\s*(?:no|number|#))?|mrn)[^\n]{0,60}"),
]


def _ai_dat_sec_023_redact_pii(text: str) -> str:
    """Redact zero-tolerance PII categories from *text* and return the sanitised copy."""
    for pattern in _ai_dat_sec_023_patterns:
        text = pattern.sub(_ai_dat_sec_023_PII_PLACEHOLDER, text)
    return text
# ---------------------------------------------------------------------------


def remove_hidden_prompts(text: str) -> str:
    """Replace hidden or invisible prompt content with a safe placeholder.

    Targets:
    - Zero-width and invisible Unicode characters (zero-width space, zero-width
      non-joiner, zero-width joiner, word joiner, invisible separator, etc.)
    - Runs of whitespace-only content that are suspiciously long (>200 chars)
      and likely used to push hidden text off-screen.
    - CSS/HTML-style hints for white-on-white or tiny-font text that may survive
      plain-text extraction (e.g. ``color:white``, ``font-size:0``).
    """
    placeholder = "<hidden_prompts_removed>"

    # Remove zero-width / invisible Unicode characters
    zero_width_pattern = (
        r"[\u200b\u200c\u200d\u200e\u200f\u202a-\u202e"
        r"\u2060\u2061\u2062\u2063\u2064\ufeff\u00ad]+"
    )
    text = re.sub(zero_width_pattern, placeholder, text)

    # Remove CSS-style hidden text hints (white color, zero/tiny font-size)
    css_hidden_pattern = (
        r"(?i)(color\s*:\s*white|color\s*:\s*#fff(?:fff)?|font-size\s*:\s*0\s*(?:px|pt|em|rem)?)"
    )
    text = re.sub(css_hidden_pattern, placeholder, text)

    # Replace suspiciously long runs of whitespace (potential off-screen padding)
    text = re.sub(r"[ \t]{200,}", placeholder, text)

    return text


class TikaProcessor(ProcessorBase):
    """
    TikaProcessor is a class that implements the ProcessorBase interface.
    It is used to process the files with the Tika server.

    To run it with docker you can do:
    ```bash
    docker run -d -p 9998:9998 apache/tika
    ```
    """

    supported_extensions = [FileExtension.pdf]

    def __init__(
        self,
        tika_url: str = os.getenv("TIKA_SERVER_URL", "http://localhost:9998/tika"),
        splitter: TextSplitter | None = None,
        splitter_config: SplitterConfig = SplitterConfig(),
        timeout: float = 5.0,
        max_retries: int = 3,
    ) -> None:
        self.tika_url = tika_url
        self.max_retries = max_retries
        self._client = httpx.AsyncClient(timeout=timeout)

        self.enc = tiktoken.get_encoding("cl100k_base")
        self.splitter_config = splitter_config

        if splitter:
            self.text_splitter = splitter
        else:
            self.text_splitter = RecursiveCharacterTextSplitter.from_tiktoken_encoder(
                chunk_size=splitter_config.chunk_size,
                chunk_overlap=splitter_config.chunk_overlap,
            )

    # ---------------------------------------------------------------------------
    # Prompt-injection sanitisation
    # ---------------------------------------------------------------------------
    _INJECTION_PATTERNS = [
        # Direct instruction overrides
        re.compile(
            r"(ignore\s+(all\s+)?(previous|prior|above)\s+instructions?)",
            re.IGNORECASE,
        ),
        re.compile(
            r"(disregard\s+(all\s+)?(previous|prior|above)\s+instructions?)",
            re.IGNORECASE,
        ),
        re.compile(r"(you\s+are\s+now\s+(?:a|an)\b)", re.IGNORECASE),
        re.compile(r"(act\s+as\s+(?:a|an)\b)", re.IGNORECASE),
        re.compile(r"(new\s+instructions?\s*:)", re.IGNORECASE),
        re.compile(r"(system\s*:\s*you\s+are)", re.IGNORECASE),
        re.compile(r"(\[INST\]|\[/INST\]|<\|im_start\|>|<\|im_end\|>)"),
        # Shell / code execution attempts
        re.compile(
            r"(\$\(|`[^`]+`|\beval\s*\(|\bexec\s*\(|\bos\.system\s*\()"
        ),
        re.compile(
            r"(\b(?:bash|sh|cmd|powershell|python|perl|ruby|node)\s+-[a-z])",
            re.IGNORECASE,
        ),
    ]

    # Leetspeak substitution map (expand as needed)
    _LEET_TABLE = str.maketrans(
        {"4": "a", "3": "e", "1": "i", "0": "o", "5": "s", "7": "t", "@": "a", "!": "i"}
    )

    def _decode_leet(self, text: str) -> str:
        """Return a leet-decoded copy of *text* for pattern matching only."""
        return text.translate(self._LEET_TABLE)

    def _extract_base64_segments(self, text: str) -> list[str]:
        """Return decoded strings for every plausible base64 token in *text*."""
        decoded: list[str] = []
        # Base64 tokens are typically 20+ chars of [A-Za-z0-9+/=]
        for token in re.findall(r"[A-Za-z0-9+/]{20,}={0,2}", text):
            try:
                candidate = base64.b64decode(token + "==").decode("utf-8", errors="ignore")
                if candidate.isprintable():
                    decoded.append(candidate)
            except Exception:
                pass
        return decoded

    def _sanitize_text(self, text: str) -> str:
        """
        Scan *text* for prompt-injection patterns.

        Raises ``ValueError`` if malicious content is detected so that the
        caller can reject the document before it reaches the LLM.
        """
        surfaces = [text, self._decode_leet(text)]
        surfaces.extend(self._extract_base64_segments(text))

        all_patterns = list(self._INJECTION_PATTERNS) + _ai_app_sec_040_patterns

        for surface in surfaces:
            for pattern in all_patterns:
                match = pattern.search(surface)
                if match:
                    raise ValueError(
                        f"Potential prompt injection detected in uploaded file "
                        f"(matched pattern '{pattern.pattern}' near: "
                        f"'{match.group(0)[:60]}'). File rejected."
                    )
        return text

    # ---------------------------------------------------------------------------

    async def _send_parse_tika(self, f: AsyncIterable[bytes]) -> str:
        retry = 0
        headers = {"Accept": "text/plain"}
        while retry < self.max_retries:
            try:
                resp = await self._client.put(self.tika_url, headers=headers, content=f)
                resp.raise_for_status()
                return resp.content.decode("utf-8")
            except Exception as e:
                retry += 1
                logger.debug(f"tika url error :{e}. retrying for the {retry} time...")
        raise RuntimeError("can't send parse request to tika server")

    @property
    def processor_metadata(self):
        return {
            "chunk_overlap": self.splitter_config.chunk_overlap,
        }

    async def process_file_inner(self, file: QuivrFile) -> ProcessedDocument[None]:
        async with file.open() as f:
            txt = await self._send_parse_tika(f)
        txt = self._sanitize_text(txt)
        txt = _ai_app_sec_032_replace_leetspeak_prompts(txt)
        txt = _ai_dat_sec_023_redact_pii(txt)
        document = Document(page_content=txt)
        docs = self.text_splitter.split_documents([document])
        for doc in docs:
            doc.metadata = {"chunk_size": len(self.enc.encode(doc.page_content))}

        return ProcessedDocument(
            chunks=docs, processor_cls="TikaProcessor", processor_response=None
        )
