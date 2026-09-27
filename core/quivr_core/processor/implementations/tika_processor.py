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

logger = logging.getLogger("quivr_core")

# ---------------------------------------------------------------------------
# Prompt-injection sanitisation helpers
# ---------------------------------------------------------------------------

# Patterns that indicate an attempt to hijack the LLM via injected instructions.
_INJECTION_PATTERNS: list[re.Pattern] = [
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
        r"(system\s*prompt|new\s+instructions?|revised\s+instructions?|updated\s+instructions?)",
        re.IGNORECASE,
    ),
    # Shell / code execution attempts
    re.compile(
        r"(\$\(|`[^`]+`|\bexec\s*\(|\beval\s*\(|\bos\.system\s*\(|\bsubprocess\b)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(rm\s+-rf|chmod\s+[0-7]+|curl\s+http|wget\s+http|nc\s+-[a-z]*e|/bin/(sh|bash|zsh))",
        re.IGNORECASE,
    ),
]

# Leetspeak substitution table used to normalise text before pattern matching.
_LEET_TABLE = str.maketrans(
    "013456789@$!",
    "oieaasbtggas",
)


def _decode_base64_segments(text: str) -> str:
    """Replace any valid base64 segments (≥20 chars) with their decoded form."""
    pattern = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")

    def _try_decode(m: re.Match) -> str:
        candidate = m.group(0)
        # Pad to a multiple of 4 if necessary.
        padded = candidate + "=" * (-len(candidate) % 4)
        try:
            decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
            if decoded.isprintable():
                return decoded
        except Exception:
            pass
        return candidate

    return pattern.sub(_try_decode, text)


def _normalise_leet(text: str) -> str:
    """Convert common leetspeak characters to their alphabetic equivalents."""
    return text.translate(_LEET_TABLE)


def sanitize_extracted_text(text: str) -> str:
    """
    Scan *text* (extracted from an uploaded file) for prompt-injection
    attempts, base64-encoded payloads, leetspeak obfuscation, and shell
    commands.  Raises ``ValueError`` if malicious content is detected so
    that the caller can reject the document before it reaches an LLM.
    """
    # 1. Expand any base64 segments so encoded payloads are visible.
    expanded = _decode_base64_segments(text)

    # 2. Normalise leetspeak in a copy so we can match obfuscated variants.
    normalised = _normalise_leet(expanded)

    for variant in (expanded, normalised):
        for pattern in _INJECTION_PATTERNS:
            match = pattern.search(variant)
            if match:
                raise ValueError(
                    f"Potential prompt injection detected in uploaded file "
                    f"(matched pattern '{pattern.pattern}' near: "
                    f"'{match.group(0)[:80]}')"
                )

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
        txt = sanitize_extracted_text(txt)
        document = Document(page_content=txt)
        docs = self.text_splitter.split_documents([document])
        for doc in docs:
            doc.metadata = {"chunk_size": len(self.enc.encode(doc.page_content))}

        return ProcessedDocument(
            chunks=docs, processor_cls="TikaProcessor", processor_response=None
        )
