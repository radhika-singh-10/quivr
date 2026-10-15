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

        for surface in surfaces:
            for pattern in self._INJECTION_PATTERNS:
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
        document = Document(page_content=txt)
        docs = self.text_splitter.split_documents([document])
        for doc in docs:
            doc.metadata = {"chunk_size": len(self.enc.encode(doc.page_content))}

        return ProcessedDocument(
            chunks=docs, processor_cls="TikaProcessor", processor_response=None
        )
