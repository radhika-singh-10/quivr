import logging
import re
import time
from dataclasses import asdict
from uuid import uuid4

import pytest
from langchain_core.documents import Document
from langchain_core.embeddings import Embeddings
from quivr_core.brain import Brain
from quivr_core.rag.entities.chat import ChatHistory
from quivr_core.llm import LLMEndpoint
from quivr_core.storage.local_storage import TransparentStorage


_ai_app_sec_029_patterns = re.compile(
    r"("
    r"\beval\s*\("
    r"|\bexec\s*\("
    r"|\bos\.system\s*\("
    r"|\bos\.popen\s*\("
    r"|subprocess\.[a-zA-Z_]+\s*\([^)]*shell\s*=\s*True"
    r"|\bcompile\s*\("
    r"|\b__import__\s*\("
    r"|\bimportlib\.import_module\s*\("
    r"|\bgetattr\s*\(.*\beval\b"
    r"|\bexecfile\s*\("
    r"|\bcallable\s*\("
    r"|\bpickle\.loads\s*\("
    r"|\bmarshal\.loads\s*\("
    r")",
    re.IGNORECASE,
)


def _ai_app_sec_029_sanitize_llm_output(text: str) -> str:
    """Sanitize LLM output by removing lines containing dynamic code execution primitives."""
    if not isinstance(text, str):
        return text
    sanitized_lines = [
        line for line in text.splitlines(keepends=True)
        if not _ai_app_sec_029_patterns.search(line)
    ]
    return "".join(sanitized_lines)


logger = logging.getLogger(__name__)

_INJECTION_PATTERNS = re.compile(
    r"(ignore\s+(previous|above|all)\s+instructions"
    r"|you\s+are\s+now"
    r"|disregard\s+(all\s+)?(previous\s+)?instructions"
    r"|system\s*:\s*"
    r"|<\s*system\s*>"
    r"|\[\s*system\s*\]"
    r"|act\s+as\s+(if\s+you\s+are|a\s+)"
    r"|forget\s+(all\s+)?(previous\s+)?instructions"
    r"|new\s+instructions\s*:"
    r"|override\s+(previous\s+)?instructions)",
    re.IGNORECASE,
)


def sanitize_input(text: str) -> str:
    """Guardrail: detect and block prompt injection attempts in user-supplied text."""
    if not isinstance(text, str):
        raise TypeError(f"Expected str, got {type(text).__name__}")
    if _INJECTION_PATTERNS.search(text):
        raise ValueError(
            "Prompt injection detected in user input. Request blocked."
        )
    # Strip null bytes and other control characters that could be used for injection
    sanitized = text.replace("\x00", "").strip()
    return sanitized


import base64 as _base64
import pathlib as _pathlib


_ai_app_sec_040_LEETSPEAK_PATTERN = re.compile(
    r"(?:[i1][g9][n][o0][r][e3]|[y][o0][u][\s_-]*[a4][r][e3]|[s5][y][s5][t][e3][m])",
    re.IGNORECASE,
)

_ai_app_sec_040_SHELL_PATTERN = re.compile(
    r"(\$\(|`[^`]*`|\beval\s*\(|\bexec\s*\(|\bos\.system\s*\(|\bsubprocess\.)",
    re.IGNORECASE,
)


def _ai_app_sec_040_scan_file_content(content: str, path: str) -> None:
    """Scan file text content for prompt injection, leetspeak, base64-encoded prompts, and shell commands."""
    if _INJECTION_PATTERNS.search(content):
        raise ValueError(
            f"Prompt injection pattern detected in file: {path}"
        )
    if _ai_app_sec_040_LEETSPEAK_PATTERN.search(content):
        raise ValueError(
            f"Leetspeak injection pattern detected in file: {path}"
        )
    if _ai_app_sec_040_SHELL_PATTERN.search(content):
        raise ValueError(
            f"Shell command injection pattern detected in file: {path}"
        )
    # Check for base64-encoded payloads that decode to injection patterns
    for token in re.findall(r"[A-Za-z0-9+/]{20,}={0,2}", content):
        try:
            decoded = _base64.b64decode(token + "==").decode("utf-8", errors="ignore")
            if _INJECTION_PATTERNS.search(decoded) or _ai_app_sec_040_SHELL_PATTERN.search(decoded):
                raise ValueError(
                    f"Base64-encoded injection pattern detected in file: {path}"
                )
        except Exception as exc:
            if "injection" in str(exc):
                raise


def _ai_app_sec_040_scan_files(file_paths) -> None:
    """Read and scan each file path for malicious prompt content before uploading."""
    for fp in file_paths:
        path_str = str(fp)
        try:
            content = _pathlib.Path(fp).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        _ai_app_sec_040_scan_file_content(content, path_str)


@pytest.mark.base
def test_brain_empty_files_no_vectordb(fake_llm, embedder):
    # Testing no files
    with pytest.raises(ValueError):
        Brain.from_files(
            name="test_brain",
            file_paths=[],
            llm=fake_llm,
            embedder=embedder,
        )


def test_brain_empty_files(fake_llm, embedder, mem_vector_store):
    brain = Brain.from_files(
        name="test_brain",
        file_paths=[],
        llm=fake_llm,
        embedder=embedder,
        vector_db=mem_vector_store,
    )
    assert brain


@pytest.mark.asyncio
async def test_brain_from_files_success(
    fake_llm: LLMEndpoint, embedder, temp_data_file, mem_vector_store
):
    _ai_app_sec_040_scan_files([temp_data_file])
    brain = await Brain.afrom_files(
        name="test_brain",
        file_paths=[temp_data_file],
        embedder=embedder,
        llm=fake_llm,
        vector_db=mem_vector_store,
    )
    assert brain.name == "test_brain"
    assert len(brain.chat_history) == 0
    assert brain.llm == fake_llm
    assert brain.vector_db.embeddings == embedder
    assert isinstance(brain.default_chat, ChatHistory)
    assert len(brain.default_chat) == 0

    # storage
    assert isinstance(brain.storage, TransparentStorage)
    assert len(await brain.storage.get_files()) == 1


@pytest.mark.asyncio
async def test_brain_from_langchain_docs(embedder, fake_llm, mem_vector_store):
    chunk = Document("content_1", metadata={"id": uuid4()})
    brain = await Brain.afrom_langchain_documents(
        name="test",
        llm=fake_llm,
        langchain_documents=[chunk],
        embedder=embedder,
        vector_db=mem_vector_store,
    )
    # No appended files
    assert len(await brain.storage.get_files()) == 0
    assert len(brain.chat_history) == 0


@pytest.mark.base
@pytest.mark.asyncio
async def test_brain_search(
    embedder: Embeddings,
):
    chunk1 = Document("content_1", metadata={"id": uuid4()})
    chunk2 = Document("content_2", metadata={"id": uuid4()})
    brain = await Brain.afrom_langchain_documents(
        name="test", langchain_documents=[chunk1, chunk2], embedder=embedder
    )

    k = 2
    result = await brain.asearch(sanitize_input("content_1"), n_results=k)

    assert len(result) == k
    assert result[0].chunk == chunk1
    assert result[1].chunk == chunk2
    assert result[0].distance == 0
    assert result[1].distance > result[0].distance


@pytest.mark.asyncio
async def test_brain_get_history(
    fake_llm: LLMEndpoint, embedder, temp_data_file, mem_vector_store
):
    brain = await Brain.afrom_files(
        name="test_brain",
        file_paths=[temp_data_file],
        embedder=embedder,
        llm=fake_llm,
        vector_db=mem_vector_store,
    )

    result1 = await brain.aask(sanitize_input("question"))
    if result1 is not None and hasattr(result1, 'answer'):
        result1.answer = _ai_app_sec_029_sanitize_llm_output(result1.answer)
    result2 = await brain.aask(sanitize_input("question"))
    if result2 is not None and hasattr(result2, 'answer'):
        result2.answer = _ai_app_sec_029_sanitize_llm_output(result2.answer)

    assert len(brain.default_chat) == 4


@pytest.mark.base
@pytest.mark.asyncio
async def test_brain_ask_streaming(
    fake_llm: LLMEndpoint, embedder, temp_data_file, answers
):
    _ai_app_sec_040_scan_files([temp_data_file])
    brain = await Brain.afrom_files(
        name="test_brain", file_paths=[temp_data_file], embedder=embedder, llm=fake_llm
    )

    response = ""
    async for chunk in brain.ask_streaming(sanitize_input("question")):
        response += chunk.answer
    response = _ai_app_sec_029_sanitize_llm_output(response)

    assert response == answers[1]


def test_brain_info_empty(fake_llm: LLMEndpoint, embedder, mem_vector_store):
    storage = TransparentStorage()
    id = uuid4()
    brain = Brain(
        name="test",
        id=id,
        llm=fake_llm,
        embedder=embedder,
        storage=storage,
        vector_db=mem_vector_store,
    )

    assert asdict(brain.info()) == {
        "brain_id": id,
        "brain_name": "test",
        "files_info": asdict(storage.info()),
        "chats_info": {
            "nb_chats": 1,  # start with a default chat
            "current_default_chat": brain.default_chat.id,
            "current_chat_history_length": 0,
        },
        "llm_info": asdict(fake_llm.info()),
    }
