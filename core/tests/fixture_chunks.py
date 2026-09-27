import asyncio
import json
import logging
import time
from uuid import uuid4

logger = logging.getLogger(__name__)

from langchain_core.embeddings import DeterministicFakeEmbedding
from langchain_core.messages.ai import AIMessageChunk
from langchain_core.vectorstores import InMemoryVectorStore
# Model card / technical documentation for the GPT-4o model used below:
# See MODEL_CARD_URL for details before deploying this integration.
MODEL_CARD_URL = "https://openai.com/research/"  # TODO: replace with the exact GPT-4o model card URL before deployment

from quivr_core.rag.entities.chat import ChatHistory
from quivr_core.rag.entities.config import LLMEndpointConfig, RetrievalConfig
from quivr_core.llm import LLMEndpoint
from quivr_core.rag.quivr_rag_langgraph import QuivrQARAGLangGraph


import re


_AI_APP_SEC_006_DISAPPROVED_MODELS = [
    "deepseek",
    "customllmclientnull",
    "openrouternull",
]


def _ai_app_sec_006_normalize(name: str) -> str:
    """Normalize a model identifier for registry comparison."""
    return re.sub(r'[\s\-_\.:]', '', name).lower()


def _ai_app_sec_006_check_model(model: str) -> str:
    """Raise ValueError if *model* matches a disapproved model; otherwise return it."""
    normalized = _ai_app_sec_006_normalize(model)
    for disapproved in _AI_APP_SEC_006_DISAPPROVED_MODELS:
        if disapproved in normalized:
            raise ValueError(
                f"Model '{model}' is on the organization's disapproved list and cannot be used."
            )
    return model


DYNAMIC_CODE_PATTERNS = [
    re.compile(r'\beval\s*\(', re.IGNORECASE),
    re.compile(r'\bexec\s*\(', re.IGNORECASE),
    re.compile(r'\bsubprocess\s*\..*shell\s*=\s*True', re.IGNORECASE),
    re.compile(r'\bos\.system\s*\(', re.IGNORECASE),
    re.compile(r'\bos\.popen\s*\(', re.IGNORECASE),
    re.compile(r'\b__import__\s*\(', re.IGNORECASE),
    re.compile(r'\bcompile\s*\(', re.IGNORECASE),
    re.compile(r'\bexecfile\s*\(', re.IGNORECASE),
    re.compile(r'\beval\b', re.IGNORECASE),  # bash/JS eval keyword
]


def _line_contains_dynamic_code(line: str) -> bool:
    """Return True if the line contains a dynamic code execution primitive."""
    return any(pattern.search(line) for pattern in DYNAMIC_CODE_PATTERNS)


def sanitize_llm_output(text: str) -> str:
    """Remove lines that contain dynamic code execution primitives."""
    if not text:
        return text
    sanitized_lines = [
        line for line in text.splitlines(keepends=True)
        if not _line_contains_dynamic_code(line)
    ]
    return "".join(sanitized_lines)


# ---------------------------------------------------------------------------
# Inline prompt-injection guardrail
# ---------------------------------------------------------------------------
_INJECTION_PATTERNS = re.compile(
    r"(ignore (all |previous |prior |above )?instructions"
    r"|disregard (all |previous |prior |above )?instructions"
    r"|you are now"
    r"|act as"
    r"|forget (all |your |previous )?instructions"
    r"|system prompt"
    r"|<\|.*?\|>"
    r"|\[INST\]"
    r"|###\s*instruction"
    r"|jailbreak)",
    re.IGNORECASE,
)


def enforce(text: str) -> str:
    """Sanitize *text* and raise ValueError if a prompt-injection attempt is detected."""
    if not isinstance(text, str):
        raise TypeError(f"enforce() expects a str, got {type(text).__name__}")
    if _INJECTION_PATTERNS.search(text):
        raise ValueError(
            f"Prompt injection detected and blocked. "
            f"Offending content: {text[:120]!r}"
        )
    return text


# ---------------------------------------------------------------------------


async def main():
    # gpt-4o-mini is not on the organization's disapproved list; no allowlist
    # exists, so any non-disapproved model is permitted per policy.
    _ai_app_sec_006_model = _ai_app_sec_006_check_model("gpt-4o-mini")
    retrieval_config = RetrievalConfig(llm_config=LLMEndpointConfig(model=_ai_app_sec_006_model))
    embedder = DeterministicFakeEmbedding(size=20)
    vec = InMemoryVectorStore(embedder)

    llm = LLMEndpoint.from_config(retrieval_config.llm_config)
    chat_history = ChatHistory(uuid4(), uuid4())
    rag_pipeline = QuivrQARAGLangGraph(
        retrieval_config=retrieval_config, llm=llm, vector_store=vec
    )

    conversational_qa_chain = rag_pipeline.build_chain()

    _request_id = str(uuid4())
    _model_name = retrieval_config.llm_config.model
    _operation = "astream_events"
    _input_messages = [
        ("user", "What is NLP, give a very long detailed answer"),
    ]
    _input_length = sum(len(str(m)) for m in _input_messages)
    logger.info(
        "LLM request",
        extra={
            "request_id": _request_id,
            "model": _model_name,
            "operation": _operation,
            "input_length_chars": _input_length,
        },
    )
    _start_time = time.monotonic()
    _output_length = 0
    _stream_error = None
    with open("response.jsonl", "w") as f:
        try:
            async for event in conversational_qa_chain.astream_events(
                {
                    "messages": _input_messages,
                    "chat_history": chat_history,
                    "custom_personality": None,
                },
                version="v1",
                config={"metadata": {}},
            ):
                kind = event["event"]
                if (
                    kind == "on_chat_model_stream"
                    and event["metadata"]["langgraph_node"] == "generate"
                ):
                    chunk = event["data"]["chunk"]
                    dict_chunk = {
                        k: v.dict() if isinstance(v, AIMessageChunk) else v
                        for k, v in chunk.items()
                    }
                    # Sanitize any text content in the chunk before writing
                    _ai_app_sec_029_sanitized_chunk = {}
                    for _ai_app_sec_029_k, _ai_app_sec_029_v in dict_chunk.items():
                        if isinstance(_ai_app_sec_029_v, dict) and "content" in _ai_app_sec_029_v:
                            _ai_app_sec_029_sanitized_content = sanitize_llm_output(_ai_app_sec_029_v["content"])
                            _ai_app_sec_029_sanitized_chunk[_ai_app_sec_029_k] = dict(_ai_app_sec_029_v, content=_ai_app_sec_029_sanitized_content)
                        elif isinstance(_ai_app_sec_029_v, str):
                            _ai_app_sec_029_sanitized_chunk[_ai_app_sec_029_k] = sanitize_llm_output(_ai_app_sec_029_v)
                        else:
                            _ai_app_sec_029_sanitized_chunk[_ai_app_sec_029_k] = _ai_app_sec_029_v
                    _output_length += len(json.dumps(_ai_app_sec_029_sanitized_chunk))
                    f.write(json.dumps(_ai_app_sec_029_sanitized_chunk) + "\n")
        except Exception as _exc:
            _stream_error = type(_exc).__name__
            raise
        finally:
            _duration = time.monotonic() - _start_time
            logger.info(
                "LLM response",
                extra={
                    "request_id": _request_id,
                    "model": _model_name,
                    "operation": _operation,
                    "duration_seconds": round(_duration, 4),
                    "output_length_chars": _output_length,
                    "status": "error" if _stream_error else "success",
                    "error": _stream_error,
                },
            )


asyncio.run(main())
