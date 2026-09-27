import logging
import re
import re
import time
from uuid import uuid4

logger = logging.getLogger(__name__)

import pytest

# Model card / technical documentation for the GPAI model used in these tests.
# See the official OpenAI research page for GPT-4o details and safety information.
MODEL_CARD_URL = "https://openai.com/research/gpt-4o"  # TODO: replace with exact model-card URL before deployment if changed
from quivr_core.rag.entities.chat import ChatHistory
from quivr_core.rag.entities.config import LLMEndpointConfig, RetrievalConfig
from quivr_core.llm import LLMEndpoint
from quivr_core.rag.entities.models import ParsedRAGChunkResponse, RAGResponseMetadata
from quivr_core.rag.quivr_rag_langgraph import QuivrQARAGLangGraph


_ai_app_sec_006_DISAPPROVED_MODELS = [
    "deepseekchat",
    "deepseekr1",
    "deepseekr1distillllama70b",
    "deepseekreasoner",
    "customllmclientnull",
    "deepseekchatnull",
    "opennull",
    "usdeepseekr1v10null",
]


def _ai_app_sec_006_check_model(model_id: str) -> str:
    """Block disapproved models; allow everything else (no approved allowlist available)."""
    import re as _re
    normalized = _re.sub(r"[\s\-_\.:\"']+", "", model_id).lower()
    for disapproved in _ai_app_sec_006_DISAPPROVED_MODELS:
        if normalized == disapproved:
            raise ValueError(
                f"Model '{model_id}' is on the organization's disapproved model list "
                f"and cannot be used."
            )
    return model_id


_PROMPT_INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions",
    r"disregard\s+(all\s+)?(previous|prior|above)\s+instructions",
    r"forget\s+(all\s+)?(previous|prior|above)\s+instructions",
    r"you\s+are\s+now\s+(?!a\s+helpful)",
    r"act\s+as\s+(if\s+you\s+are\s+)?(?!an?\s+(assistant|helpful))",
    r"new\s+instructions?\s*:",
    r"system\s*:\s*you",
    r"<\s*/?\s*(system|prompt|instruction)\s*>",
    r"\[\s*(system|prompt|instruction)\s*\]",
]


def sanitize_input(text: str) -> str:
    """Guardrail: detect and block prompt injection attempts in user input."""
    lower = text.lower()
    for pattern in _PROMPT_INJECTION_PATTERNS:
        if re.search(pattern, lower):
            raise ValueError(
                f"Prompt injection detected in user input. "
                f"Matched pattern: '{pattern}'. Input blocked."
            )
    return text


@pytest.fixture(scope="function")
def mock_chain_qa_stream(monkeypatch, chunks_stream_answer):
    class MockQAChain:
        async def astream_events(self, *args, **kwargs):
            default_metadata = {
                "langgraph_node": "generate",
                "is_final_node": False,
                "citations": None,
                "followup_questions": None,
                "sources": None,
                "metadata_model": None,
            }

            # Send all chunks except the last one
            for chunk in chunks_stream_answer[:-1]:
                yield {
                    "event": "on_chat_model_stream",
                    "metadata": default_metadata,
                    "data": {"chunk": chunk["answer"]},
                }

            # Send the last chunk
            yield {
                "event": "end",
                "metadata": {
                    "langgraph_node": "generate",
                    "is_final_node": True,
                    "citations": [],
                    "followup_questions": None,
                    "sources": [],
                    "metadata_model": None,
                },
                "data": {"chunk": chunks_stream_answer[-1]["answer"]},
            }

    def mock_qa_chain(*args, **kwargs):
        self = args[0]
        self.final_nodes = ["generate"]
        return MockQAChain()

    monkeypatch.setattr(QuivrQARAGLangGraph, "build_chain", mock_qa_chain)


# Patterns that indicate dynamic code execution primitives in LLM output
_DANGEROUS_PATTERNS = re.compile(
    r"(?m)^.*"
    r"(?:"
    r"\beval\s*\("
    r"|\bexec\s*\("
    r"|\bsubprocess\.(?:call|run|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True"
    r"|\bos\.system\s*\("
    r"|\bos\.popen\s*\("
    r"|\bcompile\s*\("
    r"|\b__import__\s*\("
    r"|\bexecfile\s*\("
    r"|\binput\s*\(.*\beval"
    r"|\bJS\s+eval"
    r"|bash\s+-c"
    r"|\$\(.*\)"
    r").*$"
)


def sanitize_llm_response(response: "ParsedRAGChunkResponse") -> "ParsedRAGChunkResponse":
    """Remove lines containing dynamic code execution primitives from LLM output."""
    sanitized_answer = _DANGEROUS_PATTERNS.sub("", response.answer)
    # Collapse multiple consecutive newlines introduced by removed lines
    sanitized_answer = re.sub(r"\n{2,}", "\n", sanitized_answer)
    response.answer = sanitized_answer
    return response


@pytest.mark.base
@pytest.mark.asyncio
async def test_quivrqaraglanggraph(
    mem_vector_store, full_response, mock_chain_qa_stream, openai_api_key
):
    # Making sure the model
    _ai_app_sec_006_check_model("gpt-4o")
    llm_config = LLMEndpointConfig(model="gpt-4o")
    llm = LLMEndpoint.from_config(llm_config)
    retrieval_config = RetrievalConfig(llm_config=llm_config)
    chat_history = ChatHistory(uuid4(), uuid4())
    rag_pipeline = QuivrQARAGLangGraph(
        retrieval_config=retrieval_config, llm=llm, vector_store=mem_vector_store
    )

    stream_responses: list[ParsedRAGChunkResponse] = []

    # Making sure that we are calling the func_calling code path
    assert rag_pipeline.llm_endpoint.supports_func_calling()
    user_query = sanitize_input("answer in bullet points. tell me something")

    _ai_app_sec_035_request_id = str(uuid4())
    _ai_app_sec_035_model_name = llm_config.model
    _ai_app_sec_035_input_len = len(user_query)
    logger.info(
        "LLM request started",
        extra={
            "request_id": _ai_app_sec_035_request_id,
            "model": _ai_app_sec_035_model_name,
            "operation": "answer_astream",
            "input_length_chars": _ai_app_sec_035_input_len,
        },
    )
    _ai_app_sec_035_start_time = time.monotonic()
    _ai_app_sec_035_output_len = 0
    _ai_app_sec_035_chunk_count = 0
    _ai_app_sec_035_success = False
    try:
        async for resp in rag_pipeline.answer_astream(
            user_query, chat_history, []
        ):
            resp = sanitize_llm_response(resp)
            _ai_app_sec_035_output_len += len(resp.answer)
            _ai_app_sec_035_chunk_count += 1
            stream_responses.append(resp)
        _ai_app_sec_035_success = True
    finally:
        _ai_app_sec_035_duration = time.monotonic() - _ai_app_sec_035_start_time
        logger.info(
            "LLM request finished",
            extra={
                "request_id": _ai_app_sec_035_request_id,
                "model": _ai_app_sec_035_model_name,
                "operation": "answer_astream",
                "duration_seconds": _ai_app_sec_035_duration,
                "output_length_chars": _ai_app_sec_035_output_len,
                "chunk_count": _ai_app_sec_035_chunk_count,
                "success": _ai_app_sec_035_success,
            },
        )

    # This assertion passed
    assert all(
        not r.last_chunk for r in stream_responses[:-1]
    ), "Some chunks before last have last_chunk=True"
    assert stream_responses[-1].last_chunk

    # Let's check this assertion
    for idx, response in enumerate(stream_responses[1:-1]):
        assert (
            len(response.answer) > 0
        ), f"Sent an empty answer {response} at index {idx+1}"

    # Verify metadata
    default_metadata = RAGResponseMetadata().model_dump()
    assert all(
        r.metadata.model_dump() == default_metadata for r in stream_responses[:-1]
    )
    last_response = stream_responses[-1]
    # TODO(@aminediro) : test responses with sources
    assert last_response.metadata.sources == []
    assert last_response.metadata.citations == []

    # Assert whole response makes sense
    assert "".join([r.answer for r in stream_responses]) == full_response
