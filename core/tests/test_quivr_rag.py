import re
import re
from uuid import uuid4

import pytest

# Model card / technical documentation for the GPAI model used in these tests.
# See the official OpenAI research page for GPT-4o details and safety information.
MODEL_CARD_URL = "https://openai.com/research/gpt-4o"  # TODO: replace with exact model-card URL before deployment if changed
from quivr_core.rag.entities.chat import ChatHistory
from quivr_core.rag.entities.config import LLMEndpointConfig, RetrievalConfig
from quivr_core.llm import LLMEndpoint
from quivr_core.rag.entities.models import ParsedRAGChunkResponse, RAGResponseMetadata
from quivr_core.rag.quivr_rag_langgraph import QuivrQARAGLangGraph


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
    llm_config = LLMEndpointConfig(model="gpt-3.5-turbo")
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
    async for resp in rag_pipeline.answer_astream(
        user_query, chat_history, []
    ):
        resp = sanitize_llm_response(resp)
        stream_responses.append(resp)

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
