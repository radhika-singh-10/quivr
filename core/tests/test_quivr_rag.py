# Copyright (c) Lineaje, Inc. All rights reserved.
# Lineaje UnifAI guardrail  version=2.0.0-alpha
def _lineaje_load_gr_client():
    """Lineaje-added: load gr_stub_client.py without a pip dependency."""
    import sys as _s, importlib.util as _ilu
    from pathlib import Path as _P
    n = "_lineaje_gr_stub_client"
    if n in _s.modules: return _s.modules[n]
    h = _P(__file__).resolve().parent
    _cand = next((d / "gr_stub_client.py" for d in [h, *h.parents][:8] if (d / "gr_stub_client.py").is_file()), h / "gr_stub_client.py")
    _spec = _ilu.spec_from_file_location(n, _cand)
    _s.modules[n] = _m = _ilu.module_from_spec(_spec)
    _spec.loader.exec_module(_m); return _m

from uuid import uuid4

import pytest
from quivr_core.rag.entities.chat import ChatHistory
from quivr_core.rag.entities.config import LLMEndpointConfig, RetrievalConfig
from quivr_core.llm import LLMEndpoint
from quivr_core.rag.entities.models import ParsedRAGChunkResponse, RAGResponseMetadata
from quivr_core.rag.quivr_rag_langgraph import QuivrQARAGLangGraph


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


@pytest.mark.base
@pytest.mark.asyncio
async def test_quivrqaraglanggraph(
    mem_vector_store, full_response, mock_chain_qa_stream, openai_api_key
):
    # Making sure the model
    llm_config = LLMEndpointConfig(model="gpt-4o")
    # LINEAJE: enforce() `llm_config` at llm->agent post_model — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.); AI_APP_SEC_028 (Do not use LLMs from the organization's disallowed list). Mask/block; do not remove without review. site_id='site:sha256:416a1daa42e31be8ccdabb216cb603ae318aa78c9dfc4b9383dc6dcc668bd5f1'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:416a1daa42e31be8ccdabb216cb603ae318aa78c9dfc4b9383dc6dcc668bd5f1', phase='post_model', boundary={'source': 'model', 'sink': 'agent_message'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_029', 'guardrail_id': 'Emit immutable, forensic-ready audit records for all AI decisions.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_006', 'guardrail_id': 'Enforce Approved LLM.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_028', 'guardrail_id': 'Enforce Approved LLM', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='llm', destination_type='agent')
    llm_config = _gr_client.enforce(_gr_site, llm_config, content_type='application/json', variable_name='llm_config', source_file=__file__, before_line=60)
    # LINEAJE: enforce() `llm_config` at html->user_interface data_egress — scan flagged AI_IAC_024 (General purpose AI model integrations must reference a model card or technical documentation). Mask/block; do not remove without review. site_id='site:sha256:7cb19d70a2ced9ec068d000c0c15809800ca754a6d46b63dc701852885303b14'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:7cb19d70a2ced9ec068d000c0c15809800ca754a6d46b63dc701852885303b14', phase='data_egress', boundary={'source': 'html', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_IAC_024', 'guardrail_id': None, 'policy_version': None}], fail_mode='BLOCK', source_type='html', destination_type='user_interface')
    llm_config = _gr_client.enforce(_gr_site, llm_config, content_type='text/html')
    llm = LLMEndpoint.from_config(llm_config)
    retrieval_config = RetrievalConfig(llm_config=llm_config)
    chat_history = ChatHistory(uuid4(), uuid4())
    rag_pipeline = QuivrQARAGLangGraph(
        retrieval_config=retrieval_config, llm=llm, vector_store=mem_vector_store
    )

    stream_responses: list[ParsedRAGChunkResponse] = []

    # Making sure that we are calling the func_calling code path
    assert rag_pipeline.llm_endpoint.supports_func_calling()
    async for resp in rag_pipeline.answer_astream(
        "answer in bullet points. tell me something", chat_history, []
    ):
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
