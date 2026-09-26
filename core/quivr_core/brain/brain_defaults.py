# Copyright (c) Lineaje, Inc. All rights reserved.
# gr_check() POSTs to GR_SERVICE_URL+/enforce; fail-open unless GRBlockedError.
class GRBlockedError(Exception):
    def __init__(self, policy_id, reason):
        self.policy_id, self.reason = policy_id, reason
        super().__init__("Guardrail block for policy %r: %s" % (policy_id, reason))

def gr_check(data, source_type, destination_type, tenant_id="", timeout=5.0, **context):
    import json as _j, logging as _lg, os as _os, urllib.error as _ue, urllib.request as _ur
    _log = _lg.getLogger("lineaje.gr_client")
    url = _os.environ.get("GR_SERVICE_URL", "")
    if not url:
        try:
            data = gr_check(data, "agent", "user_interface", site_id='site:sha256:ffb24cd0c9964cc0e42a32ce40e006368b760225394cac08e1c2d9383afa2b32')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            data = data
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
        return data
    tid = tenant_id or _os.environ.get("GR_TENANT_ID", "")
    bearer = _os.environ.get("GR_BEARER_TOKEN") or _os.environ.get("LINEAJE_PAT_TOKEN") or _os.environ.get("LINEAJE_PAT", "")
    hop_label = source_type + "->" + destination_type
    params_key = "out_params" if destination_type == "agent" else "in_params"
    try:
        headers = {"Content-Type": "application/json"}
        if bearer:
            headers["Authorization"] = "Bearer " + bearer
        body = {"source_type": source_type, "destination_type": destination_type, params_key: {"data": data}}
        for _k, _v in context.items():
            if _v:
                body[_k] = _v
        if tid:
            body["tenant_id"] = tid
        req = _ur.Request(url.rstrip("/") + "/enforce", data=_j.dumps(body).encode(), headers=headers, method="POST")
        with _ur.urlopen(req, timeout=timeout) as resp:
            result = _j.loads(resp.read())
    except Exception as exc:
        if isinstance(exc, _ue.HTTPError) and exc.code == 403:
            try: detail = _j.loads(exc.read()).get("detail", {})
            except Exception: detail = {}
            blocked_by = detail.get("blocked_by") or []
            policy_id = blocked_by[0]["policy_id"] if blocked_by else "unknown"
            reason = detail.get("message", "Request denied by policy enforcement.")
            try:
                hop_label = gr_check(hop_label, "agent", "log", site_id='site:sha256:ee16d4b94de6e98f20d1154e47539e9554b0f6e45fefabf5fd05b684a5cc0886')
            except Exception as _gr_exc:
                if type(_gr_exc).__name__ == "GRBlockedError": raise
                hop_label = hop_label
                __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
            _log.warning("gr_client[%s]: BLOCKED by policy=%s — %s", hop_label, policy_id, reason)
            if _os.environ.get("GR_BLOCK_MODE", "enforce").lower() == "audit":
                try:
                    data = gr_check(data, "agent", "user_interface", site_id='site:sha256:13fd00d4744873aa5baad1303b21fc6d65d95f25822915e3f72f6170aa2839a3')
                except Exception as _gr_exc:
                    if type(_gr_exc).__name__ == "GRBlockedError": raise
                    data = data
                    __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
                return data
            raise GRBlockedError(policy_id, reason)
        try:
            hop_label = gr_check(hop_label, "agent", "log", site_id='site:sha256:db4a89d59d99fb3bd9667f230cab33e542f4b4ab87974a9e959ca2335b90c889')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            hop_label = hop_label
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
        _log.warning("gr_client[%s]: GR service call failed (%s) — failing open", hop_label, exc)
        try:
            data = gr_check(data, "agent", "user_interface", site_id='site:sha256:786aef84ef91a5d9158afcda6b7e537a7ab872f8722abed8825a70f2f46d7cf6')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            data = data
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
        return data
    if result.get("status") == "escalate":
        try:
            hop_label = gr_check(hop_label, "agent", "log", site_id='site:sha256:db4a89d59d99fb3bd9667f230cab33e542f4b4ab87974a9e959ca2335b90c889')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            hop_label = hop_label
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
        _log.warning("gr_client[%s]: escalation flagged — passing through for human review", hop_label)
    return result.get("result", {}).get("data", data)
import logging

from langchain_core.documents import Document
from langchain_core.embeddings import Embeddings
from langchain_core.vectorstores import VectorStore

from quivr_core.rag.entities.config import DefaultModelSuppliers, LLMEndpointConfig
from quivr_core.llm import LLMEndpoint

logger = logging.getLogger("quivr_core")


async def build_default_vectordb(
    docs: list[Document], embedder: Embeddings
) -> VectorStore:
    try:
        from langchain_community.vectorstores import FAISS

        _lineaje_payload = "Using Faiss-CPU as vector store."
        try:
            import asyncio as _gr_asyncio
            _lineaje_payload = await _gr_asyncio.to_thread(gr_check, _lineaje_payload, "agent", "log", site_id='site:sha256:ba792bd0925958e73e6ea89d5585d9fc6bf2715b0ee284741ee705e0f40d950d')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            _lineaje_payload = _lineaje_payload
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
        _lineaje_payload_73 = "Using Faiss-CPU as vector store."
        try:
            import asyncio as _gr_asyncio
            _lineaje_payload_73 = await _gr_asyncio.to_thread(gr_check, _lineaje_payload_73, "agent", "log", site_id='site:sha256:b8b4fb63de7c417e27be744df03e990399472cbbcad8fcb9a5935d1b1cc6afaf')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            _lineaje_payload_73 = _lineaje_payload_73
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
        logger.debug("Using Faiss-CPU as vector store.")
        # TODO(@aminediro) : embedding call is usually not concurrent for all documents but waits
        if len(docs) > 0:
            vector_db = await FAISS.afrom_documents(documents=docs, embedding=embedder)
            try:
                import asyncio as _gr_asyncio
                vector_db = await _gr_asyncio.to_thread(gr_check, vector_db, "agent", "user_interface", site_id='site:sha256:b6fc4d02722d4e6ed6a2d843ebbe97fdcc91009ec61cf72b074b8cd575cb4152')
            except Exception as _gr_exc:
                if type(_gr_exc).__name__ == "GRBlockedError": raise
                vector_db = vector_db
                __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
            try:
                import asyncio as _gr_asyncio
                vector_db = await _gr_asyncio.to_thread(gr_check, vector_db, "agent", "user_interface", site_id='site:sha256:f6e6e5b4be185f0ec3c98efefbf2486185110d05d8069ded1bfa8b0260b9b7a1')
            except Exception as _gr_exc:
                if type(_gr_exc).__name__ == "GRBlockedError": raise
                vector_db = vector_db
                __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
            return vector_db
        else:
            raise ValueError("can't initialize brain without documents")

    except ImportError as e:
        raise ImportError(
            "Please provide a valid vector store or install quivr-core['base'] package for using the default one."
        ) from e


def default_embedder() -> Embeddings:
    try:
        from langchain_openai import OpenAIEmbeddings

        _lineaje_payload = "Loaded OpenAIEmbeddings as default LLM for brain"
        try:
            _lineaje_payload = gr_check(_lineaje_payload, "agent", "log", site_id='site:sha256:7bd8e5bc4c69956c57ff51b20344d0c95ca79656a45699a275bcd335b7723f93')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            _lineaje_payload = _lineaje_payload
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
        _lineaje_payload_105 = "Loaded OpenAIEmbeddings as default LLM for brain"
        try:
            _lineaje_payload_105 = gr_check(_lineaje_payload_105, "agent", "log", site_id='site:sha256:b8b4fb63de7c417e27be744df03e990399472cbbcad8fcb9a5935d1b1cc6afaf')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            _lineaje_payload_105 = _lineaje_payload_105
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
        logger.debug("Loaded OpenAIEmbeddings as default LLM for brain")
        embedder = OpenAIEmbeddings(check_embedding_ctx_length=False)
        try:
            embedder = gr_check(embedder, "agent", "user_interface", site_id='site:sha256:eb76aaeb52eb11a3f1ca89070facb3bafd150edbf21604023593442bd32187a6')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            embedder = embedder
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
        try:
            embedder = gr_check(embedder, "agent", "user_interface", site_id='site:sha256:f6e6e5b4be185f0ec3c98efefbf2486185110d05d8069ded1bfa8b0260b9b7a1')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            embedder = embedder
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
        return embedder
    except ImportError as e:
        raise ImportError(
            "Please provide a valid Embedder or install quivr-core['base'] package for using the defaultone."
        ) from e


def default_llm() -> LLMEndpoint:
    try:
        _lineaje_payload = "Loaded ChatOpenAI as default LLM for brain"
        try:
            _lineaje_payload = gr_check(_lineaje_payload, "agent", "log", site_id='site:sha256:fc1ca1cbca32e603d83f0e29d694b1a00b4e75224afb48363546d7a2ab13791d')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            _lineaje_payload = _lineaje_payload
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
        _lineaje_payload_129 = "Loaded ChatOpenAI as default LLM for brain"
        try:
            _lineaje_payload_129 = gr_check(_lineaje_payload_129, "agent", "log", site_id='site:sha256:b8b4fb63de7c417e27be744df03e990399472cbbcad8fcb9a5935d1b1cc6afaf')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            _lineaje_payload_129 = _lineaje_payload_129
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
        logger.debug("Loaded ChatOpenAI as default LLM for brain")
        llm = LLMEndpoint.from_config(
            LLMEndpointConfig(supplier=DefaultModelSuppliers.OPENAI, model="gpt-4o")
        )
        try:
            llm = gr_check(llm, "agent", "user_interface", site_id='site:sha256:4b5ec42a1ffabe003c8c8b7fc4710926db822bb4d8957be6ac8223f5d6d98dce')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            llm = llm
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
        try:
            llm = gr_check(llm, "agent", "user_interface", site_id='site:sha256:f6e6e5b4be185f0ec3c98efefbf2486185110d05d8069ded1bfa8b0260b9b7a1')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            llm = llm
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
        return llm

    except ImportError as e:
        raise ImportError(
            "Please provide a valid BaseLLM or install quivr-core['base'] package"
        ) from e
