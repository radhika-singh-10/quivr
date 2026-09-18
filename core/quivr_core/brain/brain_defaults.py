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
            _log.warning("gr_client[%s]: BLOCKED by policy=%s — %s", hop_label, policy_id, reason)
            if _os.environ.get("GR_BLOCK_MODE", "enforce").lower() == "audit":
                return data
            raise GRBlockedError(policy_id, reason)
        _log.warning("gr_client[%s]: GR service call failed (%s) — failing open", hop_label, exc)
        return data
    if result.get("status") == "escalate":
        _log.warning("gr_client[%s]: escalation flagged — passing through for human review", hop_label)
    return result.get("result", {}).get("data", data)
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
        # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — scan flagged AI_DAT_SEC_029 (Enforce decision logging, audit trail, and forensic readiness for AI-driven actions.). Mask/block; do not remove without review. site_id='site:sha256:538a8661b463357b281a85fe8099294292e636e7d568134d09b884594f295233'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:538a8661b463357b281a85fe8099294292e636e7d568134d09b884594f295233', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log')
        _lineaje_payload = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json'))
        # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — scan flagged AI_DAT_SEC_023 (Redact PII from uploaded files.); AI_DAT_SEC_024 (Uploaded files must not contain PII (Singapore).); AI_DAT_SEC_029 (Enforce decision logging, audit trail, and forensic readiness for AI-driven actions.). Mask/block; do not remove without review. site_id='site:sha256:ba792bd0925958e73e6ea89d5585d9fc6bf2715b0ee284741ee705e0f40d950d'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:ba792bd0925958e73e6ea89d5585d9fc6bf2715b0ee284741ee705e0f40d950d', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log')
        _lineaje_payload = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json'))
        try:
            import asyncio as _gr_asyncio
            _lineaje_payload = await _gr_asyncio.to_thread(gr_check, _lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:ba792bd0925958e73e6ea89d5585d9fc6bf2715b0ee284741ee705e0f40d950d')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            _lineaje_payload = _lineaje_payload
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
        logger.debug(_lineaje_payload)
        # TODO(@aminediro) : embedding call is usually not concurrent for all documents but waits
        if len(docs) > 0:
            vector_db = await FAISS.afrom_documents(documents=docs, embedding=embedder)
            # LINEAJE: enforce() `vector_db` at agent->user_interface data_egress — scan flagged AI_DAT_SEC_023 (Redact PII from uploaded files.); AI_DAT_SEC_024 (Uploaded files must not contain PII (Singapore).); AI_DAT_SEC_029 (Enforce decision logging, audit trail, and forensic readiness for AI-driven actions.). Mask/block; do not remove without review. site_id='site:sha256:bb90969fd2937761b35ea57689facfe773b4e20404a3b6bc1bc80bbf27900939'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:bb90969fd2937761b35ea57689facfe773b4e20404a3b6bc1bc80bbf27900939', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface')
            vector_db = _gr_client.enforce(_gr_site, vector_db, content_type='text/plain')
            # LINEAJE: enforce() `vector_db` at agent->user_interface data_egress — scan flagged AI_DAT_SEC_023 (Redact PII from uploaded files.); AI_DAT_SEC_024 (Uploaded files must not contain PII (Singapore).); AI_DAT_SEC_029 (Enforce decision logging, audit trail, and forensic readiness for AI-driven actions.). Mask/block; do not remove without review. site_id='site:sha256:b6fc4d02722d4e6ed6a2d843ebbe97fdcc91009ec61cf72b074b8cd575cb4152'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:b6fc4d02722d4e6ed6a2d843ebbe97fdcc91009ec61cf72b074b8cd575cb4152', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface')
            vector_db = _gr_client.enforce(_gr_site, vector_db, content_type='text/plain')
            try:
                import asyncio as _gr_asyncio
                vector_db = await _gr_asyncio.to_thread(gr_check, vector_db, "agent", "user_interface", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:b6fc4d02722d4e6ed6a2d843ebbe97fdcc91009ec61cf72b074b8cd575cb4152')
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
        # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — scan flagged AI_DAT_SEC_023 (Redact PII from uploaded files.); AI_DAT_SEC_024 (Uploaded files must not contain PII (Singapore).); AI_DAT_SEC_029 (Enforce decision logging, audit trail, and forensic readiness for AI-driven actions.). Mask/block; do not remove without review. site_id='site:sha256:df935a45b1851374228c8b1147302943e21bd3919bcbacb0ba642ab9432b9517'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:df935a45b1851374228c8b1147302943e21bd3919bcbacb0ba642ab9432b9517', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log')
        _lineaje_payload = _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json')
        logger.debug(_lineaje_payload)
        embedder = OpenAIEmbeddings(check_embedding_ctx_length=False)
        # LINEAJE: enforce() `embedder` at agent->user_interface data_egress — scan flagged AI_DAT_SEC_023 (Redact PII from uploaded files.); AI_DAT_SEC_024 (Uploaded files must not contain PII (Singapore).); AI_DAT_SEC_029 (Enforce decision logging, audit trail, and forensic readiness for AI-driven actions.). Mask/block; do not remove without review. site_id='site:sha256:5f5c8c872d2502951038686606cd20e9f9ffa845ef6f7d5854078b481b79790e'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:5f5c8c872d2502951038686606cd20e9f9ffa845ef6f7d5854078b481b79790e', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface')
        embedder = _gr_client.enforce(_gr_site, embedder, content_type='text/plain')
        # LINEAJE: enforce() `embedder` at agent->user_interface data_egress — scan flagged AI_DAT_SEC_023 (Redact PII from uploaded files.); AI_DAT_SEC_024 (Uploaded files must not contain PII (Singapore).); AI_DAT_SEC_029 (Enforce decision logging, audit trail, and forensic readiness for AI-driven actions.). Mask/block; do not remove without review. site_id='site:sha256:eb76aaeb52eb11a3f1ca89070facb3bafd150edbf21604023593442bd32187a6'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:eb76aaeb52eb11a3f1ca89070facb3bafd150edbf21604023593442bd32187a6', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface')
        embedder = _gr_client.enforce(_gr_site, embedder, content_type='text/plain')
        try:
            embedder = gr_check(embedder, "agent", "user_interface", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:eb76aaeb52eb11a3f1ca89070facb3bafd150edbf21604023593442bd32187a6')
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
        # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — scan flagged AI_DAT_SEC_023 (Redact PII from uploaded files.); AI_DAT_SEC_024 (Uploaded files must not contain PII (Singapore).); AI_DAT_SEC_029 (Enforce decision logging, audit trail, and forensic readiness for AI-driven actions.). Mask/block; do not remove without review. site_id='site:sha256:02bde8fcfb2c9a4c836f81a58cfcf8bd076ff58c90e6e0efe4e4b36fab50326b'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:02bde8fcfb2c9a4c836f81a58cfcf8bd076ff58c90e6e0efe4e4b36fab50326b', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log')
        _lineaje_payload = _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json')
        logger.debug(_lineaje_payload)
        llm = LLMEndpoint.from_config(
            LLMEndpointConfig(supplier=DefaultModelSuppliers.OPENAI, model="gpt-4o")
        )
        # LINEAJE: enforce() `llm` at agent->user_interface data_egress — scan flagged AI_DAT_SEC_023 (Redact PII from uploaded files.); AI_DAT_SEC_024 (Uploaded files must not contain PII (Singapore).); AI_DAT_SEC_029 (Enforce decision logging, audit trail, and forensic readiness for AI-driven actions.). Mask/block; do not remove without review. site_id='site:sha256:6c183312253642435baab4d86eea742f4ab6d0b66b031c0af2493182da8b164a'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:6c183312253642435baab4d86eea742f4ab6d0b66b031c0af2493182da8b164a', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface')
        llm = _gr_client.enforce(_gr_site, llm, content_type='text/plain')
        # LINEAJE: enforce() `llm` at agent->user_interface data_egress — scan flagged AI_DAT_SEC_023 (Redact PII from uploaded files.); AI_DAT_SEC_024 (Uploaded files must not contain PII (Singapore).); AI_DAT_SEC_029 (Enforce decision logging, audit trail, and forensic readiness for AI-driven actions.). Mask/block; do not remove without review. site_id='site:sha256:4b5ec42a1ffabe003c8c8b7fc4710926db822bb4d8957be6ac8223f5d6d98dce'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:4b5ec42a1ffabe003c8c8b7fc4710926db822bb4d8957be6ac8223f5d6d98dce', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface')
        llm = _gr_client.enforce(_gr_site, llm, content_type='text/plain')
        try:
            llm = gr_check(llm, "agent", "user_interface", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:4b5ec42a1ffabe003c8c8b7fc4710926db822bb4d8957be6ac8223f5d6d98dce')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            llm = llm
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
        return llm

    except ImportError as e:
        raise ImportError(
            "Please provide a valid BaseLLM or install quivr-core['base'] package"
        ) from e
