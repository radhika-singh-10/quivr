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

# Copyright (c) Lineaje, Inc. All rights reserved.
# gr_check() POSTs to GR_SERVICE_URL+/enforce; fail-open unless GRBlockedError.
class GRBlockedError(Exception):
    def __init__(self, policy_id, reason):
        self.policy_id, self.reason = policy_id, reason
        super().__init__("Guardrail block for policy %r: %s" % (policy_id, reason))

def gr_check(data, source_type, destination_type, tenant_id="", timeout=5.0, **context):
    import json as _j, logging as _lg, os as _os, urllib.error as _ue, urllib.request as _ur
    _log = _lg.getLogger("lineaje.gr_client")
    hop_label = source_type + "->" + destination_type
    _prior = getattr(gr_check, "_blocked", None)
    if _prior:
        # LINEAJE: enforce() `hop_label` at agent->log log_emit — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.); AI_APP_SEC_035 (Agents must log all interactions with an LLM). Mask/block; do not remove without review. site_id='site:sha256:9a5fdfeaa9809e83cef1a6eed5291df76d51300aff658252838ee03988001a0f'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:9a5fdfeaa9809e83cef1a6eed5291df76d51300aff658252838ee03988001a0f', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log')
        try:
            hop_label = _gr_client.enforce(_gr_site, hop_label, content_type='application/json')
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass
        _log.warning("gr_client[%s]: skipping POST /enforce — request already blocked (%s)", hop_label, _prior[1])
        raise GRBlockedError(_prior[0], _prior[1])
    def _blk(o):
        if isinstance(o, dict):
            return any(_blk(o.get(k)) for k in ("skill_path", "skill_file", "path", "file_path", "data", "skill_manifest_path"))
        s = str(o or "")
        b = s.replace("\\", "/").rsplit("/", 1)[-1].lower()
        if b.endswith(".md.blocked"): return True
        try:
            if b in ("skill.md", "skills.md") and _os.path.isfile(str(o) + ".blocked"): return True
        except Exception:
            pass
        return False
    if _blk(data) or _blk(context):
        # LINEAJE: enforce() `hop_label` at agent->log log_emit — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.); AI_APP_SEC_035 (Agents must log all interactions with an LLM). Mask/block; do not remove without review. site_id='site:sha256:ae2093aa9d499c092144d5336ee365379cd86d13c284e27f08eeee9e620dd9b2'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:ae2093aa9d499c092144d5336ee365379cd86d13c284e27f08eeee9e620dd9b2', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log')
        try:
            hop_label = _gr_client.enforce(_gr_site, hop_label, content_type='application/json')
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass
        _log.warning("gr_client[%s]: quarantined skill (*.blocked) — not loaded, GR not called", hop_label)
        gr_check._blocked = ("blocked_manifest", "quarantined skill must not be read, downloaded, or loaded")
        raise GRBlockedError("blocked_manifest", "quarantined skill must not be read, downloaded, or loaded")
    url = _os.environ.get("GR_SERVICE_URL", "")
    if not url:
        # LINEAJE: enforce() `data` at agent->user_interface data_egress — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.); AI_APP_SEC_035 (Agents must log all interactions with an LLM). Mask/block; do not remove without review. site_id='site:sha256:0d5c16db3719b925d20a2d6e2c2f1300212115d116fa81e81d6411cc2a9ddcaa'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:0d5c16db3719b925d20a2d6e2c2f1300212115d116fa81e81d6411cc2a9ddcaa', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface')
        try:
            data = _gr_client.enforce(_gr_site, data, content_type='text/plain')
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass
        return data
    tid = tenant_id or _os.environ.get("GR_TENANT_ID", "")
    # Refresh token first: the GR service exchanges it for the access JWT it
    # calls the Data Service policy API with; a lineaje_pat_ PAT only
    # identifies the caller and cannot be exchanged.
    bearer = _os.environ.get("GR_BEARER_TOKEN") or _os.environ.get("LINEAJE_REFRESH_TOKEN") or _os.environ.get("LINEAJE_PAT_TOKEN") or _os.environ.get("LINEAJE_PAT", "")
    params_key = "out_params" if destination_type == "agent" else "in_params"
    def _gr_js(o):
        # JSON form of non-JSON payloads (LangChain Document, pydantic models, ...).
        if hasattr(o, "page_content"):
            return {"page_content": o.page_content, "metadata": getattr(o, "metadata", None) or {}}
        for _m in ("model_dump", "dict", "to_dict"):
            _f = getattr(o, _m, None)
            if callable(_f):
                try:
                    return _f()
                except Exception:
                    pass
        if isinstance(o, (set, tuple)):
            return list(o)
        return str(o)
    def _gr_back(orig, new):
        # Map the (possibly masked) JSON back onto the caller's own objects.
        if new == _j.loads(_j.dumps(orig, default=_gr_js)):
            # LINEAJE: enforce() `orig` at agent->user_interface data_egress — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.); AI_APP_SEC_035 (Agents must log all interactions with an LLM). Mask/block; do not remove without review. site_id='site:sha256:29fb9c0665506b196db2349b6383fb3c3a59c3c8ddc3aabd3d9d244a27588804'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:29fb9c0665506b196db2349b6383fb3c3a59c3c8ddc3aabd3d9d244a27588804', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface')
            try:
                orig = _gr_client.enforce(_gr_site, orig, content_type='text/plain')
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                pass
            return orig
        if isinstance(orig, (list, tuple)) and isinstance(new, list) and len(orig) == len(new):
            _out = [_gr_back(a, b) for a, b in zip(orig, new)]
            return tuple(_out) if isinstance(orig, tuple) else _out
        if hasattr(orig, "page_content") and isinstance(new, dict) and "page_content" in new:
            import copy as _cp
            _c = _cp.copy(orig)
            _c.page_content = new["page_content"]
            if isinstance(new.get("metadata"), dict) and hasattr(_c, "metadata"):
                _c.metadata = new["metadata"]
            # LINEAJE: enforce() `_c` at agent->user_interface data_egress — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.); AI_APP_SEC_035 (Agents must log all interactions with an LLM). Mask/block; do not remove without review. site_id='site:sha256:a700d762b163bfc8c37ddfb65e2b5d155be0159d0c0ab1d2db61470952c710fd'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:a700d762b163bfc8c37ddfb65e2b5d155be0159d0c0ab1d2db61470952c710fd', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface')
            try:
                _c = _gr_client.enforce(_gr_site, _c, content_type='text/plain')
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                pass
            return _c
        if orig is None or isinstance(orig, (str, int, float, bool, dict, list)):
            # LINEAJE: enforce() `new` at agent->user_interface data_egress — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.); AI_APP_SEC_035 (Agents must log all interactions with an LLM). Mask/block; do not remove without review. site_id='site:sha256:af1a9e6ea602b69c48e365352a9d7bf9d4bdd3098ea7719c8ae81a41ad4a7cb4'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:af1a9e6ea602b69c48e365352a9d7bf9d4bdd3098ea7719c8ae81a41ad4a7cb4', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface')
            try:
                new = _gr_client.enforce(_gr_site, new, content_type='text/plain')
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                pass
            return new
        _log.warning("gr_client[%s]: masked result cannot be applied to %s — returning original", hop_label, type(orig).__name__)
        # LINEAJE: enforce() `orig` at agent->user_interface data_egress — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.); AI_APP_SEC_035 (Agents must log all interactions with an LLM). Mask/block; do not remove without review. site_id='site:sha256:778cb4d1cdee435ac7a79f0851df23760071b946e7868590e35ff8a486a5a9cb'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:778cb4d1cdee435ac7a79f0851df23760071b946e7868590e35ff8a486a5a9cb', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface')
        try:
            orig = _gr_client.enforce(_gr_site, orig, content_type='text/plain')
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass
        return orig
    try:
        headers = {"Content-Type": "application/json"}
        if bearer:
            headers["Authorization"] = "Bearer " + bearer
        _sent = _j.loads(_j.dumps(data, default=_gr_js))
        body = {"source_type": source_type, "destination_type": destination_type, params_key: {"data": _sent}}
        for _k, _v in context.items():
            if _v:
                body[_k] = _v
        if tid:
            body["tenant_id"] = tid
        _base = url.rstrip("/")
        if _base.lower().endswith("/enforce"): _base = _base[: -len("/enforce")].rstrip("/")
        req = _ur.Request(_base + "/enforce", data=_j.dumps(body, default=_gr_js).encode(), headers=headers, method="POST")
        with _ur.urlopen(req, timeout=timeout) as resp:
            result = _j.loads(resp.read())
    except Exception as exc:
        if isinstance(exc, _ue.HTTPError) and exc.code == 403:
            try: detail = _j.loads(exc.read()).get("detail", {})
            except Exception: detail = {}
            blocked_by = detail.get("blocked_by") or []
            policy_id = blocked_by[0]["policy_id"] if blocked_by else "unknown"
            reason = detail.get("message", "Request denied by policy enforcement.")
            # LINEAJE: enforce() `hop_label` at agent->log log_emit — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.); AI_APP_SEC_035 (Agents must log all interactions with an LLM). Mask/block; do not remove without review. site_id='site:sha256:0bf31831642a159acd540bc11cb82ed3ce3d7793d762cb1a962963a6a51f9724'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:0bf31831642a159acd540bc11cb82ed3ce3d7793d762cb1a962963a6a51f9724', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log')
            try:
                hop_label = _gr_client.enforce(_gr_site, hop_label, content_type='application/json')
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                pass
            _log.warning("gr_client[%s]: BLOCKED by policy=%s — %s", hop_label, policy_id, reason)
            if _os.environ.get("GR_BLOCK_MODE", "enforce").lower() == "audit":
                # LINEAJE: enforce() `data` at agent->user_interface data_egress — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.); AI_APP_SEC_035 (Agents must log all interactions with an LLM). Mask/block; do not remove without review. site_id='site:sha256:88f4ac56231880c83f511de4cc5809dd5dd5239aaa800cf66892692199d88e08'
                _gr_client = _lineaje_load_gr_client()
                _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:88f4ac56231880c83f511de4cc5809dd5dd5239aaa800cf66892692199d88e08', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface')
                try:
                    data = _gr_client.enforce(_gr_site, data, content_type='text/plain')
                except _gr_client.GuardrailUnavailableError:
                    pass
                except PermissionError:
                    pass
                return data
            gr_check._blocked = (policy_id, reason)
            raise GRBlockedError(policy_id, reason)
        # LINEAJE: enforce() `hop_label` at agent->log log_emit — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.); AI_APP_SEC_035 (Agents must log all interactions with an LLM). Mask/block; do not remove without review. site_id='site:sha256:beed4a05b1515afc88250c212a106a041f4f6c7732e4b90263ff951a7672efd5'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:beed4a05b1515afc88250c212a106a041f4f6c7732e4b90263ff951a7672efd5', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log')
        try:
            hop_label = _gr_client.enforce(_gr_site, hop_label, content_type='application/json')
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass
        _log.warning("gr_client[%s]: GR service call failed (%s) — failing open", hop_label, exc)
        # LINEAJE: enforce() `data` at agent->user_interface data_egress — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.); AI_APP_SEC_035 (Agents must log all interactions with an LLM). Mask/block; do not remove without review. site_id='site:sha256:d56ef148d49b622b1ba30384d874747a879dc2bff8edc84fcb605faf6c01e2b5'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:d56ef148d49b622b1ba30384d874747a879dc2bff8edc84fcb605faf6c01e2b5', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface')
        try:
            data = _gr_client.enforce(_gr_site, data, content_type='text/plain')
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass
        return data
    if result.get("status") == "escalate":
        # LINEAJE: enforce() `hop_label` at agent->log log_emit — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.); AI_APP_SEC_035 (Agents must log all interactions with an LLM). Mask/block; do not remove without review. site_id='site:sha256:042f430869c164aa3558069ffc791eae37e5d27b16e3c10cce1a59aecf42f883'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:042f430869c164aa3558069ffc791eae37e5d27b16e3c10cce1a59aecf42f883', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log')
        try:
            hop_label = _gr_client.enforce(_gr_site, hop_label, content_type='application/json')
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass
        _log.warning("gr_client[%s]: escalation flagged — passing through for human review", hop_label)
    if not isinstance(result.get("result"), dict) or "data" not in result["result"]:
        # LINEAJE: enforce() `data` at agent->user_interface data_egress — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.); AI_APP_SEC_035 (Agents must log all interactions with an LLM). Mask/block; do not remove without review. site_id='site:sha256:4d4cb3cd41ef6eabf79be15bcdc891503660999ceadc7f57468988ffb0d3e156'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:4d4cb3cd41ef6eabf79be15bcdc891503660999ceadc7f57468988ffb0d3e156', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface')
        try:
            data = _gr_client.enforce(_gr_site, data, content_type='text/plain')
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass
        return data
    return _gr_back(data, result["result"]["data"])
import asyncio
import json
from uuid import uuid4

from langchain_core.embeddings import DeterministicFakeEmbedding
from langchain_core.messages.ai import AIMessageChunk
from langchain_core.vectorstores import InMemoryVectorStore
from quivr_core.rag.entities.chat import ChatHistory
from quivr_core.rag.entities.config import LLMEndpointConfig, RetrievalConfig
from quivr_core.llm import LLMEndpoint
from quivr_core.rag.quivr_rag_langgraph import QuivrQARAGLangGraph


async def main():
    retrieval_config = RetrievalConfig(llm_config=LLMEndpointConfig(model="gpt-4o"))
    embedder = DeterministicFakeEmbedding(size=20)
    vec = InMemoryVectorStore(embedder)

    llm = LLMEndpoint.from_config(retrieval_config.llm_config)
    chat_history = ChatHistory(uuid4(), uuid4())
    rag_pipeline = QuivrQARAGLangGraph(
        retrieval_config=retrieval_config, llm=llm, vector_store=vec
    )

    conversational_qa_chain = rag_pipeline.build_chain()

    with open("response.jsonl", "w") as f:
        async for event in conversational_qa_chain.astream_events(
            {
                "messages": [
                    ("user", "What is NLP, give a very long detailed answer"),
                ],
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
                try:
                    import asyncio as _gr_asyncio
                    dict_chunk = await _gr_asyncio.to_thread(gr_check, dict_chunk, "agent", "external", candidate_policies=['AI_APP_SEC_006', 'AI_APP_SEC_035'], site_id='site:sha256:5c68389e092835bfceae8e47f5bc611a1349443c14c403a6dc79dca9fb96a8d8')
                except Exception as _gr_exc:
                    if type(_gr_exc).__name__ == "GRBlockedError": raise
                    dict_chunk = dict_chunk
                    __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->external' — passing data through unchecked")
                try:
                    import asyncio as _gr_asyncio
                    dict_chunk = await _gr_asyncio.to_thread(gr_check, dict_chunk, "agent", "external", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_076', 'AI_APP_SEC_078', 'AI_APP_SEC_079', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_DAT_SEC_039', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_027', 'AI_VULN_SEC_002', 'AI_VULN_SEC_005', 'AI_VULN_SEC_006', 'AI_VULN_SEC_007'], site_id='site:sha256:50e5ce2465b6022042bfddcded02e980d51e17614eab4c66eab6d1d9018eddd1')
                except Exception as _gr_exc:
                    if type(_gr_exc).__name__ == "GRBlockedError": raise
                    dict_chunk = dict_chunk
                    __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->external' — passing data through unchecked")
                f.write(json.dumps(dict_chunk) + "\n")


asyncio.run(main())
