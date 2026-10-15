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
        # LINEAJE: enforce() `hop_label` at agent->log log_emit — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.). Mask/block; do not remove without review. site_id='site:sha256:ac7e67db3f39495165104cf6ec14cc99fbbae6bb1ce8514a858a5403af929fbc'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:ac7e67db3f39495165104cf6ec14cc99fbbae6bb1ce8514a858a5403af929fbc', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log')
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
        # LINEAJE: enforce() `hop_label` at agent->log log_emit — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.). Mask/block; do not remove without review. site_id='site:sha256:31fc55b1a05887e5cedb318017bbb9699395bce402b273ff1adc97d411450ecc'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:31fc55b1a05887e5cedb318017bbb9699395bce402b273ff1adc97d411450ecc', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log')
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
        # LINEAJE: enforce() `data` at agent->user_interface data_egress — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.). Mask/block; do not remove without review. site_id='site:sha256:786aef84ef91a5d9158afcda6b7e537a7ab872f8722abed8825a70f2f46d7cf6'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:786aef84ef91a5d9158afcda6b7e537a7ab872f8722abed8825a70f2f46d7cf6', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface')
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
            # LINEAJE: enforce() `orig` at agent->user_interface data_egress — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.). Mask/block; do not remove without review. site_id='site:sha256:a986a791b7285fabc65c8fda7b7c20b12ee37c2ebb51e70340074acd66216335'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:a986a791b7285fabc65c8fda7b7c20b12ee37c2ebb51e70340074acd66216335', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface')
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
            # LINEAJE: enforce() `_c` at agent->user_interface data_egress — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.). Mask/block; do not remove without review. site_id='site:sha256:13fd00d4744873aa5baad1303b21fc6d65d95f25822915e3f72f6170aa2839a3'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:13fd00d4744873aa5baad1303b21fc6d65d95f25822915e3f72f6170aa2839a3', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface')
            try:
                _c = _gr_client.enforce(_gr_site, _c, content_type='text/plain')
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                pass
            return _c
        if orig is None or isinstance(orig, (str, int, float, bool, dict, list)):
            # LINEAJE: enforce() `new` at agent->user_interface data_egress — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.). Mask/block; do not remove without review. site_id='site:sha256:bb82e00a5ac8804f659f22f4172caa41e87ffc5eae5da2a01009fa1b7847efc6'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:bb82e00a5ac8804f659f22f4172caa41e87ffc5eae5da2a01009fa1b7847efc6', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface')
            try:
                new = _gr_client.enforce(_gr_site, new, content_type='text/plain')
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                pass
            return new
        _log.warning("gr_client[%s]: masked result cannot be applied to %s — returning original", hop_label, type(orig).__name__)
        # LINEAJE: enforce() `orig` at agent->user_interface data_egress — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.). Mask/block; do not remove without review. site_id='site:sha256:1923bc8925026cc736fcd67bf9b6348124c6ae64bb5c052dc37acef23a3c8cf4'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:1923bc8925026cc736fcd67bf9b6348124c6ae64bb5c052dc37acef23a3c8cf4', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface')
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
            # LINEAJE: enforce() `hop_label` at agent->log log_emit — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.). Mask/block; do not remove without review. site_id='site:sha256:8172aa74b963e1a1cef238cdcd0321790764781c26a0e2ea439ab957b9526349'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:8172aa74b963e1a1cef238cdcd0321790764781c26a0e2ea439ab957b9526349', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log')
            try:
                hop_label = _gr_client.enforce(_gr_site, hop_label, content_type='application/json')
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                pass
            _log.warning("gr_client[%s]: BLOCKED by policy=%s — %s", hop_label, policy_id, reason)
            if _os.environ.get("GR_BLOCK_MODE", "enforce").lower() == "audit":
                # LINEAJE: enforce() `data` at agent->user_interface data_egress — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.). Mask/block; do not remove without review. site_id='site:sha256:5d65343f7dd9c5826d45ff647003bb810b33444d3a5c8aefd78e9bb0a1b75342'
                _gr_client = _lineaje_load_gr_client()
                _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:5d65343f7dd9c5826d45ff647003bb810b33444d3a5c8aefd78e9bb0a1b75342', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface')
                try:
                    data = _gr_client.enforce(_gr_site, data, content_type='text/plain')
                except _gr_client.GuardrailUnavailableError:
                    pass
                except PermissionError:
                    pass
                return data
            gr_check._blocked = (policy_id, reason)
            raise GRBlockedError(policy_id, reason)
        # LINEAJE: enforce() `hop_label` at agent->log log_emit — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.). Mask/block; do not remove without review. site_id='site:sha256:db4a89d59d99fb3bd9667f230cab33e542f4b4ab87974a9e959ca2335b90c889'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:db4a89d59d99fb3bd9667f230cab33e542f4b4ab87974a9e959ca2335b90c889', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log')
        try:
            hop_label = _gr_client.enforce(_gr_site, hop_label, content_type='application/json')
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass
        _log.warning("gr_client[%s]: GR service call failed (%s) — failing open", hop_label, exc)
        # LINEAJE: enforce() `data` at agent->user_interface data_egress — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.). Mask/block; do not remove without review. site_id='site:sha256:8a962d5fffbba0b2fddd0ba32a84004c8cbc234ddc224356007b7bf720392a60'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:8a962d5fffbba0b2fddd0ba32a84004c8cbc234ddc224356007b7bf720392a60', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface')
        try:
            data = _gr_client.enforce(_gr_site, data, content_type='text/plain')
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass
        return data
    if result.get("status") == "escalate":
        # LINEAJE: enforce() `hop_label` at agent->log log_emit — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.). Mask/block; do not remove without review. site_id='site:sha256:04dd7b5ef310cc42266bd705b3844397431ce557c5a42ebe5c66e64ed8345458'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:04dd7b5ef310cc42266bd705b3844397431ce557c5a42ebe5c66e64ed8345458', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log')
        try:
            hop_label = _gr_client.enforce(_gr_site, hop_label, content_type='application/json')
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass
        _log.warning("gr_client[%s]: escalation flagged — passing through for human review", hop_label)
    if not isinstance(result.get("result"), dict) or "data" not in result["result"]:
        # LINEAJE: enforce() `data` at agent->user_interface data_egress — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.). Mask/block; do not remove without review. site_id='site:sha256:b8241d68be8bc3c6e8d77e4bc5162f443aba25fb37820fb42d6079ba0d15d510'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:b8241d68be8bc3c6e8d77e4bc5162f443aba25fb37820fb42d6079ba0d15d510', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface')
        try:
            data = _gr_client.enforce(_gr_site, data, content_type='text/plain')
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass
        return data
    return _gr_back(data, result["result"]["data"])
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
            _lineaje_payload = await _gr_asyncio.to_thread(gr_check, _lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_006'], site_id='site:sha256:ba792bd0925958e73e6ea89d5585d9fc6bf2715b0ee284741ee705e0f40d950d')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            _lineaje_payload = _lineaje_payload
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
        _lineaje_payload_133 = "Using Faiss-CPU as vector store."
        try:
            import asyncio as _gr_asyncio
            _lineaje_payload_133 = await _gr_asyncio.to_thread(gr_check, _lineaje_payload_133, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_076', 'AI_APP_SEC_078', 'AI_APP_SEC_079', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_DAT_SEC_039', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_027', 'AI_IAC_031', 'AI_VULN_SEC_002', 'AI_VULN_SEC_005', 'AI_VULN_SEC_006', 'AI_VULN_SEC_007'], site_id='site:sha256:b8b4fb63de7c417e27be744df03e990399472cbbcad8fcb9a5935d1b1cc6afaf')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            _lineaje_payload_133 = _lineaje_payload_133
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
        logger.debug("Using Faiss-CPU as vector store.")
        # TODO(@aminediro) : embedding call is usually not concurrent for all documents but waits
        if len(docs) > 0:
            vector_db = await FAISS.afrom_documents(documents=docs, embedding=embedder)
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
            _lineaje_payload = gr_check(_lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_006'], site_id='site:sha256:7bd8e5bc4c69956c57ff51b20344d0c95ca79656a45699a275bcd335b7723f93')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            _lineaje_payload = _lineaje_payload
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
        _lineaje_payload_158 = "Loaded OpenAIEmbeddings as default LLM for brain"
        try:
            _lineaje_payload_158 = gr_check(_lineaje_payload_158, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_076', 'AI_APP_SEC_078', 'AI_APP_SEC_079', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_DAT_SEC_039', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_027', 'AI_IAC_031', 'AI_VULN_SEC_002', 'AI_VULN_SEC_005', 'AI_VULN_SEC_006', 'AI_VULN_SEC_007'], site_id='site:sha256:b8b4fb63de7c417e27be744df03e990399472cbbcad8fcb9a5935d1b1cc6afaf')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            _lineaje_payload_158 = _lineaje_payload_158
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
        _lineaje_payload_173 = "Loaded OpenAIEmbeddings as default LLM for brain"
        # LINEAJE: enforce() `_lineaje_payload_173` at agent->log log_emit — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.). Mask/block; do not remove without review. site_id='site:sha256:d71261aab8182e54f1c56398d88c28c287ccb7c6c9ebabfaa1e24fde7c85eb7e'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:d71261aab8182e54f1c56398d88c28c287ccb7c6c9ebabfaa1e24fde7c85eb7e', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log')
        try:
            _lineaje_payload_173 = _gr_client.enforce(_gr_site, _lineaje_payload_173, content_type='application/json')
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass
        logger.debug(_lineaje_payload_173)
        embedder = OpenAIEmbeddings(check_embedding_ctx_length=False)
        return embedder
    except ImportError as e:
        raise ImportError(
            "Please provide a valid Embedder or install quivr-core['base'] package for using the defaultone."
        ) from e


def default_llm() -> LLMEndpoint:
    try:
        _lineaje_payload = "Loaded ChatOpenAI as default LLM for brain"
        try:
            _lineaje_payload = gr_check(_lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_006'], site_id='site:sha256:fc1ca1cbca32e603d83f0e29d694b1a00b4e75224afb48363546d7a2ab13791d')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            _lineaje_payload = _lineaje_payload
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
        _lineaje_payload_176 = "Loaded ChatOpenAI as default LLM for brain"
        try:
            _lineaje_payload_176 = gr_check(_lineaje_payload_176, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_076', 'AI_APP_SEC_078', 'AI_APP_SEC_079', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_DAT_SEC_039', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_027', 'AI_IAC_031', 'AI_VULN_SEC_002', 'AI_VULN_SEC_005', 'AI_VULN_SEC_006', 'AI_VULN_SEC_007'], site_id='site:sha256:b8b4fb63de7c417e27be744df03e990399472cbbcad8fcb9a5935d1b1cc6afaf')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            _lineaje_payload_176 = _lineaje_payload_176
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
        _lineaje_payload_198 = "Loaded ChatOpenAI as default LLM for brain"
        # LINEAJE: enforce() `_lineaje_payload_198` at agent->log log_emit — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.). Mask/block; do not remove without review. site_id='site:sha256:06db89322419e2bca301270370d0ea35a1b8484f6caeaa7ff792a8c57a70eabc'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:06db89322419e2bca301270370d0ea35a1b8484f6caeaa7ff792a8c57a70eabc', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log')
        try:
            _lineaje_payload_198 = _gr_client.enforce(_gr_site, _lineaje_payload_198, content_type='application/json')
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass
        logger.debug(_lineaje_payload_198)
        llm = LLMEndpoint.from_config(
            LLMEndpointConfig(supplier=DefaultModelSuppliers.OPENAI, model="gpt-4o")
        )
        return llm

    except ImportError as e:
        raise ImportError(
            "Please provide a valid BaseLLM or install quivr-core['base'] package"
        ) from e
