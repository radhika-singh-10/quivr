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
        # LINEAJE: enforce() `hop_label` at agent->log log_emit — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.); AI_DAT_SEC_023 (Redact PII from uploaded files.). Mask/block; do not remove without review. site_id='site:sha256:24b4da870ee4f761caa073f7bbdc2fa28794c5c3e76437d1d3839ece870a94b4'
        # APPROVED MODELS ONLY: Replace any reference to GPT, Claude, LLaMA, Mistral, DeepSeek, Gemini, o3-mini, o4-mini, o1-mini, o1-preview, o1, codestral, code-llama with an approved model from the organization registry before use.
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:24b4da870ee4f761caa073f7bbdc2fa28794c5c3e76437d1d3839ece870a94b4', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_006', 'guardrail_id': 'Approved LLM Registry', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log')
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
        # LINEAJE: enforce() `hop_label` at agent->log log_emit — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.); AI_DAT_SEC_023 (Redact PII from uploaded files.). Mask/block; do not remove without review. site_id='site:sha256:788c32352c0f760a95e6dafbf46e822ef38ad4db416d67dde98bdfce9196d944'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:788c32352c0f760a95e6dafbf46e822ef38ad4db416d67dde98bdfce9196d944', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log')
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
        # LINEAJE: enforce() `data` at agent->user_interface data_egress — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.); AI_DAT_SEC_023 (Redact PII from uploaded files.). Mask/block; do not remove without review. site_id='site:sha256:8a7db22d05addd540f90a1fa67009452d721f11b053f35a79a2518546f6937bc'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:8a7db22d05addd540f90a1fa67009452d721f11b053f35a79a2518546f6937bc', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface')
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
            # LINEAJE: enforce() `orig` at agent->user_interface data_egress — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.); AI_DAT_SEC_023 (Redact PII from uploaded files.). Mask/block; do not remove without review. site_id='site:sha256:ac5576aae62beff3dc2955884510187b2d0f8b11fff1f84675f579d42920c349'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:ac5576aae62beff3dc2955884510187b2d0f8b11fff1f84675f579d42920c349', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface')
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
            # LINEAJE: enforce() `_c` at agent->user_interface data_egress — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.); AI_DAT_SEC_023 (Redact PII from uploaded files.). Mask/block; do not remove without review. site_id='site:sha256:b77d3328f5588221cf343bc9836add1a1a74f3eeadd865f5cbf3a5620178e71e'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:b77d3328f5588221cf343bc9836add1a1a74f3eeadd865f5cbf3a5620178e71e', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface')
            try:
                _c = _gr_client.enforce(_gr_site, _c, content_type='text/plain')
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                pass
            return _c
        if orig is None or isinstance(orig, (str, int, float, bool, dict, list)):
            # LINEAJE: enforce() `new` at agent->user_interface data_egress — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.); AI_DAT_SEC_023 (Redact PII from uploaded files.). Mask/block; do not remove without review. site_id='site:sha256:e1041ed4690e1c6b3f4e9bb29924966e4ac2ffe7f475aab28c12a65d98102704'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:e1041ed4690e1c6b3f4e9bb29924966e4ac2ffe7f475aab28c12a65d98102704', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface')
            try:
                new = _gr_client.enforce(_gr_site, new, content_type='text/plain')
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                pass
            return new
        _log.warning("gr_client[%s]: masked result cannot be applied to %s — returning original", hop_label, type(orig).__name__)
        # LINEAJE: enforce() `orig` at agent->user_interface data_egress — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.); AI_DAT_SEC_023 (Redact PII from uploaded files.). Mask/block; do not remove without review. site_id='site:sha256:705a7551bc7dc8b48b1cb4bf737d65585880d8ce39d8fe02cf9e9b9c626eb6f9'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:705a7551bc7dc8b48b1cb4bf737d65585880d8ce39d8fe02cf9e9b9c626eb6f9', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface')
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
            # LINEAJE: enforce() `hop_label` at agent->log log_emit — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.); AI_DAT_SEC_023 (Redact PII from uploaded files.). Mask/block; do not remove without review. site_id='site:sha256:6366c51c5576dde299c69dda2de7b0afcd03d0fd50234d1e516f26d6c77ee3c1'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:6366c51c5576dde299c69dda2de7b0afcd03d0fd50234d1e516f26d6c77ee3c1', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log')
            try:
                hop_label = _gr_client.enforce(_gr_site, hop_label, content_type='application/json')
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                pass
            _log.warning("gr_client[%s]: BLOCKED by policy=%s — %s", hop_label, policy_id, reason)
            if _os.environ.get("GR_BLOCK_MODE", "enforce").lower() == "audit":
                # LINEAJE: enforce() `data` at agent->user_interface data_egress — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.); AI_DAT_SEC_023 (Redact PII from uploaded files.). Mask/block; do not remove without review. site_id='site:sha256:b7aa7a909f8c8828f7d675e291b94c0697f5a5c5e3e4608ec7deb552e7e31414'
                _gr_client = _lineaje_load_gr_client()
                _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:b7aa7a909f8c8828f7d675e291b94c0697f5a5c5e3e4608ec7deb552e7e31414', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface')
                try:
                    data = _gr_client.enforce(_gr_site, data, content_type='text/plain')
                except _gr_client.GuardrailUnavailableError:
                    pass
                except PermissionError:
                    pass
                return data
            gr_check._blocked = (policy_id, reason)
            raise GRBlockedError(policy_id, reason)
        # LINEAJE: enforce() `hop_label` at agent->log log_emit — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.); AI_DAT_SEC_023 (Redact PII from uploaded files.). Mask/block; do not remove without review. site_id='site:sha256:7aad79c6803316bdb7edf9cab950d581d87d8e0cbdfb068f0de90f2e4cf25fe6'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:7aad79c6803316bdb7edf9cab950d581d87d8e0cbdfb068f0de90f2e4cf25fe6', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log')
        try:
            hop_label = _gr_client.enforce(_gr_site, hop_label, content_type='application/json')
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass
        _log.warning("gr_client[%s]: GR service call failed (%s) — failing open", hop_label, exc)
        # LINEAJE: enforce() `data` at agent->user_interface data_egress — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.); AI_DAT_SEC_023 (Redact PII from uploaded files.). Mask/block; do not remove without review. site_id='site:sha256:9e77092c6af271d49bf566a9fe33147eed687d648c7f3c24c9ed27039865384d'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:9e77092c6af271d49bf566a9fe33147eed687d648c7f3c24c9ed27039865384d', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface')
        try:
            data = _gr_client.enforce(_gr_site, data, content_type='text/plain')
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass
        return data
    if result.get("status") == "escalate":
        # LINEAJE: enforce() `hop_label` at agent->log log_emit — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.); AI_DAT_SEC_023 (Redact PII from uploaded files.). Mask/block; do not remove without review. site_id='site:sha256:580bcb70631de970f2e2d918b77d102593fdd4bb50da38ce719802d2c9ccb48b'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:580bcb70631de970f2e2d918b77d102593fdd4bb50da38ce719802d2c9ccb48b', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log')
        try:
            hop_label = _gr_client.enforce(_gr_site, hop_label, content_type='application/json')
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass
        _log.warning("gr_client[%s]: escalation flagged — passing through for human review", hop_label)
    if not isinstance(result.get("result"), dict) or "data" not in result["result"]:
        # LINEAJE: enforce() `data` at agent->user_interface data_egress — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.); AI_DAT_SEC_023 (Redact PII from uploaded files.). Mask/block; do not remove without review. site_id='site:sha256:fe93c605450bbd8f1436d619075ab68690d3dee9367d806ad28c0ff8e7aca304'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:fe93c605450bbd8f1436d619075ab68690d3dee9367d806ad28c0ff8e7aca304', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface')
        try:
            data = _gr_client.enforce(_gr_site, data, content_type='text/plain')
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass
        return data
    return _gr_back(data, result["result"]["data"])
import logging
from typing import Any, List, Type, TypeVar

import tiktoken
from langchain_community.document_loaders import (
    BibtexLoader,
    CSVLoader,
    Docx2txtLoader,
    NotebookLoader,
    PythonLoader,
    UnstructuredEPubLoader,
    UnstructuredExcelLoader,
    UnstructuredHTMLLoader,
    UnstructuredMarkdownLoader,
    UnstructuredODTLoader,
    UnstructuredPDFLoader,
    UnstructuredPowerPointLoader,
)
from langchain_community.document_loaders.base import BaseLoader
from langchain_community.document_loaders.text import TextLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter, TextSplitter

from quivr_core.files.file import FileExtension, QuivrFile
from quivr_core.processor.processor_base import ProcessedDocument, ProcessorBase
from quivr_core.processor.splitter import SplitterConfig

logger = logging.getLogger("quivr_core")

P = TypeVar("P", bound=BaseLoader)


class ProcessorInit(ProcessorBase):
    def __init__(self, *args, **loader_kwargs) -> None:
        pass


# FIXME(@aminediro):
# dynamically creates Processor classes. Maybe redo this for finer control over instanciation
# processor classes are opaque as we don't know what params they would have -> not easy to have lsp completion
def _build_processor(
    cls_name: str, load_cls: Type[P], cls_extensions: List[FileExtension | str]
) -> Type[ProcessorInit]:
    enc = tiktoken.get_encoding("cl100k_base")

    class _Processor(ProcessorBase):
        supported_extensions = cls_extensions

        def __init__(
            self,
            splitter: TextSplitter | None = None,
            splitter_config: SplitterConfig = SplitterConfig(),
            **loader_kwargs: dict[str, Any],
        ) -> None:
            self.loader_cls = load_cls
            self.loader_kwargs = loader_kwargs

            self.splitter_config = splitter_config

            if splitter:
                self.text_splitter = splitter
            else:
                self.text_splitter = (
                    RecursiveCharacterTextSplitter.from_tiktoken_encoder(
                        chunk_size=splitter_config.chunk_size,
                        chunk_overlap=splitter_config.chunk_overlap,
                    )
                )

        @property
        def processor_metadata(self) -> dict[str, Any]:
            return {
                "processor_cls": self.loader_cls.__name__,
                "splitter": self.splitter_config.model_dump(),
            }

        async def process_file_inner(self, file: QuivrFile) -> ProcessedDocument[None]:
            if hasattr(self.loader_cls, "__init__"):
                # NOTE: mypy can't correctly type this as BaseLoader doesn't have a constructor method
                loader = self.loader_cls(file_path=str(file.path), **self.loader_kwargs)  # type: ignore
            else:
                loader = self.loader_cls()

            documents = await loader.aload()
            try:
                import asyncio as _gr_asyncio
                documents = await _gr_asyncio.to_thread(gr_check, documents, "data_source", "rag_pipeline", site_id='site:sha256:a5f887ffe4da94aa65d3319ab85bdaa8200d18c4c01e32584dc8ad2b74ee95f2')
            except Exception as _gr_exc:
                if type(_gr_exc).__name__ == "GRBlockedError": raise
                documents = documents
                __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'data_source->rag_pipeline' — passing data through unchecked")
            try:
                import asyncio as _gr_asyncio
                documents = await _gr_asyncio.to_thread(gr_check, documents, "rag_source", "rag_pipeline", site_id='site:sha256:a5617df644ac78b4dab04687a216e2f9102f871c8b553f2e65bf8e2b8438b71a')
            except Exception as _gr_exc:
                if type(_gr_exc).__name__ == "GRBlockedError": raise
                documents = documents
                __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'rag_source->rag_pipeline' — passing data through unchecked")
            try:
                import asyncio as _gr_asyncio
                documents = await _gr_asyncio.to_thread(gr_check, documents, "rag_source", "rag_pipeline", site_id='site:sha256:098f1f959e736f7630953b43c578bb34f8497b78efccff7455a093a9f133db38')
            except Exception as _gr_exc:
                if type(_gr_exc).__name__ == "GRBlockedError": raise
                documents = documents
                __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'rag_source->rag_pipeline' — passing data through unchecked")
            docs = self.text_splitter.split_documents(documents)

            for doc in docs:
                # TODO: This metadata info should be typed
                doc.metadata = {"chunk_size": len(enc.encode(doc.page_content))}

            return ProcessedDocument(
                chunks=docs, processor_cls=cls_name, processor_response=None
            )

    return type(cls_name, (ProcessorInit,), dict(_Processor.__dict__))


CSVProcessor = _build_processor("CSVProcessor", CSVLoader, [FileExtension.csv])
TikTokenTxtProcessor = _build_processor(
    "TikTokenTxtProcessor", TextLoader, [FileExtension.txt]
)
DOCXProcessor = _build_processor(
    "DOCXProcessor", Docx2txtLoader, [FileExtension.docx, FileExtension.doc]
)
XLSXProcessor = _build_processor(
    "XLSXProcessor", UnstructuredExcelLoader, [FileExtension.xlsx, FileExtension.xls]
)
PPTProcessor = _build_processor(
    "PPTProcessor", UnstructuredPowerPointLoader, [FileExtension.pptx]
)
MarkdownProcessor = _build_processor(
    "MarkdownProcessor",
    UnstructuredMarkdownLoader,
    [FileExtension.md, FileExtension.mdx, FileExtension.markdown],
)
EpubProcessor = _build_processor(
    "EpubProcessor", UnstructuredEPubLoader, [FileExtension.epub]
)
BibTexProcessor = _build_processor("BibTexProcessor", BibtexLoader, [FileExtension.bib])
ODTProcessor = _build_processor(
    "ODTProcessor", UnstructuredODTLoader, [FileExtension.odt]
)
HTMLProcessor = _build_processor(
    "HTMLProcessor", UnstructuredHTMLLoader, [FileExtension.html]
)
PythonProcessor = _build_processor("PythonProcessor", PythonLoader, [FileExtension.py])
NotebookProcessor = _build_processor(
    "NotebookProcessor", NotebookLoader, [FileExtension.ipynb]
)
UnstructuredPDFProcessor = _build_processor(
    "UnstructuredPDFProcessor", UnstructuredPDFLoader, [FileExtension.pdf]
)
