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
        try:
            hop_label = gr_check(hop_label, "agent", "log", candidate_policies=['AI_APP_SEC_006'], site_id='site:sha256:ce0a5d67faa061211d5942fecd18662c099e0ca33973a604b09acc4af56ed02c')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            hop_label = hop_label
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
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
        try:
            hop_label = gr_check(hop_label, "agent", "log", candidate_policies=['AI_APP_SEC_006'], site_id='site:sha256:819b2a6077ea67d7e2eb026fb36c7eaacbe18908cfbed6c9a3f656d1f72cfe5d')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            hop_label = hop_label
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
        _log.warning("gr_client[%s]: quarantined skill (*.blocked) — not loaded, GR not called", hop_label)
        gr_check._blocked = ("blocked_manifest", "quarantined skill must not be read, downloaded, or loaded")
        raise GRBlockedError("blocked_manifest", "quarantined skill must not be read, downloaded, or loaded")
    url = _os.environ.get("GR_SERVICE_URL", "")
    if not url:
        try:
            data = gr_check(data, "agent", "user_interface", candidate_policies=['AI_APP_SEC_006', 'AI_APP_SEC_035'], site_id='site:sha256:6d45d90394bfb8f1bed5ffc9afbbfde265b5d31036ffd598e2c4367c426aa456')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            data = data
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
        return data
    tid = tenant_id or _os.environ.get("GR_TENANT_ID", "")
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
            try:
                orig = gr_check(orig, "agent", "user_interface", candidate_policies=['AI_APP_SEC_006'], site_id='site:sha256:1529ba327a73c51a7514fe1599dd802d12b70131afe4ad9d5c5ed385610999e5')
            except Exception as _gr_exc:
                if type(_gr_exc).__name__ == "GRBlockedError": raise
                orig = orig
                __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
            try:
                orig = gr_check(orig, "agent", "user_interface", candidate_policies=['AI_APP_SEC_006', 'AI_APP_SEC_035'], site_id='site:sha256:a5958cd50dd880d3f9163c1c7faad8648f509706dae4b2d4666d411f38505b07')
            except Exception as _gr_exc:
                if type(_gr_exc).__name__ == "GRBlockedError": raise
                orig = orig
                __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
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
            try:
                _c = gr_check(_c, "agent", "user_interface", candidate_policies=['AI_APP_SEC_006'], site_id='site:sha256:c9b24609160e71ede8def9185e678c35ba10a1767dfa2152f83933c08c59726e')
            except Exception as _gr_exc:
                if type(_gr_exc).__name__ == "GRBlockedError": raise
                _c = _c
                __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
            try:
                _c = gr_check(_c, "agent", "user_interface", candidate_policies=['AI_APP_SEC_006', 'AI_APP_SEC_035'], site_id='site:sha256:a5958cd50dd880d3f9163c1c7faad8648f509706dae4b2d4666d411f38505b07')
            except Exception as _gr_exc:
                if type(_gr_exc).__name__ == "GRBlockedError": raise
                _c = _c
                __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
            return _c
        if orig is None or isinstance(orig, (str, int, float, bool, dict, list)):
            try:
                new = gr_check(new, "agent", "user_interface", candidate_policies=['AI_APP_SEC_006'], site_id='site:sha256:c9b24609160e71ede8def9185e678c35ba10a1767dfa2152f83933c08c59726e')
            except Exception as _gr_exc:
                if type(_gr_exc).__name__ == "GRBlockedError": raise
                new = new
                __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
            try:
                new = gr_check(new, "agent", "user_interface", candidate_policies=['AI_APP_SEC_006', 'AI_APP_SEC_035'], site_id='site:sha256:a5958cd50dd880d3f9163c1c7faad8648f509706dae4b2d4666d411f38505b07')
            except Exception as _gr_exc:
                if type(_gr_exc).__name__ == "GRBlockedError": raise
                new = new
                __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
            return new
        _log.warning("gr_client[%s]: masked result cannot be applied to %s — returning original", hop_label, type(orig).__name__)
        try:
            orig = gr_check(orig, "agent", "user_interface", candidate_policies=['AI_APP_SEC_006'], site_id='site:sha256:c9b24609160e71ede8def9185e678c35ba10a1767dfa2152f83933c08c59726e')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            orig = orig
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
        try:
            orig = gr_check(orig, "agent", "user_interface", candidate_policies=['AI_APP_SEC_006', 'AI_APP_SEC_035'], site_id='site:sha256:a5958cd50dd880d3f9163c1c7faad8648f509706dae4b2d4666d411f38505b07')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            orig = orig
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
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
            try:
                hop_label = gr_check(hop_label, "agent", "log", candidate_policies=['AI_APP_SEC_006'], site_id='site:sha256:e9fc99a9ec885e3bd0352af0c9cebaf73f3e7081aa8910b3166f93dc12e8b53e')
            except Exception as _gr_exc:
                if type(_gr_exc).__name__ == "GRBlockedError": raise
                hop_label = hop_label
                __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
            _log.warning("gr_client[%s]: BLOCKED by policy=%s — %s", hop_label, policy_id, reason)
            if _os.environ.get("GR_BLOCK_MODE", "enforce").lower() == "audit":
                try:
                    data = gr_check(data, "agent", "user_interface", candidate_policies=['AI_APP_SEC_006'], site_id='site:sha256:c9b24609160e71ede8def9185e678c35ba10a1767dfa2152f83933c08c59726e')
                except Exception as _gr_exc:
                    if type(_gr_exc).__name__ == "GRBlockedError": raise
                    data = data
                    __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
                try:
                    data = gr_check(data, "agent", "user_interface", candidate_policies=['AI_APP_SEC_006', 'AI_APP_SEC_035'], site_id='site:sha256:a5958cd50dd880d3f9163c1c7faad8648f509706dae4b2d4666d411f38505b07')
                except Exception as _gr_exc:
                    if type(_gr_exc).__name__ == "GRBlockedError": raise
                    data = data
                    __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
                return data
            gr_check._blocked = (policy_id, reason)
            raise GRBlockedError(policy_id, reason)
        _log.warning("gr_client[%s]: GR service call failed (%s) — failing open", hop_label, exc)
        try:
            data = gr_check(data, "agent", "user_interface", candidate_policies=['AI_APP_SEC_006'], site_id='site:sha256:6d45d90394bfb8f1bed5ffc9afbbfde265b5d31036ffd598e2c4367c426aa456')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            data = data
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
        return data
    if result.get("status") == "escalate":
        try:
            hop_label = gr_check(hop_label, "agent", "log", candidate_policies=['AI_APP_SEC_006'], site_id='site:sha256:c128add1d51788e140a7a60ae3370585856ba93fa0abd4cef35a3152341bfe3d')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            hop_label = hop_label
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
        _log.warning("gr_client[%s]: escalation flagged — passing through for human review", hop_label)
    if not isinstance(result.get("result"), dict) or "data" not in result["result"]:
        try:
            data = gr_check(data, "agent", "user_interface", candidate_policies=['AI_APP_SEC_006'], site_id='site:sha256:c9b24609160e71ede8def9185e678c35ba10a1767dfa2152f83933c08c59726e')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            data = data
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
        try:
            data = gr_check(data, "agent", "user_interface", candidate_policies=['AI_APP_SEC_006', 'AI_APP_SEC_035'], site_id='site:sha256:a5958cd50dd880d3f9163c1c7faad8648f509706dae4b2d4666d411f38505b07')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            data = data
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
        return data
    return _gr_back(data, result["result"]["data"])
import logging
import os
from typing import AsyncIterable

import httpx
import tiktoken
from langchain_core.documents import Document
from langchain_text_splitters import RecursiveCharacterTextSplitter, TextSplitter

from quivr_core.files.file import QuivrFile
from quivr_core.processor.processor_base import ProcessedDocument, ProcessorBase
from quivr_core.processor.registry import FileExtension
from quivr_core.processor.splitter import SplitterConfig

logger = logging.getLogger("quivr_core")


class TikaProcessor(ProcessorBase):
    """
    TikaProcessor is a class that implements the ProcessorBase interface.
    It is used to process the files with the Tika server.

    To run it with docker you can do:
    ```bash
    docker run -d -p 9998:9998 apache/tika
    ```
    """

    supported_extensions = [FileExtension.pdf]

    def __init__(
        self,
        tika_url: str = os.getenv("TIKA_SERVER_URL", "http://localhost:9998/tika"),
        splitter: TextSplitter | None = None,
        splitter_config: SplitterConfig = SplitterConfig(),
        timeout: float = 5.0,
        max_retries: int = 3,
    ) -> None:
        self.tika_url = tika_url
        self.max_retries = max_retries
        self._client = httpx.AsyncClient(timeout=timeout)

        self.enc = tiktoken.get_encoding("cl100k_base")
        self.splitter_config = splitter_config

        if splitter:
            self.text_splitter = splitter
        else:
            self.text_splitter = RecursiveCharacterTextSplitter.from_tiktoken_encoder(
                chunk_size=splitter_config.chunk_size,
                chunk_overlap=splitter_config.chunk_overlap,
            )

    async def _send_parse_tika(self, f: AsyncIterable[bytes]) -> str:
        retry = 0
        headers = {"Accept": "text/plain"}
        while retry < self.max_retries:
            try:
                resp = await self._client.put(self.tika_url, headers=headers, content=f)
                try:
                    import asyncio as _gr_asyncio
                    resp = await _gr_asyncio.to_thread(gr_check, resp, "api", "agent", site_id='site:sha256:4b831e98cf2fe5db3bbeac68440e0b35a72bcfce54e2546662bd648247e58c98')
                except Exception as _gr_exc:
                    if type(_gr_exc).__name__ == "GRBlockedError": raise
                    resp = resp
                    __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'api->agent' — passing data through unchecked")
                resp.raise_for_status()
                return resp.content.decode("utf-8")
            except Exception as e:
                retry += 1
                _lineaje_payload = f"tika url error :{e}. retrying for the {retry} time..."
                try:
                    import asyncio as _gr_asyncio
                    _lineaje_payload = await _gr_asyncio.to_thread(gr_check, _lineaje_payload, "agent", "log", site_id='site:sha256:e3278ed8e92ec19109ebb88abd25cf53e9a09b1aa296607cf60a51ff95bec7c4')
                except Exception as _gr_exc:
                    if type(_gr_exc).__name__ == "GRBlockedError": raise
                    _lineaje_payload = _lineaje_payload
                    __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
                _lineaje_payload_182 = f"tika url error :{e}. retrying for the {retry} time..."
                try:
                    import asyncio as _gr_asyncio
                    _lineaje_payload_182 = await _gr_asyncio.to_thread(gr_check, _lineaje_payload_182, "agent", "log", candidate_policies=['AI_APP_SEC_006'], site_id='site:sha256:c102682e5b02c05de0d0f9bee9218ef1a8e2d012873b444bb204e3af80711abf')
                except Exception as _gr_exc:
                    if type(_gr_exc).__name__ == "GRBlockedError": raise
                    _lineaje_payload_182 = _lineaje_payload_182
                    __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
                _lineaje_payload_256 = f"tika url error :{e}. retrying for the {retry} time..."
                try:
                    import asyncio as _gr_asyncio
                    _lineaje_payload_256 = await _gr_asyncio.to_thread(gr_check, _lineaje_payload_256, "agent", "log", candidate_policies=['AI_APP_SEC_006', 'AI_APP_SEC_035'], site_id='site:sha256:c102682e5b02c05de0d0f9bee9218ef1a8e2d012873b444bb204e3af80711abf')
                except Exception as _gr_exc:
                    if type(_gr_exc).__name__ == "GRBlockedError": raise
                    _lineaje_payload_256 = _lineaje_payload_256
                    __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
                logger.debug(f"tika url error :{e}. retrying for the {retry} time...")
        raise RuntimeError("can't send parse request to tika server")

    @property
    def processor_metadata(self):
        return {
            "chunk_overlap": self.splitter_config.chunk_overlap,
        }

    async def process_file_inner(self, file: QuivrFile) -> ProcessedDocument[None]:
        async with file.open() as f:
            txt = await self._send_parse_tika(f)
        document = Document(page_content=txt)
        _lineaje_payload = [document]
        try:
            import asyncio as _gr_asyncio
            _lineaje_payload = await _gr_asyncio.to_thread(gr_check, _lineaje_payload, "rag_source", "rag_pipeline", site_id='site:sha256:4e8c14e61065c77f2c38f662eb118dfaadd5912ae64c1e97d453f884442b8029')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            _lineaje_payload = _lineaje_payload
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'rag_source->rag_pipeline' — passing data through unchecked")
        _lineaje_payload_203 = [document]
        try:
            import asyncio as _gr_asyncio
            _lineaje_payload_203 = await _gr_asyncio.to_thread(gr_check, _lineaje_payload_203, "rag_source", "rag_pipeline", site_id='site:sha256:b8fc2a1e9349485fa81a714a2a7b7494de5f933a607fcced4c8eac5fec8963f8')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            _lineaje_payload_203 = _lineaje_payload_203
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'rag_source->rag_pipeline' — passing data through unchecked")
        _lineaje_payload_285 = [document]
        try:
            import asyncio as _gr_asyncio
            _lineaje_payload_285 = await _gr_asyncio.to_thread(gr_check, _lineaje_payload_285, "rag_source", "rag_pipeline", site_id='site:sha256:b8fc2a1e9349485fa81a714a2a7b7494de5f933a607fcced4c8eac5fec8963f8')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            _lineaje_payload_285 = _lineaje_payload_285
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'rag_source->rag_pipeline' — passing data through unchecked")
        docs = self.text_splitter.split_documents([document])
        for doc in docs:
            doc.metadata = {"chunk_size": len(self.enc.encode(doc.page_content))}

        return ProcessedDocument(
            chunks=docs, processor_cls="TikaProcessor", processor_response=None
        )
