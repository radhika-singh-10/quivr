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
            hop_label = gr_check(hop_label, "agent", "log", candidate_policies=['AI_APP_SEC_006', 'AI_APP_SEC_035'], site_id='site:sha256:d99eca1c6adf43258a2ad1fc2ecdaac4f0c024ce75c24185c0082a65a3ee8d3a')
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
            hop_label = gr_check(hop_label, "agent", "log", candidate_policies=['AI_APP_SEC_006', 'AI_APP_SEC_035'], site_id='site:sha256:849ac997027470d853f0012c6d9627324cdb3d974676a5846ef95fcb491344a6')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            hop_label = hop_label
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
        _log.warning("gr_client[%s]: quarantined skill (*.blocked) — not loaded, GR not called", hop_label)
        gr_check._blocked = ("blocked_manifest", "quarantined skill must not be read, downloaded, or loaded")
        raise GRBlockedError("blocked_manifest", "quarantined skill must not be read, downloaded, or loaded")
    url = _os.environ.get("GR_SERVICE_URL", "")
    if not url:
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
                orig = gr_check(orig, "agent", "user_interface", candidate_policies=['AI_APP_SEC_006', 'AI_APP_SEC_035'], site_id='site:sha256:17d0fb9dd02a36ae67da67393e68af9a9443f68b0d09dbeb28f44faa368c5cc5')
            except Exception as _gr_exc:
                if type(_gr_exc).__name__ == "GRBlockedError": raise
                orig = orig
                __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
            try:
                orig = gr_check(orig, "agent", "user_interface", candidate_policies=['AI_APP_SEC_006', 'AI_APP_SEC_035'], site_id='site:sha256:479f90241b6a66df027596ac280c89291ef61bcf9844867d4bcbf60edf2d7eb9')
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
                _c = gr_check(_c, "agent", "user_interface", candidate_policies=['AI_APP_SEC_006', 'AI_APP_SEC_035'], site_id='site:sha256:aa8612957ab84fd94bf110441b10be17e9754ada917c4ca1d221aa7bfc3d2b72')
            except Exception as _gr_exc:
                if type(_gr_exc).__name__ == "GRBlockedError": raise
                _c = _c
                __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
            try:
                _c = gr_check(_c, "agent", "user_interface", candidate_policies=['AI_APP_SEC_006', 'AI_APP_SEC_035'], site_id='site:sha256:479f90241b6a66df027596ac280c89291ef61bcf9844867d4bcbf60edf2d7eb9')
            except Exception as _gr_exc:
                if type(_gr_exc).__name__ == "GRBlockedError": raise
                _c = _c
                __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
            return _c
        if orig is None or isinstance(orig, (str, int, float, bool, dict, list)):
            try:
                new = gr_check(new, "agent", "user_interface", candidate_policies=['AI_APP_SEC_006', 'AI_APP_SEC_035'], site_id='site:sha256:aa8612957ab84fd94bf110441b10be17e9754ada917c4ca1d221aa7bfc3d2b72')
            except Exception as _gr_exc:
                if type(_gr_exc).__name__ == "GRBlockedError": raise
                new = new
                __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
            try:
                new = gr_check(new, "agent", "user_interface", candidate_policies=['AI_APP_SEC_006', 'AI_APP_SEC_035'], site_id='site:sha256:479f90241b6a66df027596ac280c89291ef61bcf9844867d4bcbf60edf2d7eb9')
            except Exception as _gr_exc:
                if type(_gr_exc).__name__ == "GRBlockedError": raise
                new = new
                __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
            return new
        _log.warning("gr_client[%s]: masked result cannot be applied to %s — returning original", hop_label, type(orig).__name__)
        try:
            orig = gr_check(orig, "agent", "user_interface", candidate_policies=['AI_APP_SEC_006', 'AI_APP_SEC_035'], site_id='site:sha256:aa8612957ab84fd94bf110441b10be17e9754ada917c4ca1d221aa7bfc3d2b72')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            orig = orig
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
        try:
            orig = gr_check(orig, "agent", "user_interface", candidate_policies=['AI_APP_SEC_006', 'AI_APP_SEC_035'], site_id='site:sha256:479f90241b6a66df027596ac280c89291ef61bcf9844867d4bcbf60edf2d7eb9')
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
                hop_label = gr_check(hop_label, "agent", "log", candidate_policies=['AI_APP_SEC_006', 'AI_APP_SEC_035'], site_id='site:sha256:5b3179375aa5b433bbf678c6f285f58bbee539f056b1db098f4f40b544370105')
            except Exception as _gr_exc:
                if type(_gr_exc).__name__ == "GRBlockedError": raise
                hop_label = hop_label
                __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
            _log.warning("gr_client[%s]: BLOCKED by policy=%s — %s", hop_label, policy_id, reason)
            if _os.environ.get("GR_BLOCK_MODE", "enforce").lower() == "audit":
                try:
                    data = gr_check(data, "agent", "user_interface", candidate_policies=['AI_APP_SEC_006', 'AI_APP_SEC_035'], site_id='site:sha256:aa8612957ab84fd94bf110441b10be17e9754ada917c4ca1d221aa7bfc3d2b72')
                except Exception as _gr_exc:
                    if type(_gr_exc).__name__ == "GRBlockedError": raise
                    data = data
                    __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
                try:
                    data = gr_check(data, "agent", "user_interface", candidate_policies=['AI_APP_SEC_006', 'AI_APP_SEC_035'], site_id='site:sha256:479f90241b6a66df027596ac280c89291ef61bcf9844867d4bcbf60edf2d7eb9')
                except Exception as _gr_exc:
                    if type(_gr_exc).__name__ == "GRBlockedError": raise
                    data = data
                    __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
                return data
            gr_check._blocked = (policy_id, reason)
            raise GRBlockedError(policy_id, reason)
        _log.warning("gr_client[%s]: GR service call failed (%s) — failing open", hop_label, exc)
        try:
            data = gr_check(data, "agent", "user_interface", candidate_policies=['AI_APP_SEC_006', 'AI_APP_SEC_035'], site_id='site:sha256:ec97dd2b1452f503fe7b1c6e3e7b8c3188a97436d2f8d3c3748797ec2a5ab7ba')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            data = data
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
        return data
    if result.get("status") == "escalate":
        try:
            hop_label = gr_check(hop_label, "agent", "log", candidate_policies=['AI_APP_SEC_006', 'AI_APP_SEC_035'], site_id='site:sha256:3a356eb76f3774302783bb2f2a60670651362f7ac54c7549e56bceec2dbfc2be')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            hop_label = hop_label
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
        _log.warning("gr_client[%s]: escalation flagged — passing through for human review", hop_label)
    if not isinstance(result.get("result"), dict) or "data" not in result["result"]:
        try:
            data = gr_check(data, "agent", "user_interface", candidate_policies=['AI_APP_SEC_006', 'AI_APP_SEC_035'], site_id='site:sha256:aa8612957ab84fd94bf110441b10be17e9754ada917c4ca1d221aa7bfc3d2b72')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            data = data
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
        try:
            data = gr_check(data, "agent", "user_interface", candidate_policies=['AI_APP_SEC_006', 'AI_APP_SEC_035'], site_id='site:sha256:479f90241b6a66df027596ac280c89291ef61bcf9844867d4bcbf60edf2d7eb9')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            data = data
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
        return data
    return _gr_back(data, result["result"]["data"])
import logging

import tiktoken
from langchain_core.documents import Document
from langchain_text_splitters import RecursiveCharacterTextSplitter, TextSplitter
from megaparse_sdk.client import MegaParseNATSClient
from megaparse_sdk.config import ClientNATSConfig
from megaparse_sdk.schema.document import Document as MPDocument

from quivr_core.config import MegaparseConfig
from quivr_core.files.file import QuivrFile
from quivr_core.processor.processor_base import ProcessedDocument, ProcessorBase
from quivr_core.processor.registry import FileExtension
from quivr_core.processor.splitter import SplitterConfig

logger = logging.getLogger("quivr_core")


class MegaparseProcessor(ProcessorBase[MPDocument]):
    """
    Megaparse processor for PDF files.

    It can be used to parse PDF files and split them into chunks.

    It comes from the megaparse library.

    ## Installation
    ```bash
    pip install megaparse
    ```

    """

    supported_extensions = [
        FileExtension.txt,
        FileExtension.pdf,
        FileExtension.docx,
        FileExtension.doc,
        FileExtension.pptx,
        FileExtension.xls,
        FileExtension.xlsx,
        FileExtension.csv,
        FileExtension.epub,
        FileExtension.bib,
        FileExtension.odt,
        FileExtension.html,
        FileExtension.markdown,
        FileExtension.md,
        FileExtension.mdx,
    ]

    def __init__(
        self,
        splitter: TextSplitter | None = None,
        splitter_config: SplitterConfig = SplitterConfig(),
        megaparse_config: MegaparseConfig = MegaparseConfig(),
    ) -> None:
        self.enc = tiktoken.get_encoding("cl100k_base")
        self.splitter_config = splitter_config
        self.megaparse_config = megaparse_config

        if splitter:
            self.text_splitter = splitter
        else:
            self.text_splitter = RecursiveCharacterTextSplitter.from_tiktoken_encoder(
                chunk_size=splitter_config.chunk_size,
                chunk_overlap=splitter_config.chunk_overlap,
            )

    @property
    def processor_metadata(self):
        return {
            "chunk_overlap": self.splitter_config.chunk_overlap,
        }

    async def process_file_inner(
        self, file: QuivrFile
    ) -> ProcessedDocument[MPDocument | str]:
        _lineaje_payload = f"Uploading file {file.path} to MegaParse"
        try:
            import asyncio as _gr_asyncio
            _lineaje_payload = await _gr_asyncio.to_thread(gr_check, _lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_006', 'AI_APP_SEC_035'], site_id='site:sha256:2866654916370240f89772d3332c5a3dd011848da7885cdd92d0d6de0a79a480')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            _lineaje_payload = _lineaje_payload
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
        _lineaje_payload_190 = f"Uploading file {file.path} to MegaParse"
        try:
            import asyncio as _gr_asyncio
            _lineaje_payload_190 = await _gr_asyncio.to_thread(gr_check, _lineaje_payload_190, "agent", "log", candidate_policies=['AI_APP_SEC_006', 'AI_APP_SEC_035'], site_id='site:sha256:00084c6336769e6e3b4190ec2dd4656b187f50270c07ae022479802a1a92865c')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            _lineaje_payload_190 = _lineaje_payload_190
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
        _lineaje_payload_264 = f"Uploading file {file.path} to MegaParse"
        try:
            import asyncio as _gr_asyncio
            _lineaje_payload_264 = await _gr_asyncio.to_thread(gr_check, _lineaje_payload_264, "agent", "log", candidate_policies=['AI_APP_SEC_006', 'AI_APP_SEC_035'], site_id='site:sha256:00084c6336769e6e3b4190ec2dd4656b187f50270c07ae022479802a1a92865c')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            _lineaje_payload_264 = _lineaje_payload_264
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
        logger.info(f"Uploading file {file.path} to MegaParse")
        async with MegaParseNATSClient(ClientNATSConfig()) as client:
            response = await client.parse_file(file=file.path)

        document = Document(
            page_content=str(response),
        )

        _lineaje_payload = [document]
        try:
            import asyncio as _gr_asyncio
            _lineaje_payload = await _gr_asyncio.to_thread(gr_check, _lineaje_payload, "rag_source", "rag_pipeline", site_id='site:sha256:e000d86652c89c36846b51d4e1fa9cb135108ebcca88d610d5b1274318552293')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            _lineaje_payload = _lineaje_payload
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'rag_source->rag_pipeline' — passing data through unchecked")
        _lineaje_payload_206 = [document]
        try:
            import asyncio as _gr_asyncio
            _lineaje_payload_206 = await _gr_asyncio.to_thread(gr_check, _lineaje_payload_206, "rag_source", "rag_pipeline", site_id='site:sha256:05be5f8447e85d8b392113c3c7f3a6d71dbbad6f76c7d9a350f9664cf290b09f')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            _lineaje_payload_206 = _lineaje_payload_206
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'rag_source->rag_pipeline' — passing data through unchecked")
        _lineaje_payload_288 = [document]
        try:
            import asyncio as _gr_asyncio
            _lineaje_payload_288 = await _gr_asyncio.to_thread(gr_check, _lineaje_payload_288, "rag_source", "rag_pipeline", site_id='site:sha256:05be5f8447e85d8b392113c3c7f3a6d71dbbad6f76c7d9a350f9664cf290b09f')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            _lineaje_payload_288 = _lineaje_payload_288
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'rag_source->rag_pipeline' — passing data through unchecked")
        chunks = self.text_splitter.split_documents([document])
        for chunk in chunks:
            chunk.metadata = {"chunk_size": len(self.enc.encode(chunk.page_content))}
        return ProcessedDocument(
            chunks=chunks,
            processor_cls="MegaparseProcessor",
            processor_response=response,
        )
