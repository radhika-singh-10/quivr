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
            hop_label = gr_check(hop_label, "agent", "log", candidate_policies=['AI_APP_SEC_006', 'AI_APP_SEC_035'], site_id='site:sha256:f33c4ca5cc5f2501e797aa7d60fd560f357cf09d9ad7d4952343104beb036fa2')
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
            hop_label = gr_check(hop_label, "agent", "log", candidate_policies=['AI_APP_SEC_006', 'AI_APP_SEC_035'], site_id='site:sha256:d6258ddb93f3621d9c0414e7266acd68d42769a57744ba50c57609e0765cf59c')
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
                orig = gr_check(orig, "agent", "user_interface", candidate_policies=['AI_APP_SEC_006', 'AI_APP_SEC_035'], site_id='site:sha256:6f7a072b6ced3c703086b0c84751ebe72eb06445951c367ea12292a3a5149428')
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
                _c = gr_check(_c, "agent", "user_interface", candidate_policies=['AI_APP_SEC_006', 'AI_APP_SEC_035'], site_id='site:sha256:253e517dc4c4044001c9876363efcbb3d461b2bb41a261d48ca66a0e23d7bf05')
            except Exception as _gr_exc:
                if type(_gr_exc).__name__ == "GRBlockedError": raise
                _c = _c
                __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
            return _c
        if orig is None or isinstance(orig, (str, int, float, bool, dict, list)):
            try:
                new = gr_check(new, "agent", "user_interface", candidate_policies=['AI_APP_SEC_006', 'AI_APP_SEC_035'], site_id='site:sha256:253e517dc4c4044001c9876363efcbb3d461b2bb41a261d48ca66a0e23d7bf05')
            except Exception as _gr_exc:
                if type(_gr_exc).__name__ == "GRBlockedError": raise
                new = new
                __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
            return new
        _log.warning("gr_client[%s]: masked result cannot be applied to %s — returning original", hop_label, type(orig).__name__)
        try:
            orig = gr_check(orig, "agent", "user_interface", candidate_policies=['AI_APP_SEC_006', 'AI_APP_SEC_035'], site_id='site:sha256:253e517dc4c4044001c9876363efcbb3d461b2bb41a261d48ca66a0e23d7bf05')
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
                hop_label = gr_check(hop_label, "agent", "log", candidate_policies=['AI_APP_SEC_006', 'AI_APP_SEC_035'], site_id='site:sha256:f115c500168101cba6551dc23e8057eb65099eaafd0e6d91a991bed7711b3bda')
            except Exception as _gr_exc:
                if type(_gr_exc).__name__ == "GRBlockedError": raise
                hop_label = hop_label
                __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
            _log.warning("gr_client[%s]: BLOCKED by policy=%s — %s", hop_label, policy_id, reason)
            if _os.environ.get("GR_BLOCK_MODE", "enforce").lower() == "audit":
                try:
                    data = gr_check(data, "agent", "user_interface", candidate_policies=['AI_APP_SEC_006', 'AI_APP_SEC_035'], site_id='site:sha256:253e517dc4c4044001c9876363efcbb3d461b2bb41a261d48ca66a0e23d7bf05')
                except Exception as _gr_exc:
                    if type(_gr_exc).__name__ == "GRBlockedError": raise
                    data = data
                    __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
                return data
            gr_check._blocked = (policy_id, reason)
            raise GRBlockedError(policy_id, reason)
        _log.warning("gr_client[%s]: GR service call failed (%s) — failing open", hop_label, exc)
        try:
            data = gr_check(data, "agent", "user_interface", candidate_policies=['AI_APP_SEC_006', 'AI_APP_SEC_035'], site_id='site:sha256:ffddd42a2d19a5425a89ace5569f38102406ce51dea24c8a90ad7a7f3fb4ff7c')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            data = data
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
        return data
    if result.get("status") == "escalate":
        try:
            hop_label = gr_check(hop_label, "agent", "log", candidate_policies=['AI_APP_SEC_006', 'AI_APP_SEC_035'], site_id='site:sha256:6a92d39ea88f7cbb590893cc2367c18ea8aeeca7d361408622de27cead7b3148')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            hop_label = hop_label
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
        _log.warning("gr_client[%s]: escalation flagged — passing through for human review", hop_label)
    if not isinstance(result.get("result"), dict) or "data" not in result["result"]:
        try:
            data = gr_check(data, "agent", "user_interface", candidate_policies=['AI_APP_SEC_006', 'AI_APP_SEC_035'], site_id='site:sha256:253e517dc4c4044001c9876363efcbb3d461b2bb41a261d48ca66a0e23d7bf05')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            data = data
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
        return data
    return _gr_back(data, result["result"]["data"])
from quivr_core.rag.entities.config import LLMEndpointConfig, RetrievalConfig


def test_default_llm_config():
    config = LLMEndpointConfig()

    assert (
        config.model_dump()
        == LLMEndpointConfig(
            model="gpt-4o",
            llm_base_url=None,
            llm_api_key=None,
            max_context_tokens=2000,
            max_output_tokens=2000,
            temperature=0.7,
            streaming=True,
        ).model_dump()
    )


def test_default_retrievalconfig():
    config = RetrievalConfig()

    assert config.max_files == 20
    assert config.prompt is None
    _lineaje_payload_129 = "\n\n"
    try:
        _lineaje_payload_129 = gr_check(_lineaje_payload_129, "agent", "log", candidate_policies=['AI_APP_SEC_006', 'AI_APP_SEC_035'], site_id='site:sha256:7fd745c7a348a937b9a4e479a81a79ea0ce80a249b391b0f0058120b5587590d')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        _lineaje_payload_129 = _lineaje_payload_129
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
    print("\n\n", config.llm_config, "\n\n")
    _lineaje_payload = "\n\n"
    try:
        _lineaje_payload = gr_check(_lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_006'], site_id='site:sha256:7fd745c7a348a937b9a4e479a81a79ea0ce80a249b391b0f0058120b5587590d')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        _lineaje_payload = _lineaje_payload
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
    _lineaje_payload_137 = "\n\n"
    try:
        _lineaje_payload_137 = gr_check(_lineaje_payload_137, "agent", "log", candidate_policies=['AI_APP_SEC_006', 'AI_APP_SEC_035'], site_id='site:sha256:7fd745c7a348a937b9a4e479a81a79ea0ce80a249b391b0f0058120b5587590d')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        _lineaje_payload_137 = _lineaje_payload_137
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
    print("\n\n", LLMEndpointConfig(), "\n\n")
    assert config.llm_config == LLMEndpointConfig()
