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
            hop_label = gr_check(hop_label, "agent", "log", candidate_policies=['AI_APP_SEC_006', 'AI_APP_SEC_035'], site_id='site:sha256:6cb11dc79320c80ecb1825f233ab24c601f429eae4eceb7868f0f62fc49acf52')
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
            hop_label = gr_check(hop_label, "agent", "log", candidate_policies=['AI_APP_SEC_006', 'AI_APP_SEC_035'], site_id='site:sha256:5b9a405ea44459bd1108a1dce4daf4634c8d7ee6ea6a5011e232adc5aa2ec2c5')
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
                orig = gr_check(orig, "agent", "user_interface", candidate_policies=['AI_APP_SEC_006', 'AI_APP_SEC_035'], site_id='site:sha256:92a202d0e4313f772fe9502e7e721cfee51af040af9736a9b4d6fa2ba7550489')
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
                _c = gr_check(_c, "agent", "user_interface", candidate_policies=['AI_APP_SEC_006', 'AI_APP_SEC_035'], site_id='site:sha256:4f4cb79bcb753db85cd7ba38f74898befc62839d0122f12fb9c94fa1806e7870')
            except Exception as _gr_exc:
                if type(_gr_exc).__name__ == "GRBlockedError": raise
                _c = _c
                __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
            return _c
        if orig is None or isinstance(orig, (str, int, float, bool, dict, list)):
            try:
                new = gr_check(new, "agent", "user_interface", candidate_policies=['AI_APP_SEC_006', 'AI_APP_SEC_035'], site_id='site:sha256:4f4cb79bcb753db85cd7ba38f74898befc62839d0122f12fb9c94fa1806e7870')
            except Exception as _gr_exc:
                if type(_gr_exc).__name__ == "GRBlockedError": raise
                new = new
                __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
            return new
        _log.warning("gr_client[%s]: masked result cannot be applied to %s — returning original", hop_label, type(orig).__name__)
        try:
            orig = gr_check(orig, "agent", "user_interface", candidate_policies=['AI_APP_SEC_006', 'AI_APP_SEC_035'], site_id='site:sha256:4f4cb79bcb753db85cd7ba38f74898befc62839d0122f12fb9c94fa1806e7870')
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
                hop_label = gr_check(hop_label, "agent", "log", candidate_policies=['AI_APP_SEC_006', 'AI_APP_SEC_035'], site_id='site:sha256:c976f3c060c3b584cdcedd53611aca4a5c59cb3bbbff87bff632f29b264e6c65')
            except Exception as _gr_exc:
                if type(_gr_exc).__name__ == "GRBlockedError": raise
                hop_label = hop_label
                __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
            _log.warning("gr_client[%s]: BLOCKED by policy=%s — %s", hop_label, policy_id, reason)
            if _os.environ.get("GR_BLOCK_MODE", "enforce").lower() == "audit":
                try:
                    data = gr_check(data, "agent", "user_interface", candidate_policies=['AI_APP_SEC_006', 'AI_APP_SEC_035'], site_id='site:sha256:4f4cb79bcb753db85cd7ba38f74898befc62839d0122f12fb9c94fa1806e7870')
                except Exception as _gr_exc:
                    if type(_gr_exc).__name__ == "GRBlockedError": raise
                    data = data
                    __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
                return data
            gr_check._blocked = (policy_id, reason)
            raise GRBlockedError(policy_id, reason)
        _log.warning("gr_client[%s]: GR service call failed (%s) — failing open", hop_label, exc)
        try:
            data = gr_check(data, "agent", "user_interface", candidate_policies=['AI_APP_SEC_006', 'AI_APP_SEC_035'], site_id='site:sha256:b5dc9ea81ee35996b55edd19589a56977ebda854e2f0c5f89c4129f72821678f')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            data = data
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
        return data
    if result.get("status") == "escalate":
        try:
            hop_label = gr_check(hop_label, "agent", "log", candidate_policies=['AI_APP_SEC_006', 'AI_APP_SEC_035'], site_id='site:sha256:b7a6baa99fc394aa41a04b7a2df596671a66dc96494eaca3469bc08a9aec08cb')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            hop_label = hop_label
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
        _log.warning("gr_client[%s]: escalation flagged — passing through for human review", hop_label)
    if not isinstance(result.get("result"), dict) or "data" not in result["result"]:
        try:
            data = gr_check(data, "agent", "user_interface", candidate_policies=['AI_APP_SEC_006', 'AI_APP_SEC_035'], site_id='site:sha256:4f4cb79bcb753db85cd7ba38f74898befc62839d0122f12fb9c94fa1806e7870')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            data = data
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
        return data
    return _gr_back(data, result["result"]["data"])
from langchain_core.embeddings import DeterministicFakeEmbedding
from langchain_core.language_models import FakeListChatModel
from quivr_core import Brain
from quivr_core.rag.entities.config import LLMEndpointConfig
from quivr_core.llm.llm_endpoint import LLMEndpoint
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt

if __name__ == "__main__":
    brain = Brain.from_files(
        name="test_brain",
        file_paths=["tests/processor/data/dummy.pdf"],
        llm=LLMEndpoint(
            llm=FakeListChatModel(responses=["good"]),
            llm_config=LLMEndpointConfig(model="fake_model", llm_base_url="local"),
        ),
        embedder=DeterministicFakeEmbedding(size=20),
    )
    # Check brain info
    brain.print_info()

    console = Console()
    _lineaje_payload = Panel.fit("Ask your brain !", style="bold magenta")
    try:
        _lineaje_payload = gr_check(_lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_006', 'AI_APP_SEC_035'], site_id='site:sha256:a688ff436888322ffc60e2a431014e6f572e454c91c14900d1530bd0e4dfbc41')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        _lineaje_payload = _lineaje_payload
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
    _lineaje_payload_134 = Panel.fit("Ask your brain !", style="bold magenta")
    try:
        _lineaje_payload_134 = gr_check(_lineaje_payload_134, "agent", "log", candidate_policies=['AI_APP_SEC_006', 'AI_APP_SEC_035'], site_id='site:sha256:41bfa746c65dec4945ca3bb983798129accbd4b24fbc8390bb21ca70fd08cedd')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        _lineaje_payload_134 = _lineaje_payload_134
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
    console.print(Panel.fit("Ask your brain !", style="bold magenta"))

    while True:
        # Get user input
        question = Prompt.ask("[bold cyan]Question[/bold cyan]")

        # Check if user wants to exit
        if question.lower() == "exit":
            _lineaje_payload = Panel("Goodbye!", style="bold yellow")
            try:
                _lineaje_payload = gr_check(_lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_006', 'AI_APP_SEC_035'], site_id='site:sha256:a688ff436888322ffc60e2a431014e6f572e454c91c14900d1530bd0e4dfbc41')
            except Exception as _gr_exc:
                if type(_gr_exc).__name__ == "GRBlockedError": raise
                _lineaje_payload = _lineaje_payload
                __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
            _lineaje_payload_149 = Panel("Goodbye!", style="bold yellow")
            try:
                _lineaje_payload_149 = gr_check(_lineaje_payload_149, "agent", "log", candidate_policies=['AI_APP_SEC_006', 'AI_APP_SEC_035'], site_id='site:sha256:41bfa746c65dec4945ca3bb983798129accbd4b24fbc8390bb21ca70fd08cedd')
            except Exception as _gr_exc:
                if type(_gr_exc).__name__ == "GRBlockedError": raise
                _lineaje_payload_149 = _lineaje_payload_149
                __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
            console.print(Panel("Goodbye!", style="bold yellow"))
            break

        answer = brain.ask(question)
        # Print the answer with typing effect
        _lineaje_payload = f"[bold green]Quivr Assistant[/bold green]: {answer.answer}"
        try:
            _lineaje_payload = gr_check(_lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_006', 'AI_APP_SEC_035'], site_id='site:sha256:a688ff436888322ffc60e2a431014e6f572e454c91c14900d1530bd0e4dfbc41')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            _lineaje_payload = _lineaje_payload
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
        _lineaje_payload_161 = f"[bold green]Quivr Assistant[/bold green]: {answer.answer}"
        try:
            _lineaje_payload_161 = gr_check(_lineaje_payload_161, "agent", "log", candidate_policies=['AI_APP_SEC_006', 'AI_APP_SEC_035'], site_id='site:sha256:41bfa746c65dec4945ca3bb983798129accbd4b24fbc8390bb21ca70fd08cedd')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            _lineaje_payload_161 = _lineaje_payload_161
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
        console.print(f"[bold green]Quivr Assistant[/bold green]: {answer.answer}")

        _lineaje_payload = "-" * console.width
        try:
            _lineaje_payload = gr_check(_lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_006', 'AI_APP_SEC_035'], site_id='site:sha256:a688ff436888322ffc60e2a431014e6f572e454c91c14900d1530bd0e4dfbc41')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            _lineaje_payload = _lineaje_payload
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
        _lineaje_payload_170 = "-" * console.width
        try:
            _lineaje_payload_170 = gr_check(_lineaje_payload_170, "agent", "log", candidate_policies=['AI_APP_SEC_006', 'AI_APP_SEC_035'], site_id='site:sha256:41bfa746c65dec4945ca3bb983798129accbd4b24fbc8390bb21ca70fd08cedd')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            _lineaje_payload_170 = _lineaje_payload_170
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
        console.print("-" * console.width)

    brain.print_info()
