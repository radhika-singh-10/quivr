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
def _lineaje_current_model():
    """Lineaje-added: reread the app's model setting for every request."""
    import os as _o
    from pathlib import Path as _P
    _keys = ("OPENROUTER_MODEL", "LLM_MODEL", "MODEL_NAME", "MODEL_ID", "OPENAI_MODEL", "ANTHROPIC_MODEL", "BEDROCK_MODEL_ID")
    _here = _P(__file__).resolve().parent
    for _path in (_here / ".env", *(_p / ".env" for _p in list(_here.parents)[:8])):
        if not _path.is_file(): continue
        try: _lines = _path.read_text(encoding="utf-8").splitlines()
        except OSError: continue
        _values = {}
        for _line in _lines:
            _line = _line.strip()
            if not _line or _line.startswith("#") or "=" not in _line: continue
            _key, _, _value = _line.partition("=")
            if _key.strip() in _keys: _values[_key.strip()] = _value.strip().strip(chr(34)).strip(chr(39))
        for _key in _keys:
            if _values.get(_key): return _values[_key]
    return next((_o.environ[_key].strip() for _key in _keys if _o.environ.get(_key, "").strip()), "")
import os

from langchain_openai import ChatOpenAI, OpenAIEmbeddings
from quivr_core import Brain
from quivr_core.llm.llm_endpoint import LLMEndpoint
from quivr_core.rag.entities.config import LLMEndpointConfig
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt

if __name__ == "__main__":
    brain = Brain.from_files(
        name="test_brain",
        file_paths=["./tests/processor/pdf/sample.pdf"],
        llm=LLMEndpoint(
            llm_config=LLMEndpointConfig(model="gpt-4o"),
            llm=ChatOpenAI(model="gpt-4o", api_key=str(os.getenv("OPENAI_API_KEY"))),
        ),
    )
    # LINEAJE: enforce() `brain` at llm->agent post_model — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.); AI_APP_SEC_035 (Agents must log all interactions with an LLM); AI_DAT_SEC_023 (Redact PII from uploaded files.). Mask/block; do not remove without review. site_id='site:sha256:928b993ec1367b6373c12ed4588b5893fe900f4f742e13f093a561fc229bfd40'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:928b993ec1367b6373c12ed4588b5893fe900f4f742e13f093a561fc229bfd40', phase='post_model', boundary={'source': 'model', 'sink': 'agent_message'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_029', 'guardrail_id': 'Emit immutable, forensic-ready audit records for all AI decisions.', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='llm', destination_type='agent')
    try:
        brain = _gr_client.enforce(_gr_site, brain, content_type='application/json', variable_name='brain', source_file=__file__, before_line=44)
    except _gr_client.GuardrailUnavailableError:
        pass
    embedder = embeddings = OpenAIEmbeddings(
        model="text-embedding-3-large",
    )
    # Check brain info
    brain.print_info()

    console = Console()
    _lineaje_payload = Panel.fit("Ask your brain !", style="bold magenta")
    # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.); AI_APP_SEC_035 (Agents must log all interactions with an LLM). Mask/block; do not remove without review. site_id='site:sha256:40703df3628713ad01f67b2b011c26027306f6a42b9dffcd238ce036debc6c5c'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:40703df3628713ad01f67b2b011c26027306f6a42b9dffcd238ce036debc6c5c', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_APP_SEC_006', 'policy_name': "Use only LLMs from the organization's approved list.", 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_APP_SEC_035', 'policy_name': 'Agents must log all interactions with an LLM', 'guardrail_id': None, 'policy_version': None}], fail_mode='BLOCK', source_type='agent', destination_type='log')
    try:
        _lineaje_payload = _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json')
    except _gr_client.GuardrailUnavailableError:
        pass
    except PermissionError:
        pass
    console.print(_lineaje_payload)

    while True:
        # Get user input
        _lineaje_payload_73 = "[bold cyan]Question[/bold cyan]"
        # LINEAJE: enforce() `_lineaje_payload_73` at agent->llm pre_model — scan flagged AI_APP_SEC_070 (Detect and block all forms of prompt injection attacks in user inputs and file contents). Mask/block; do not remove without review. site_id='site:sha256:58215b1342f10c36e12882e16545cb54587bb05cb3ce5ddc4ec7ad27d68766ec'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:58215b1342f10c36e12882e16545cb54587bb05cb3ce5ddc4ec7ad27d68766ec', phase='pre_model', boundary={'source': 'agent_message', 'sink': 'model'}, candidate_policies=[{'policy_id': 'AI_APP_SEC_006', 'guardrail_id': 'Enforce Approved LLM.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_028', 'guardrail_id': 'Enforce Approved LLM', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_070', 'guardrail_id': 'Sanitize Prompt Injection', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_011', 'guardrail_id': 'Redact PII', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_029', 'guardrail_id': 'Emit immutable, forensic-ready audit records for all AI decisions.', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='llm')
        try:
            _lineaje_payload_73 = _gr_client.enforce(_gr_site, _lineaje_payload_73, content_type='application/json', variable_name='_lineaje_payload_73', source_file=__file__, before_line=73)
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            raise
        question = Prompt.ask(_lineaje_payload_73)

        # Check if user wants to exit
        if question.lower() == "exit":
            _lineaje_payload = Panel("Goodbye!", style="bold yellow")
            # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.); AI_APP_SEC_035 (Agents must log all interactions with an LLM). Mask/block; do not remove without review. site_id='site:sha256:2f9f24a5009e3a821499e2a7cdf35a9fd2e0bbc8fee15e678b120180d46c2896'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:2f9f24a5009e3a821499e2a7cdf35a9fd2e0bbc8fee15e678b120180d46c2896', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_APP_SEC_006', 'policy_name': "Use only LLMs from the organization's approved list.", 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_APP_SEC_035', 'policy_name': 'Agents must log all interactions with an LLM', 'guardrail_id': None, 'policy_version': None}], fail_mode='BLOCK', source_type='agent', destination_type='log')
            try:
                _lineaje_payload = _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json')
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                pass
            console.print(_lineaje_payload)
            break

        # LINEAJE: enforce() `question` at agent->llm pre_model — scan flagged AI_APP_SEC_070 (Detect and block all forms of prompt injection attacks in user inputs and file contents). Mask/block; do not remove without review. site_id='site:sha256:9fbb5569e6b8ff9bdd676530aef63f0a03d446e9933efbc7902ddeb94d589e45'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:9fbb5569e6b8ff9bdd676530aef63f0a03d446e9933efbc7902ddeb94d589e45', phase='pre_model', boundary={'source': 'agent_message', 'sink': 'model'}, candidate_policies=[{'policy_id': 'AI_APP_SEC_006', 'policy_name': "Use only LLMs from the organization's approved list.", 'guardrail_id': 'Enforce Approved LLM.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_028', 'policy_name': "Do not use LLMs from the organization's disallowed list", 'guardrail_id': 'Enforce Approved LLM', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_070', 'policy_name': 'Detect and block all forms of prompt injection attacks in user inputs and file contents', 'guardrail_id': 'Sanitize Prompt Injection', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_011', 'policy_name': 'Do not send PII and/or secrets to AI Models', 'guardrail_id': 'Redact PII', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_029', 'policy_name': 'Enforce decision logging, audit trail, and forensic readiness for AI-driven actions.', 'guardrail_id': 'Emit immutable, forensic-ready audit records for all AI decisions.', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='llm', project='', organization='Root Organization')
        try:
            question = _gr_client.enforce(_gr_site, question, content_type='application/json', variable_name='question', source_file=__file__, before_line=91)
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            raise
        # LINEAJE: enforce() `question` at agent->system security_decision — scan flagged AI_APP_SEC_035 (Agents must log all interactions with an LLM). Mask/block; do not remove without review. site_id='site:sha256:9e616dcb16e78beaa038b9303d604cc537096b0d55bbfb28a9ca9fa8f4720b35'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:9e616dcb16e78beaa038b9303d604cc537096b0d55bbfb28a9ca9fa8f4720b35', phase='security_decision', boundary={'source': 'agent_message', 'sink': 'agent_message'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_029', 'guardrail_id': 'Emit immutable, forensic-ready audit records for all AI decisions.', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='system')
        try:
            question = _gr_client.enforce(_gr_site, question, content_type='application/json', variable_name='question', source_file=__file__, before_line=99)
        except _gr_client.GuardrailUnavailableError:
            pass
        answer = brain.ask(question)
        # Print the answer with typing effect
        _lineaje_payload = f"[bold green]Quivr Assistant[/bold green]: {answer.answer}"
        # LINEAJE: enforce() `_lineaje_payload` at agent->user_interface data_egress — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.); AI_APP_SEC_035 (Agents must log all interactions with an LLM). Mask/block; do not remove without review. site_id='site:sha256:0c1ad90ebca8491a95b3b84107d35545b61c33dada4e4e2f88ddfa15b7945831'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:0c1ad90ebca8491a95b3b84107d35545b61c33dada4e4e2f88ddfa15b7945831', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'policy_name': 'Mask PII on user interfaces', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface', project='', organization='Root Organization')
        try:
            _lineaje_payload = _gr_client.enforce(_gr_site, _lineaje_payload, content_type='text/plain')
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass
        # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.); AI_APP_SEC_035 (Agents must log all interactions with an LLM). Mask/block; do not remove without review. site_id='site:sha256:a98c4663ef2ddb841a1c6e4da18031773dd2c9c6db4592be0a95dedcfb4610d6'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:a98c4663ef2ddb841a1c6e4da18031773dd2c9c6db4592be0a95dedcfb4610d6', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_APP_SEC_006', 'policy_name': "Use only LLMs from the organization's approved list.", 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_APP_SEC_035', 'policy_name': 'Agents must log all interactions with an LLM', 'guardrail_id': None, 'policy_version': None}], fail_mode='BLOCK', source_type='agent', destination_type='log')
        try:
            _lineaje_payload = _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json')
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass
        console.print(_lineaje_payload)

        _lineaje_payload = "-" * console.width
        # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.); AI_APP_SEC_035 (Agents must log all interactions with an LLM). Mask/block; do not remove without review. site_id='site:sha256:333e8f0b353e1724ba24cce5785ed44625d5f654750b667c7596249411363f76'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:333e8f0b353e1724ba24cce5785ed44625d5f654750b667c7596249411363f76', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_APP_SEC_006', 'policy_name': "Use only LLMs from the organization's approved list.", 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_APP_SEC_035', 'policy_name': 'Agents must log all interactions with an LLM', 'guardrail_id': None, 'policy_version': None}], fail_mode='BLOCK', source_type='agent', destination_type='log')
        try:
            _lineaje_payload = _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json')
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass
        console.print(_lineaje_payload)

    brain.print_info()
