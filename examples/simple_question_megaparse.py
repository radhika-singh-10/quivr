# Copyright (c) Lineaje, Inc. All rights reserved.
# Lineaje UnifAI guardrail  version=2.0.0-alpha
# Each enforce() call site below carries a SiteDescriptor with:
#   site_id            deterministic id for this exact call site (file +
#                      symbol + insertion point + pattern) — stable across
#                      re-scans, used to dedupe stub insertions and to look
#                      up this site's policy mapping at runtime.
#   candidate_policies policy IDs this site matched during the scan.
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
    embedder = embeddings = OpenAIEmbeddings(
        model="text-embedding-3-large",
    )
    # Check brain info
    brain.print_info()

    console = Console()
    _lineaje_payload = Panel.fit("Ask your brain !", style="bold magenta")
    # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — scan flagged AI_IAC_023 (Chatbot and AI interfaces must disclose AI identity to the user). Mask/block; do not remove without review. site_id='site:sha256:40703df3628713ad01f67b2b011c26027306f6a42b9dffcd238ce036debc6c5c'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:40703df3628713ad01f67b2b011c26027306f6a42b9dffcd238ce036debc6c5c', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_IAC_023', 'guardrail_id': None, 'policy_version': None}], fail_mode='BLOCK', source_type='agent', destination_type='log')
    _lineaje_payload = _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json')
    console.print(_lineaje_payload)

    while True:
        # Get user input
        question = Prompt.ask("[bold cyan]Question[/bold cyan]")

        # Check if user wants to exit
        if question.lower() == "exit":
            _lineaje_payload = Panel("Goodbye!", style="bold yellow")
            # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.); AI_APP_SEC_029 (Agent must validate, sanitize LLM output including for presence of eval or any dynamic code execution primitive in LLM output.); AI_APP_SEC_039 (Sanitize and validate all input to the AI Model.). Mask/block; do not remove without review. site_id='site:sha256:2f9f24a5009e3a821499e2a7cdf35a9fd2e0bbc8fee15e678b120180d46c2896'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:2f9f24a5009e3a821499e2a7cdf35a9fd2e0bbc8fee15e678b120180d46c2896', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_006', 'guardrail_id': 'Enforce Approved LLM.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_029', 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_APP_SEC_039', 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_APP_SEC_040', 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_APP_SEC_059', 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_APP_SEC_071', 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_DAT_SEC_023', 'guardrail_id': 'Redact PII from uploaded files', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_024', 'guardrail_id': 'Redact PII (Singapore) from contents ofuploaded files', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_IAC_014', 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_IAC_023', 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_IAC_024', 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_DAT_SEC_027', 'guardrail_id': 'Minimise and redact all outbound AI outputs.', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log')
            _lineaje_payload = _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json')
            console.print(_lineaje_payload)
            break

        answer = brain.ask(question)
        # Print the answer with typing effect
        _lineaje_payload = f"[bold green]Quivr Assistant[/bold green]: {answer.answer}"
        # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — scan flagged AI_DAT_SEC_027 (Enforce output data minimization for model, tool, and API responses.). Mask/block; do not remove without review. site_id='site:sha256:a98c4663ef2ddb841a1c6e4da18031773dd2c9c6db4592be0a95dedcfb4610d6'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:a98c4663ef2ddb841a1c6e4da18031773dd2c9c6db4592be0a95dedcfb4610d6', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_027', 'guardrail_id': 'Minimise and redact all outbound AI outputs.', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log')
        _lineaje_payload = _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json')
        console.print(_lineaje_payload)

        _lineaje_payload = "-" * console.width
        # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.); AI_APP_SEC_029 (Agent must validate, sanitize LLM output including for presence of eval or any dynamic code execution primitive in LLM output.); AI_APP_SEC_039 (Sanitize and validate all input to the AI Model.). Mask/block; do not remove without review. site_id='site:sha256:333e8f0b353e1724ba24cce5785ed44625d5f654750b667c7596249411363f76'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:333e8f0b353e1724ba24cce5785ed44625d5f654750b667c7596249411363f76', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_006', 'guardrail_id': 'Enforce Approved LLM.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_029', 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_APP_SEC_039', 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_APP_SEC_040', 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_APP_SEC_059', 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_APP_SEC_071', 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_DAT_SEC_023', 'guardrail_id': 'Redact PII from uploaded files', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_024', 'guardrail_id': 'Redact PII (Singapore) from contents ofuploaded files', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_IAC_014', 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_IAC_023', 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_IAC_024', 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_DAT_SEC_027', 'guardrail_id': 'Minimise and redact all outbound AI outputs.', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log')
        _lineaje_payload = _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json')
        console.print(_lineaje_payload)

    brain.print_info()
