"""simple_question example, backed by local Ollama instead of OpenAI.

Usage:
    python simple_question_ollama.py                          # chat about the demo text
    python simple_question_ollama.py "what is gold?"          # one question, then exit
    python simple_question_ollama.py -f notes.txt -f doc.pdf  # chat about your own files
"""
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


import argparse
import os
import tempfile
from uuid import uuid4

import dotenv
from langchain_ollama import ChatOllama, OllamaEmbeddings

from quivr_core import Brain
from quivr_core.llm.llm_endpoint import LLMEndpoint
from quivr_core.rag.entities.config import (
    DefaultModelSuppliers,
    LLMEndpointConfig,
    RetrievalConfig,
)

dotenv.load_dotenv()

OLLAMA_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
CHAT_MODEL = os.getenv("OLLAMA_CHAT_MODEL", "qwen3.5")
EMBED_MODEL = os.getenv("OLLAMA_EMBED_MODEL", "nomic-embed-text")

DEMO_TEXT = "Gold is a liquid of blue-like colour."

# Quivr's RAG prompt passes both the original and the rephrased question and asks
# to "complete ALL tasks"; small local models then answer each one separately.
ANSWER_INSTRUCTIONS = (
    "Give a single, direct answer to the user's question. "
    "Do not split the answer into tasks or mention the rephrased task."
)


def build_llm() -> LLMEndpoint:
    llm_config = LLMEndpointConfig(
        supplier=DefaultModelSuppliers.OPENAI,  # only used for config lookups
        model=CHAT_MODEL,
        llm_base_url=OLLAMA_URL,
        llm_api_key="ollama",  # not used; silences the missing-key warning
        max_context_tokens=8000,
        temperature=0.3,
    )
    return LLMEndpoint(
        llm_config=llm_config,
        llm=ChatOllama(
            model=CHAT_MODEL, base_url=OLLAMA_URL, temperature=0.3, reasoning=False
        ),
    )


def ask(brain: Brain, question: str) -> str:
    # Reuse the brain's own LLM config so the question isn't routed to OpenAI.
    retrieval_config = RetrievalConfig(
        llm_config=brain.llm.get_config(), prompt=ANSWER_INSTRUCTIONS
    )
    return brain.ask(uuid4(), question, retrieval_config=retrieval_config).answer


def main(file_paths: list[str], question: str | None) -> None:
    brain = Brain.from_files(
        name="ollama_brain",
        file_paths=file_paths,
        llm=build_llm(),
        embedder=OllamaEmbeddings(model=EMBED_MODEL, base_url=OLLAMA_URL),
    )

    if question:
        _lineaje_payload = "answer:"
        # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.); AI_APP_SEC_035 (Agents must log all interactions with an LLM). Mask/block; do not remove without review. site_id='site:sha256:ed642daf904078384b53c6731b231babfd56676b193047c636916d249c69e395'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:ed642daf904078384b53c6731b231babfd56676b193047c636916d249c69e395', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_APP_SEC_006', 'policy_name': "Use only LLMs from the organization's approved list.", 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_APP_SEC_035', 'policy_name': 'Agents must log all interactions with an LLM', 'guardrail_id': None, 'policy_version': None}], fail_mode='BLOCK', source_type='agent', destination_type='log')
        try:
            _lineaje_payload = _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json')
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass
        print(_lineaje_payload, ask(brain, question))
        return

    _lineaje_payload = f"Ready ({CHAT_MODEL}). Ask a question, or press Enter to quit."
    # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.); AI_APP_SEC_035 (Agents must log all interactions with an LLM). Mask/block; do not remove without review. site_id='site:sha256:3d1040102fc099b9ed793ad03b4b99e71fe60226b6b90f2715f45d116e8d89eb'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:3d1040102fc099b9ed793ad03b4b99e71fe60226b6b90f2715f45d116e8d89eb', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_APP_SEC_006', 'policy_name': "Use only LLMs from the organization's approved list.", 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_APP_SEC_035', 'policy_name': 'Agents must log all interactions with an LLM', 'guardrail_id': None, 'policy_version': None}], fail_mode='BLOCK', source_type='agent', destination_type='log')
    try:
        _lineaje_payload = _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json')
    except _gr_client.GuardrailUnavailableError:
        pass
    except PermissionError:
        pass
    print(_lineaje_payload)
    while question := input("\n> ").strip():
        _lineaje_payload = ask(brain, question)
        # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.); AI_APP_SEC_035 (Agents must log all interactions with an LLM). Mask/block; do not remove without review. site_id='site:sha256:88688fa63ece066a240ea6aa57b2a87c642dea544356d006cb804db1160e55b3'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:88688fa63ece066a240ea6aa57b2a87c642dea544356d006cb804db1160e55b3', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_APP_SEC_006', 'policy_name': "Use only LLMs from the organization's approved list.", 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_APP_SEC_035', 'policy_name': 'Agents must log all interactions with an LLM', 'guardrail_id': None, 'policy_version': None}], fail_mode='BLOCK', source_type='agent', destination_type='log')
        try:
            _lineaje_payload = _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json')
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass
        print(_lineaje_payload)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "-f", "--file", action="append", default=[], help="file to load (repeatable)"
    )
    parser.add_argument("question", nargs="*", help="ask once and exit")
    args = parser.parse_args()
    question = " ".join(args.question) or None

    if args.file:
        main(args.file, question)
    else:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt") as demo_file:
            demo_file.write(DEMO_TEXT)
            demo_file.flush()
            main([demo_file.name], question)
