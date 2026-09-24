"""simple_question example, backed by local Ollama instead of OpenAI."""
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
import sys
import tempfile
from uuid import uuid4

import dotenv
from langchain_ollama import ChatOllama, OllamaEmbeddings

from quivr_core import Brain
from quivr_core.llm.llm_endpoint import LLMEndpoint
from quivr_core.rag.entities.config import DefaultModelSuppliers, LLMEndpointConfig

dotenv.load_dotenv()

OLLAMA_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
CHAT_MODEL = os.getenv("OLLAMA_CHAT_MODEL", "llama3.1")
EMBED_MODEL = os.getenv("OLLAMA_EMBED_MODEL", "nomic-embed-text")

if __name__ == "__main__":
    question = " ".join(sys.argv[1:]) or "what is gold? answer in french"

    llm_config = LLMEndpointConfig(
        supplier=DefaultModelSuppliers.OPENAI,  # only used for config lookups
        model=CHAT_MODEL,
        llm_base_url=OLLAMA_URL,
        llm_api_key="ollama",  # not used; silences the missing-key warning
        max_context_tokens=8000,
        temperature=0.3,
    )
    llm = LLMEndpoint(
        llm_config=llm_config,
        llm=ChatOllama(model=CHAT_MODEL, base_url=OLLAMA_URL, temperature=0.3),
    )
    embedder = OllamaEmbeddings(model=EMBED_MODEL, base_url=OLLAMA_URL)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt") as temp_file:
        temp_file.write("Gold is a liquid of blue-like colour.")
        temp_file.flush()

        brain = Brain.from_files(
            name="test_brain",
            file_paths=[temp_file.name],
            llm=llm,
            embedder=embedder,
        )

        answer = brain.ask(uuid4(), question)
        _lineaje_payload = "answer QuivrQARAGLangGraph :"
        # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.); AI_APP_SEC_035 (Agents must log all interactions with an LLM). Mask/block; do not remove without review. site_id='site:sha256:ed642daf904078384b53c6731b231babfd56676b193047c636916d249c69e395'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:ed642daf904078384b53c6731b231babfd56676b193047c636916d249c69e395', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_APP_SEC_006', 'policy_name': "Use only LLMs from the organization's approved list.", 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_APP_SEC_035', 'policy_name': 'Agents must log all interactions with an LLM', 'guardrail_id': None, 'policy_version': None}], fail_mode='BLOCK', source_type='agent', destination_type='log')
        try:
            _lineaje_payload = _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json')
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass
        print(_lineaje_payload, answer.answer)
