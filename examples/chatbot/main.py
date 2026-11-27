# Copyright (c) Lineaje, Inc. All rights reserved.
# Lineaje UnifAI guardrail  version=2.0.0-alpha
def _lineaje_gr_load(_f):
    """Lineaje-added: load gr_stub_client.py beside _f or in one of its 7 parent folders. Missing or broken:
    a pass-through client and ONE warning per process (GR_REQUIRE_CLIENT=1: ImportError instead)."""
    import sys, os, logging, importlib.util as u, pathlib
    n = "_lineaje_gr_stub_client"
    if n in sys.modules: return sys.modules[n]
    h = pathlib.Path(_f or ".").resolve().parent
    d = [h, *h.parents][:8]
    p = next((x / "gr_stub_client.py" for x in d if (x / "gr_stub_client.py").is_file()), None)
    try:
        s = u.spec_from_file_location(n, p) if p else None
        if s is None: raise FileNotFoundError("gr_stub_client.py")
        m = sys.modules[n] = u.module_from_spec(s); s.loader.exec_module(m); return m
    except Exception as e:
        sys.modules.pop(n, None)
        w = ("gr_stub_client.py not found for %s (searched: %s)" % (_f or "<no __file__>", ", ".join(map(str, d)))
             if p is None else "%s failed to load (%s%s)" % (p, type(e).__name__,
                                                          " line %s" % e.lineno if isinstance(e, SyntaxError) else ""))
        w = ("Lineaje guardrail NOT active: " + w + ". Calls pass through unchecked; set GR_REQUIRE_CLIENT=1 to fail "
             "instead. Each deploy unit needs gr_stub_client.py beside its code and GR_SERVICE_URL plus credentials as "
             "environment variables.")
        if os.environ.get("GR_REQUIRE_CLIENT", "").strip() == "1": raise ImportError(w) from (None if p is None else e)
        z = sys.__dict__.setdefault("_lineaje_gr_null", __import__('types').SimpleNamespace(STUB_API=999999, GuardrailUnavailableError=type('GuardrailUnavailableError', (PermissionError,), {}), SiteDescriptor=lambda *a, **k: None, new_interaction_id=lambda *a, **k: None, enforce=lambda _s, _p, *a, **k: _p, enforce_request=lambda _s, _p, *a, **k: _p, enforce_reply=lambda _s, _p, *a, **k: _p, _lineaje_seen=set()))
        k = "missing" if p is None else (str(p), type(e).__name__)
        if k not in z._lineaje_seen:
            z._lineaje_seen.add(k); g = logging.getLogger("lineaje.guardrail"); g.log(30 if p is None else 40, w)
            if g.hasHandlers(): sys.stderr.write(w + "\n")
        return z
__import__("sys").__dict__.setdefault("_lineaje_gr_load_v1", _lineaje_gr_load)
del _lineaje_gr_load
def _lineaje_load_gr_client():
    """Lineaje-added: this file's gr_stub_client.py (the loader _lineaje_gr_load registered)."""
    return __import__("sys").__dict__["_lineaje_gr_load_v1"](globals().get("__file__"))
if __import__("os").environ.get("GR_REQUIRE_CLIENT", "").strip() == "1": __import__("sys").__dict__["_lineaje_gr_load_v1"](globals().get("__file__"))

import os
import tempfile
from uuid import uuid4

import chainlit as cl
from langchain_community.embeddings import OllamaEmbeddings
from quivr_core import Brain, register_processor
from quivr_core.files.file import FileExtension
from quivr_core.llm import LLMEndpoint
from quivr_core.processor.implementations.simple_txt_processor import SimpleTxtProcessor
from quivr_core.rag.entities.config import LLMEndpointConfig, RetrievalConfig

# Parse .txt locally. Megaparse is the default and tries Quivr's hosted NATS,
# which fails with "nodename nor servname provided" when that host is down.
register_processor(FileExtension.txt, SimpleTxtProcessor, override=True)

# ChatOpenAI requires a key even when the backend is Ollama.
os.environ.setdefault("OPENAI_API_KEY", "ollama")

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_CHAT_MODEL = os.getenv("OLLAMA_CHAT_MODEL", "llama3.2")
OLLAMA_EMBED_MODEL = os.getenv("OLLAMA_EMBED_MODEL", "nomic-embed-text")


def ollama_llm() -> LLMEndpoint:
    llm = LLMEndpoint.from_config(
        LLMEndpointConfig(
            model=OLLAMA_CHAT_MODEL,
            llm_api_key="ollama",
            llm_base_url=f"{OLLAMA_HOST.rstrip('/')}/v1",
            max_output_tokens=8192,
            temperature=0.7,
        )
    )
    # Local models usually cannot satisfy cited_answer tool calls.
    llm._supports_func_calling = False
    return llm


def ollama_embedder() -> OllamaEmbeddings:
    # LINEAJE: runtime guardrail checks the model this client is built with as it flows from the agent to the LLM, before it is sent to the model (in ollama_embedder).
    #   Detected: this statement moves data from the agent to the LLM with no runtime policy check (detection confidence: medium).
    #   Decision: the Guardrail evaluates AI_AGENT_ACTIVITY_LOG, AI_APP_SEC_006, AI_APP_SEC_028, AI_APP_SEC_070 (+1 more); a model that is not approved is refused before the client is built (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
    #   Do not remove without review. site_id='site:sha256:95c8f08ef7abc7e6fa8a5e6e0ebc2adf91f362bdbe962d1df46d47a048ad8ea5'
    _lineaje_model_evidence = {'model': OLLAMA_EMBED_MODEL, 'client': 'OllamaEmbeddings', 'provider': 'langchain_ollama', 'model_source': 'call_kwarg', 'project': 'quivr'}
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:95c8f08ef7abc7e6fa8a5e6e0ebc2adf91f362bdbe962d1df46d47a048ad8ea5', phase='pre_model', boundary={'source': 'agent_config', 'sink': 'model'}, fail_mode='BLOCK', source_type='agent', destination_type='llm', components={'destination': {'entity_type': 'llm', 'name': 'nomic-embed-text', 'provider': '', 'version': ''}, 'invocation': {'file': 'examples/chatbot/main.py', 'function': 'ollama_embedder', 'line': 41}, 'file': 'examples/chatbot/main.py', 'line': 41, 'function': 'ollama_embedder', 'agent_name': 'ollama_embedder', 'agent_name_source': 'inferred_from_function', 'boundary_id': 'bnd:90f1dfdc615a3995'})
    try:
        _lineaje_model_evidence = _gr_client.enforce(_gr_site, _lineaje_model_evidence, content_type='application/json')
    except _gr_client.GuardrailUnavailableError:
        pass
    except PermissionError:
        raise
    return OllamaEmbeddings(model=OLLAMA_EMBED_MODEL, base_url=OLLAMA_HOST)


@cl.on_chat_start
async def on_chat_start():
    files = None

    # Wait for the user to upload a file
    while files is None:
        files = await cl.AskFileMessage(
            content="Please upload a text .txt file to begin!",
            accept=["text/plain"],
            max_size_mb=20,
            timeout=180,
        ).send()
        # LINEAJE: runtime guardrail checks `files` as it flows from an external API to the agent, after the tool returns (in on_chat_start).
        #   Detected: this statement moves data from an external API to the agent with no runtime policy check (detection confidence: low).
        #   Decision: the Guardrail evaluates the policies enabled for this boundary; sensitive values in `files` are masked in place; a policy violation is logged and the call continues (fail_mode=ALLOW_WITH_AUDIT). If the Guardrail is unreachable, the call continues unchanged.
        #   Do not remove without review. site_id='site:sha256:052c03993e27fd952f1c055e9fe1ad584e43d7079c82b1a2e619fcad244c25fa'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:052c03993e27fd952f1c055e9fe1ad584e43d7079c82b1a2e619fcad244c25fa', phase='post_tool', boundary={'source': 'external_endpoint', 'sink': 'agent_message'}, fail_mode='ALLOW_WITH_AUDIT', source_type='api', destination_type='agent', components={'invocation': {'file': 'examples/chatbot/main.py', 'line': 50, 'function': 'on_chat_start'}, 'file': 'examples/chatbot/main.py', 'line': 50, 'function': 'on_chat_start', 'agent_name': 'on_chat_start', 'agent_name_source': 'inferred_from_function', 'not_on_graph': True})
        try:
            if not __import__('builtins').hasattr(_gr_client, 'aenforce'):
                __import__("logging").getLogger("lineaje.gr_client").error("gr_stub_client.py predates aenforce (STUB_API 5): this site is NOT enforced; replace gr_stub_client.py with the current companion")
                raise _gr_client.GuardrailUnavailableError("stale gr_stub_client.py: no aenforce")
            files = await _gr_client.aenforce(_gr_site, files, content_type='application/json', variable_name='files', source_file=__file__, before_line=50)
        except _gr_client.GuardrailUnavailableError:
            pass

    file = files[0]

    msg = cl.Message(content=f"Processing `{file.name}`...")
    try:
        _lineaje_obs = _lineaje_load_gr_client()
        _lineaje_obs_site = _lineaje_obs.SiteDescriptor(site_id='site:sha256:7030a4d7ddc9436ffd0f0604d922f08b7626c8d2283c2ae1607e7b9e88197b43', phase='', boundary={}, fail_mode='ALLOW', source_type='agent', destination_type='user_interface', components={'file': 'examples/chatbot/main.py', 'line': 60, 'function': 'on_chat_start', 'agent_name': 'on_chat_start', 'agent_name_source': 'inferred_from_function', 'call_target': 'msg.send', 'not_on_graph': True}, observe_only=True)
        await _lineaje_obs.aenforce(_lineaje_obs_site, {'activity': 'agent_to_ui'}, content_type='application/json')
    except Exception as _lineaje_obs_err:
        [__import__('sys').__dict__.setdefault('_lineaje_gr_logged', set()).add(_k) or __import__('logging').getLogger('lineaje.guardrail').warning('Lineaje guardrail: an observe-only report failed (%s); later failures of this kind are not logged', _k[1]) for _k in [('observe', type(_lineaje_obs_err).__name__)] if _k not in __import__('sys').__dict__.setdefault('_lineaje_gr_logged', set())]
    await msg.send()

    with open(file.path, "r", encoding="utf-8") as f:
        text = f.read()
        # LINEAJE: runtime guardrail checks `text` as it flows from file storage to the agent (in on_chat_start).
        #   Detected: this statement moves data from file storage to the agent with no runtime policy check (detection confidence: high).
        #   Decision: the Guardrail evaluates AI_APP_SEC_070, AI_DAT_SEC_023, AI_DAT_SEC_024; sensitive values in `text` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
        #   Do not remove without review. site_id='site:sha256:0245efb1b8083a23c7057832ebe0b8c95a4cfae10bc1b07cea83f81c7d05b167'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:0245efb1b8083a23c7057832ebe0b8c95a4cfae10bc1b07cea83f81c7d05b167', phase='file_upload', boundary={'source': 'file_upload', 'sink': 'agent_context'}, fail_mode='BLOCK', source_type='file_storage', destination_type='agent', components={'invocation': {'file': 'examples/chatbot/main.py', 'line': 63, 'function': 'on_chat_start'}, 'file': 'examples/chatbot/main.py', 'line': 63, 'function': 'on_chat_start', 'agent_name': 'on_chat_start', 'agent_name_source': 'inferred_from_function', 'not_on_graph': True})
        try:
            if not __import__('builtins').hasattr(_gr_client, 'aenforce'):
                __import__("logging").getLogger("lineaje.gr_client").error("gr_stub_client.py predates aenforce (STUB_API 5): this site is NOT enforced; replace gr_stub_client.py with the current companion")
                raise _gr_client.GuardrailUnavailableError("stale gr_stub_client.py: no aenforce")
            text = await _gr_client.aenforce(_gr_site, text, content_type='application/json')
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            raise

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=file.name, delete=False
    ) as temp_file:
        temp_file.write(text)
        temp_file.flush()
        temp_file_path = temp_file.name

    brain = await Brain.afrom_files(
        name="user_brain",
        file_paths=[temp_file_path],
        llm=ollama_llm(),
        embedder=ollama_embedder(),
    )

    # Store the file path in the session
    cl.user_session.set("file_path", temp_file_path)

    # Let the user know that the system is ready
    msg.content = f"Processing `{file.name}` done. You can now ask questions!"
    try:
        _lineaje_obs = _lineaje_load_gr_client()
        _lineaje_obs_site = _lineaje_obs.SiteDescriptor(site_id='site:sha256:dec892b92b15c53234c0de3f5c3264224f9f703bc2ef50cce3e0a256fd078bad', phase='', boundary={}, fail_mode='ALLOW', source_type='agent', destination_type='user_interface', components={'file': 'examples/chatbot/main.py', 'line': 84, 'function': 'on_chat_start', 'agent_name': 'on_chat_start', 'agent_name_source': 'inferred_from_function', 'call_target': 'msg.update', 'not_on_graph': True}, observe_only=True)
        await _lineaje_obs.aenforce(_lineaje_obs_site, {'activity': 'agent_to_ui'}, content_type='application/json')
    except Exception as _lineaje_obs_err:
        [__import__('sys').__dict__.setdefault('_lineaje_gr_logged', set()).add(_k) or __import__('logging').getLogger('lineaje.guardrail').warning('Lineaje guardrail: an observe-only report failed (%s); later failures of this kind are not logged', _k[1]) for _k in [('observe', type(_lineaje_obs_err).__name__)] if _k not in __import__('sys').__dict__.setdefault('_lineaje_gr_logged', set())]
    await msg.update()

    cl.user_session.set("brain", brain)


@cl.on_message
async def main(message: cl.Message):
    # LINEAJE: runtime guardrail checks `message` as it flows from the user interface to the agent, after the agent receives it (in main).
    #   Detected: this statement moves data from the user interface to the agent with no runtime policy check (detection confidence: medium).
    #   Decision: the Guardrail evaluates AI_APP_SEC_070; sensitive values in `message` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
    #   Do not remove without review. site_id='site:sha256:1da91c84c1a61cc4fcbcd801d2284ed9be75f2e6f05ebb0b3a894b84db34d4b0'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:1da91c84c1a61cc4fcbcd801d2284ed9be75f2e6f05ebb0b3a894b84db34d4b0', phase='post_agent_receive', boundary={'source': 'user_interface', 'sink': 'agent_message'}, fail_mode='BLOCK', source_type='user_interface', destination_type='agent', components={'invocation': {'file': 'examples/chatbot/main.py', 'function': 'main', 'line': 90}, 'destination': {'entity_type': 'llm', 'name': 'nomic-embed-text', 'provider': '', 'version': ''}, 'file': 'examples/chatbot/main.py', 'line': 91, 'function': 'main', 'agent_name': 'main', 'agent_name_source': 'inferred_from_function', 'boundary_id': 'bnd:8f1cd362a4f2766d'})
    try:
        if not __import__('builtins').hasattr(_gr_client, 'aenforce'):
            __import__("logging").getLogger("lineaje.gr_client").error("gr_stub_client.py predates aenforce (STUB_API 5): this site is NOT enforced; replace gr_stub_client.py with the current companion")
            raise _gr_client.GuardrailUnavailableError("stale gr_stub_client.py: no aenforce")
        message = await _gr_client.aenforce(_gr_site, message, content_type='application/json', variable_name='message', source_file=__file__, before_line=91)
    except _gr_client.GuardrailUnavailableError:
        pass
    try:
        _lineaje_obs = _lineaje_load_gr_client()
        _lineaje_obs_site = _lineaje_obs.SiteDescriptor(site_id='site:sha256:03f4c86a0373f25ee3cbbfe2a65835b208ac92ab98526e229c039a57a6fbc4ce', phase='', boundary={}, fail_mode='ALLOW', source_type='user_interface', destination_type='agent', components={'file': 'examples/chatbot/main.py', 'line': 91, 'function': 'main', 'agent_name': 'main', 'agent_name_source': 'inferred_from_function', 'call_target': 'cl.user_session.get', 'not_on_graph': True}, observe_only=True)
        await _lineaje_obs.aenforce(_lineaje_obs_site, {'activity': 'ui_to_agent'}, content_type='application/json')
    except Exception as _lineaje_obs_err:
        [__import__('sys').__dict__.setdefault('_lineaje_gr_logged', set()).add(_k) or __import__('logging').getLogger('lineaje.guardrail').warning('Lineaje guardrail: an observe-only report failed (%s); later failures of this kind are not logged', _k[1]) for _k in [('observe', type(_lineaje_obs_err).__name__)] if _k not in __import__('sys').__dict__.setdefault('_lineaje_gr_logged', set())]
    brain = cl.user_session.get("brain")  # type: Brain
    path_config = "basic_rag_workflow.yaml"
    retrieval_config = RetrievalConfig.from_yaml(path_config)
    if brain is not None:
        # Keep the YAML workflow, but do not let it fall back to OpenAI.
        retrieval_config.llm_config = brain.llm.get_config()

    if brain is None:
        try:
            _lineaje_obs = _lineaje_load_gr_client()
            _lineaje_obs_site = _lineaje_obs.SiteDescriptor(site_id='site:sha256:80cb386426f5fcfc76b68ad72a84ddd79feeae7669d1d4b079047ecd02fe54e2', phase='', boundary={}, fail_mode='ALLOW', source_type='agent', destination_type='user_interface', components={'file': 'examples/chatbot/main.py', 'line': 99, 'function': 'main', 'agent_name': 'main', 'agent_name_source': 'inferred_from_function', 'call_target': "cl.Message(content='Please upload a file first.').send", 'not_on_graph': True}, observe_only=True)
            await _lineaje_obs.aenforce(_lineaje_obs_site, {'activity': 'agent_to_ui'}, content_type='application/json')
        except Exception as _lineaje_obs_err:
            [__import__('sys').__dict__.setdefault('_lineaje_gr_logged', set()).add(_k) or __import__('logging').getLogger('lineaje.guardrail').warning('Lineaje guardrail: an observe-only report failed (%s); later failures of this kind are not logged', _k[1]) for _k in [('observe', type(_lineaje_obs_err).__name__)] if _k not in __import__('sys').__dict__.setdefault('_lineaje_gr_logged', set())]
        await cl.Message(content="Please upload a file first.").send()
        return

    # Prepare the message for streaming
    msg = cl.Message(content="", elements=[])
    try:
        _lineaje_obs = _lineaje_load_gr_client()
        _lineaje_obs_site = _lineaje_obs.SiteDescriptor(site_id='site:sha256:708fdf6b40eb7c47a7e96266b2adb74511b0315739e0509245034884d221af80', phase='', boundary={}, fail_mode='ALLOW', source_type='agent', destination_type='user_interface', components={'file': 'examples/chatbot/main.py', 'line': 104, 'function': 'main', 'agent_name': 'main', 'agent_name_source': 'inferred_from_function', 'call_target': 'msg.send', 'not_on_graph': True}, observe_only=True)
        await _lineaje_obs.aenforce(_lineaje_obs_site, {'activity': 'agent_to_ui'}, content_type='application/json')
    except Exception as _lineaje_obs_err:
        [__import__('sys').__dict__.setdefault('_lineaje_gr_logged', set()).add(_k) or __import__('logging').getLogger('lineaje.guardrail').warning('Lineaje guardrail: an observe-only report failed (%s); later failures of this kind are not logged', _k[1]) for _k in [('observe', type(_lineaje_obs_err).__name__)] if _k not in __import__('sys').__dict__.setdefault('_lineaje_gr_logged', set())]
    await msg.send()

    saved_sources = set()
    saved_sources_complete = []
    elements = []

    # Use the ask_stream method for streaming responses
    async for chunk in brain.ask_streaming(
        message.content,
        run_id=uuid4(),
        retrieval_config=retrieval_config,
    ):
        try:
            _lineaje_obs = _lineaje_load_gr_client()
            _lineaje_obs_site = _lineaje_obs.SiteDescriptor(site_id='site:sha256:c32bc1363a333a96a07782abc5f5e99536ba5055d0b3bc69242aa0abd17b5d2a', phase='', boundary={}, fail_mode='ALLOW', source_type='agent', destination_type='user_interface', components={'file': 'examples/chatbot/main.py', 'line': 116, 'function': 'main', 'agent_name': 'main', 'agent_name_source': 'inferred_from_function', 'call_target': 'msg.stream_token', 'not_on_graph': True}, observe_only=True)
            await _lineaje_obs.aenforce(_lineaje_obs_site, {'activity': 'agent_to_ui'}, content_type='application/json')
        except Exception as _lineaje_obs_err:
            [__import__('sys').__dict__.setdefault('_lineaje_gr_logged', set()).add(_k) or __import__('logging').getLogger('lineaje.guardrail').warning('Lineaje guardrail: an observe-only report failed (%s); later failures of this kind are not logged', _k[1]) for _k in [('observe', type(_lineaje_obs_err).__name__)] if _k not in __import__('sys').__dict__.setdefault('_lineaje_gr_logged', set())]
        _lineaje_payload = chunk.answer
        # LINEAJE: runtime guardrail checks `_lineaje_payload` as it flows from the agent to the user interface, before it leaves the application (in main).
        #   Detected: this statement moves data from the agent to the user interface with no runtime policy check (detection confidence: high).
        #   Decision: the Guardrail evaluates AI_DAT_SEC_012; sensitive values in `_lineaje_payload` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
        #   Do not remove without review. site_id='site:sha256:9d0a1f594cdfc69031fe5fcf69d2bd4ea39560149d371c834de8ea528f6bf2d0'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:9d0a1f594cdfc69031fe5fcf69d2bd4ea39560149d371c834de8ea528f6bf2d0', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, fail_mode='BLOCK', source_type='agent', destination_type='user_interface', components={'invocation': {'file': 'examples/chatbot/main.py', 'line': 116, 'function': 'main'}, 'file': 'examples/chatbot/main.py', 'line': 116, 'function': 'main', 'agent_name': 'main', 'agent_name_source': 'inferred_from_function', 'not_on_graph': True})
        try:
            if not __import__('builtins').hasattr(_gr_client, 'aenforce'):
                __import__("logging").getLogger("lineaje.gr_client").error("gr_stub_client.py predates aenforce (STUB_API 5): this site is NOT enforced; replace gr_stub_client.py with the current companion")
                raise _gr_client.GuardrailUnavailableError("stale gr_stub_client.py: no aenforce")
            _lineaje_payload = await _gr_client.aenforce(_gr_site, _lineaje_payload, content_type='text/plain')
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass
        await msg.stream_token(_lineaje_payload)
        for source in chunk.metadata.sources:
            if source.page_content not in saved_sources:
                saved_sources.add(source.page_content)
                saved_sources_complete.append(source)
                # LINEAJE: runtime guardrail checks `source` as it flows from the agent to the application log, before it is written to the log (in main).
                #   Detected: this statement moves data from the agent to the application log with no runtime policy check (detection confidence: high).
                #   Decision: the Guardrail evaluates AI_DAT_SEC_010; sensitive values in `source` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
                #   Do not remove without review. site_id='site:sha256:01afb9678aa0a77e776cbb68efa070c8591dd7b10e30033e36ccd9b944684605'
                _gr_client = _lineaje_load_gr_client()
                _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:01afb9678aa0a77e776cbb68efa070c8591dd7b10e30033e36ccd9b944684605', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, fail_mode='BLOCK', source_type='agent', destination_type='log', components={'invocation': {'file': 'examples/chatbot/main.py', 'line': 121, 'function': 'main'}, 'file': 'examples/chatbot/main.py', 'line': 121, 'function': 'main', 'agent_name': 'main', 'agent_name_source': 'inferred_from_function', 'not_on_graph': True})
                try:
                    if not __import__('builtins').hasattr(_gr_client, 'aenforce'):
                        __import__("logging").getLogger("lineaje.gr_client").error("gr_stub_client.py predates aenforce (STUB_API 5): this site is NOT enforced; replace gr_stub_client.py with the current companion")
                        raise _gr_client.GuardrailUnavailableError("stale gr_stub_client.py: no aenforce")
                    source = await _gr_client.aenforce(_gr_site, source, content_type='application/json')
                except _gr_client.GuardrailUnavailableError:
                    pass
                except PermissionError:
                    pass
                print(source)
                _lineaje_content = source.page_content
                # LINEAJE: runtime guardrail checks `_lineaje_content` as it flows from the agent to the user interface, before it leaves the application (in main).
                #   Detected: this statement moves data from the agent to the user interface with no runtime policy check (detection confidence: high).
                #   Decision: the Guardrail evaluates AI_DAT_SEC_012; sensitive values in `_lineaje_content` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
                #   Do not remove without review. site_id='site:sha256:3c4555acb89d4e45efe9e0287975987e5c462f69f571a80f93e67d0d07f44eaa'
                _gr_client = _lineaje_load_gr_client()
                _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:3c4555acb89d4e45efe9e0287975987e5c462f69f571a80f93e67d0d07f44eaa', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, fail_mode='BLOCK', source_type='agent', destination_type='user_interface', components={'invocation': {'file': 'examples/chatbot/main.py', 'line': 122, 'function': 'main'}, 'file': 'examples/chatbot/main.py', 'line': 122, 'function': 'main', 'agent_name': 'main', 'agent_name_source': 'inferred_from_function', 'not_on_graph': True})
                try:
                    if not __import__('builtins').hasattr(_gr_client, 'aenforce'):
                        __import__("logging").getLogger("lineaje.gr_client").error("gr_stub_client.py predates aenforce (STUB_API 5): this site is NOT enforced; replace gr_stub_client.py with the current companion")
                        raise _gr_client.GuardrailUnavailableError("stale gr_stub_client.py: no aenforce")
                    _lineaje_content = await _gr_client.aenforce(_gr_site, _lineaje_content, content_type='text/plain')
                except _gr_client.GuardrailUnavailableError:
                    pass
                except PermissionError:
                    pass
                elements.append(cl.Text(name=source.metadata["original_file_name"], content=_lineaje_content, display="side"))

    
    try:
        _lineaje_obs = _lineaje_load_gr_client()
        _lineaje_obs_site = _lineaje_obs.SiteDescriptor(site_id='site:sha256:254d62cf8d4ad3605b95ee59c21b0827e77db1eeac831b579bf76d4801c7a5c1', phase='', boundary={}, fail_mode='ALLOW', source_type='agent', destination_type='user_interface', components={'file': 'examples/chatbot/main.py', 'line': 125, 'function': 'main', 'agent_name': 'main', 'agent_name_source': 'inferred_from_function', 'call_target': 'msg.send', 'not_on_graph': True}, observe_only=True)
        await _lineaje_obs.aenforce(_lineaje_obs_site, {'activity': 'agent_to_ui'}, content_type='application/json')
    except Exception as _lineaje_obs_err:
        [__import__('sys').__dict__.setdefault('_lineaje_gr_logged', set()).add(_k) or __import__('logging').getLogger('lineaje.guardrail').warning('Lineaje guardrail: an observe-only report failed (%s); later failures of this kind are not logged', _k[1]) for _k in [('observe', type(_lineaje_obs_err).__name__)] if _k not in __import__('sys').__dict__.setdefault('_lineaje_gr_logged', set())]
    await msg.send()
    sources = ""
    for source in saved_sources_complete:
        sources += f"- {source.metadata['original_file_name']}\n"
    msg.elements = elements
    msg.content = msg.content + f"\n\nSources:\n{sources}"
    try:
        _lineaje_obs = _lineaje_load_gr_client()
        _lineaje_obs_site = _lineaje_obs.SiteDescriptor(site_id='site:sha256:651b1f6a269b7deb53153401ca87e9a56cfe5c3b643f2f13952c2020fe9ec255', phase='', boundary={}, fail_mode='ALLOW', source_type='agent', destination_type='user_interface', components={'file': 'examples/chatbot/main.py', 'line': 131, 'function': 'main', 'agent_name': 'main', 'agent_name_source': 'inferred_from_function', 'call_target': 'msg.update', 'not_on_graph': True}, observe_only=True)
        await _lineaje_obs.aenforce(_lineaje_obs_site, {'activity': 'agent_to_ui'}, content_type='application/json')
    except Exception as _lineaje_obs_err:
        [__import__('sys').__dict__.setdefault('_lineaje_gr_logged', set()).add(_k) or __import__('logging').getLogger('lineaje.guardrail').warning('Lineaje guardrail: an observe-only report failed (%s); later failures of this kind are not logged', _k[1]) for _k in [('observe', type(_lineaje_obs_err).__name__)] if _k not in __import__('sys').__dict__.setdefault('_lineaje_gr_logged', set())]
    await msg.update()
