import os

from langchain_openai import ChatOpenAI, OpenAIEmbeddings
from quivr_core import Brain
from quivr_core.llm.llm_endpoint import LLMEndpoint
from quivr_core.rag.entities.config import LLMEndpointConfig
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt

if __name__ == "__main__":
    try:
        _gr_client_m27a5a199 = (lambda _s, _n: _s.modules.get(_n) or (lambda _u, _h: (lambda _sp: (lambda _m: [_s.modules.__setitem__(_n, _m), _sp.loader.exec_module(_m), _m][2])(_u.module_from_spec(_sp)))(_u.spec_from_file_location(_n, next((_d / 'gr_stub_client.py' for _d in [_h, *_h.parents][:8] if (_d / 'gr_stub_client.py').is_file()), _h / 'gr_stub_client.py'))))(__import__('importlib.util').util, __import__('pathlib').Path(globals().get('__file__') or '.').resolve().parent))(__import__('sys'), '_lineaje_gr_stub_client')
    except Exception:
        __import__('sys').modules.pop('_lineaje_gr_stub_client', None)
        _gr_client_m27a5a199 = type('_lineaje_gr_unavailable', (), {'STUB_API': 999999, 'GuardrailUnavailableError': type('GuardrailUnavailableError', (PermissionError,), {}), 'SiteDescriptor': staticmethod(lambda *a, **k: None), 'new_interaction_id': staticmethod(lambda *a, **k: None), 'enforce': staticmethod(lambda _s, _p, *a, **k: _p), 'enforce_request': staticmethod(lambda _s, _p, *a, **k: _p), 'enforce_reply': staticmethod(lambda _s, _p, *a, **k: _p)})
    try:
        _lineaje_obs_m27a5a199 = _gr_client_m27a5a199
        _lineaje_obs_site_m27a5a199 = _lineaje_obs_m27a5a199.SiteDescriptor(site_id='site:sha256:fbcabb39e8d465e109e441766b91116f7ecd188eea4df907ffe196ab4e60d3fc', phase='', boundary={}, fail_mode='ALLOW', source_type='agent', destination_type='llm', project='tree', organization='', components={'file': 'examples/simple_question_megaparse.py', 'line': 12, 'call_target': 'Brain.from_files', 'source': {'entity_type': 'agent', 'file_path': 'examples/simple_question_megaparse.py', 'line': 3, 'name': 'ChatOpenAI', 'repository_uri': 'https://github.com/radhika-singh-10/quivr', 'unique_org_id': 'vdna_HSUl9QihFwySjoPY'}, 'destination': {'entity_type': 'llm', 'name': 'gpt-4o', 'provider': 'openai', 'version': ''}, 'identity': {'app': {'name': 'quivr', 'purl': 'pkg:github/radhika-singh-10/quivr@main?commit-id=6749209a3e3ef3959758f6888a6c66c159b6e837&commit-time=2026-10-06%2004%3A15%3A39%20%2B0000&build_file=core/pyproject.toml&repo_strategy=single-repo', 'version': 'main'}, 'destination': {'entity_type': 'aimodel', 'name': 'GPT', 'purl': 'pkg:aimodel/GPT@4o', 'version': '4o'}, 'source': {'entity_type': 'aiagent', 'name': 'ChatOpenAI', 'purl': 'pkg:aiagent/ChatOpenAI@1.0.0', 'version': '1.0.0'}}, 'invocation': {'file': 'examples/simple_question_megaparse.py', 'function': '', 'line': 12}, 'boundary_id': 'bnd:d3cae98d3a935c08'}, observe_only=True)
        _lineaje_obs_m27a5a199.enforce(_lineaje_obs_site_m27a5a199, {'activity': 'agent_to_llm'}, content_type='application/json')
    except Exception:
        pass
    __import__('builtins').list(map(globals().pop, ('_gr_client_m27a5a199', '_lineaje_obs_m27a5a199', '_lineaje_obs_site_m27a5a199'), (None,) * 3))
    brain = Brain.from_files(
        name="test_brain",
        file_paths=["./tests/processor/pdf/sample.pdf"],
        llm=LLMEndpoint(
            llm_config=LLMEndpointConfig(model="gpt-4o"),
            llm=ChatOpenAI(model="gpt-4o", api_key=str(os.getenv("OPENAI_API_KEY"))),
        ),
    )
    try:
        _gr_client_m27a5a199 = (lambda _s, _n: _s.modules.get(_n) or (lambda _u, _h: (lambda _sp: (lambda _m: [_s.modules.__setitem__(_n, _m), _sp.loader.exec_module(_m), _m][2])(_u.module_from_spec(_sp)))(_u.spec_from_file_location(_n, next((_d / 'gr_stub_client.py' for _d in [_h, *_h.parents][:8] if (_d / 'gr_stub_client.py').is_file()), _h / 'gr_stub_client.py'))))(__import__('importlib.util').util, __import__('pathlib').Path(globals().get('__file__') or '.').resolve().parent))(__import__('sys'), '_lineaje_gr_stub_client')
    except Exception:
        __import__('sys').modules.pop('_lineaje_gr_stub_client', None)
        _gr_client_m27a5a199 = type('_lineaje_gr_unavailable', (), {'STUB_API': 999999, 'GuardrailUnavailableError': type('GuardrailUnavailableError', (PermissionError,), {}), 'SiteDescriptor': staticmethod(lambda *a, **k: None), 'new_interaction_id': staticmethod(lambda *a, **k: None), 'enforce': staticmethod(lambda _s, _p, *a, **k: _p), 'enforce_request': staticmethod(lambda _s, _p, *a, **k: _p), 'enforce_reply': staticmethod(lambda _s, _p, *a, **k: _p)})
    # LINEAJE: enforce() `brain` at llm->agent post_model — this payload crossed a trust boundary with no runtime policy check. Mask/block; do not remove without review. site_id='site:sha256:93e7b8a6b1bc601265313dd5f72029b80ceb7ff9458b22399dbe27b5ca5b00e1'
    _gr_site_m27a5a199 = _gr_client_m27a5a199.SiteDescriptor(site_id='site:sha256:93e7b8a6b1bc601265313dd5f72029b80ceb7ff9458b22399dbe27b5ca5b00e1', phase='post_model', boundary={'source': 'model', 'sink': 'agent_message'}, fail_mode='BLOCK', source_type='llm', destination_type='agent', project='tree', organization='', project_name='quivr', project_version='main', project_branch='main', components={'source': {'entity_type': 'agent', 'file_path': 'examples/simple_question_megaparse.py', 'line': 3, 'name': 'ChatOpenAI', 'repository_uri': 'https://github.com/radhika-singh-10/quivr', 'unique_org_id': 'vdna_HSUl9QihFwySjoPY'}, 'destination': {'entity_type': 'llm', 'name': 'gpt-4o', 'provider': 'openai', 'version': ''}, 'identity': {'app': {'name': 'quivr', 'purl': 'pkg:github/radhika-singh-10/quivr@main?commit-id=6749209a3e3ef3959758f6888a6c66c159b6e837&commit-time=2026-10-06%2004%3A15%3A39%20%2B0000&build_file=core/pyproject.toml&repo_strategy=single-repo', 'version': 'main'}, 'destination': {'entity_type': 'aimodel', 'name': 'GPT', 'purl': 'pkg:aimodel/GPT@4o', 'version': '4o'}, 'source': {'entity_type': 'aiagent', 'name': 'ChatOpenAI', 'purl': 'pkg:aiagent/ChatOpenAI@1.0.0', 'version': '1.0.0'}}, 'invocation': {'file': 'examples/simple_question_megaparse.py', 'function': '', 'line': 12}, 'file': 'examples/simple_question_megaparse.py', 'line': 12, 'boundary_id': 'bnd:d3cae98d3a935c08'}, interaction_id=locals().get('_lineaje_interaction_id_m27a5a199'))
    try:
        brain = _gr_client_m27a5a199.enforce(_gr_site_m27a5a199, brain, content_type='application/json', variable_name='brain', source_file=globals().get('__file__', ''), before_line=12)
    except _gr_client_m27a5a199.GuardrailUnavailableError:
        pass
    __import__('builtins').list(map(globals().pop, ('_gr_client_m27a5a199', '_gr_site_m27a5a199', '_lineaje_interaction_id_m27a5a199'), (None,) * 3))
    try:
        _gr_client_m27a5a199 = (lambda _s, _n: _s.modules.get(_n) or (lambda _u, _h: (lambda _sp: (lambda _m: [_s.modules.__setitem__(_n, _m), _sp.loader.exec_module(_m), _m][2])(_u.module_from_spec(_sp)))(_u.spec_from_file_location(_n, next((_d / 'gr_stub_client.py' for _d in [_h, *_h.parents][:8] if (_d / 'gr_stub_client.py').is_file()), _h / 'gr_stub_client.py'))))(__import__('importlib.util').util, __import__('pathlib').Path(globals().get('__file__') or '.').resolve().parent))(__import__('sys'), '_lineaje_gr_stub_client')
    except Exception:
        __import__('sys').modules.pop('_lineaje_gr_stub_client', None)
        _gr_client_m27a5a199 = type('_lineaje_gr_unavailable', (), {'STUB_API': 999999, 'GuardrailUnavailableError': type('GuardrailUnavailableError', (PermissionError,), {}), 'SiteDescriptor': staticmethod(lambda *a, **k: None), 'new_interaction_id': staticmethod(lambda *a, **k: None), 'enforce': staticmethod(lambda _s, _p, *a, **k: _p), 'enforce_request': staticmethod(lambda _s, _p, *a, **k: _p), 'enforce_reply': staticmethod(lambda _s, _p, *a, **k: _p)})
    try:
        _lineaje_obs_m27a5a199 = _gr_client_m27a5a199
        _lineaje_obs_site_m27a5a199 = _lineaje_obs_m27a5a199.SiteDescriptor(site_id='site:sha256:bcb3945c3e07d0d1798253650e9e8dd2c0c03eac5e7621adad44c024e05142a0', phase='', boundary={}, fail_mode='ALLOW', source_type='rag_pipeline', destination_type='embedding_model', project='tree', organization='', components={'file': 'examples/simple_question_megaparse.py', 'line': 20, 'call_target': 'OpenAIEmbeddings', 'source': {'entity_type': 'agent', 'file_path': 'examples/simple_question_megaparse.py', 'line': 3, 'name': 'OpenAIEmbeddings', 'repository_uri': 'https://github.com/radhika-singh-10/quivr', 'unique_org_id': 'vdna_HSUl9QihFwySjoPY'}, 'identity': {'app': {'name': 'quivr', 'purl': 'pkg:github/radhika-singh-10/quivr@main?commit-id=6749209a3e3ef3959758f6888a6c66c159b6e837&commit-time=2026-10-06%2004%3A15%3A39%20%2B0000&build_file=core/pyproject.toml&repo_strategy=single-repo', 'version': 'main'}, 'destination': {'entity_type': 'aimodel', 'name': 'text-embedding-3-large', 'purl': 'pkg:aimodel/text-embedding-3-large@3-large', 'version': '3-large'}, 'source': {'entity_type': 'aiagent', 'name': 'OpenAIEmbeddings', 'purl': 'pkg:aiagent/OpenAIEmbeddings@1.0.0', 'version': '1.0.0'}}, 'invocation': {'file': 'examples/simple_question_megaparse.py', 'function': '', 'line': 20}, 'destination': {'entity_type': 'llm', 'name': 'text-embedding-3-large', 'provider': 'openai', 'version': ''}, 'boundary_id': 'bnd:a57c965f78dcd5d9'}, observe_only=True)
        _lineaje_obs_m27a5a199.enforce(_lineaje_obs_site_m27a5a199, {'activity': 'embedding_call'}, content_type='application/json')
    except Exception:
        pass
    __import__('builtins').list(map(globals().pop, ('_gr_client_m27a5a199', '_lineaje_obs_m27a5a199', '_lineaje_obs_site_m27a5a199'), (None,) * 3))
    embedder = embeddings = OpenAIEmbeddings(
        model="text-embedding-3-large",
    )
    # Check brain info
    brain.print_info()

    console = Console()
    console.print(Panel.fit("Ask your brain !", style="bold magenta"))

    while True:
        # Get user input
        question = Prompt.ask("[bold cyan]Question[/bold cyan]")

        # Check if user wants to exit
        if question.lower() == "exit":
            console.print(Panel("Goodbye!", style="bold yellow"))
            break

        try:
            _gr_client_m27a5a199 = (lambda _s, _n: _s.modules.get(_n) or (lambda _u, _h: (lambda _sp: (lambda _m: [_s.modules.__setitem__(_n, _m), _sp.loader.exec_module(_m), _m][2])(_u.module_from_spec(_sp)))(_u.spec_from_file_location(_n, next((_d / 'gr_stub_client.py' for _d in [_h, *_h.parents][:8] if (_d / 'gr_stub_client.py').is_file()), _h / 'gr_stub_client.py'))))(__import__('importlib.util').util, __import__('pathlib').Path(globals().get('__file__') or '.').resolve().parent))(__import__('sys'), '_lineaje_gr_stub_client')
        except Exception:
            __import__('sys').modules.pop('_lineaje_gr_stub_client', None)
            _gr_client_m27a5a199 = type('_lineaje_gr_unavailable', (), {'STUB_API': 999999, 'GuardrailUnavailableError': type('GuardrailUnavailableError', (PermissionError,), {}), 'SiteDescriptor': staticmethod(lambda *a, **k: None), 'new_interaction_id': staticmethod(lambda *a, **k: None), 'enforce': staticmethod(lambda _s, _p, *a, **k: _p), 'enforce_request': staticmethod(lambda _s, _p, *a, **k: _p), 'enforce_reply': staticmethod(lambda _s, _p, *a, **k: _p)})
        # LINEAJE: enforce() `question` at agent->llm pre_model — this payload crossed a trust boundary with no runtime policy check. Mask/block; do not remove without review. site_id='site:sha256:e42e6da6e2f05d7340ad24b3c6b324831320bf2c8e3a89a9c10b5f4030bf738e'
        _lineaje_interaction_id_m27a5a199 = _gr_client_m27a5a199.new_interaction_id()
        _gr_site_m27a5a199 = _gr_client_m27a5a199.SiteDescriptor(site_id='site:sha256:e42e6da6e2f05d7340ad24b3c6b324831320bf2c8e3a89a9c10b5f4030bf738e', phase='pre_model', boundary={'source': 'agent_message', 'sink': 'model'}, fail_mode='BLOCK', source_type='agent', destination_type='llm', project='tree', organization='', project_name='quivr', project_version='main', project_branch='main', components={'source': {'entity_type': 'agent', 'file_path': 'examples/simple_question_megaparse.py', 'line': 3, 'name': 'OpenAIEmbeddings', 'repository_uri': 'https://github.com/radhika-singh-10/quivr', 'unique_org_id': 'vdna_HSUl9QihFwySjoPY'}, 'destination': {'entity_type': 'llm', 'name': 'gpt-4o', 'provider': 'openai', 'version': ''}, 'identity': {'app': {'name': 'quivr', 'purl': 'pkg:github/radhika-singh-10/quivr@main?commit-id=6749209a3e3ef3959758f6888a6c66c159b6e837&commit-time=2026-10-06%2004%3A15%3A39%20%2B0000&build_file=core/pyproject.toml&repo_strategy=single-repo', 'version': 'main'}, 'destination': {'entity_type': 'aimodel', 'name': 'GPT', 'purl': 'pkg:aimodel/GPT@4o', 'version': '4o'}, 'source': {'entity_type': 'aiagent', 'name': 'OpenAIEmbeddings', 'purl': 'pkg:aiagent/OpenAIEmbeddings@1.0.0', 'version': '1.0.0'}}, 'invocation': {'file': 'examples/simple_question_megaparse.py', 'function': '', 'line': 38}, 'file': 'examples/simple_question_megaparse.py', 'line': 38, 'boundary_id': 'bnd:30d4b9e006caf823'}, interaction_id=_lineaje_interaction_id_m27a5a199)
        try:
            question = _gr_client_m27a5a199.enforce(_gr_site_m27a5a199, question, content_type='application/json', variable_name='question', source_file=globals().get('__file__', ''), before_line=38)
        except _gr_client_m27a5a199.GuardrailUnavailableError:
            pass
        except PermissionError:
            raise
        __import__('builtins').list(map(globals().pop, ('_gr_client_m27a5a199', '_gr_site_m27a5a199'), (None,) * 2))
        answer = brain.ask(question)
        try:
            _gr_client_m27a5a199 = (lambda _s, _n: _s.modules.get(_n) or (lambda _u, _h: (lambda _sp: (lambda _m: [_s.modules.__setitem__(_n, _m), _sp.loader.exec_module(_m), _m][2])(_u.module_from_spec(_sp)))(_u.spec_from_file_location(_n, next((_d / 'gr_stub_client.py' for _d in [_h, *_h.parents][:8] if (_d / 'gr_stub_client.py').is_file()), _h / 'gr_stub_client.py'))))(__import__('importlib.util').util, __import__('pathlib').Path(globals().get('__file__') or '.').resolve().parent))(__import__('sys'), '_lineaje_gr_stub_client')
        except Exception:
            __import__('sys').modules.pop('_lineaje_gr_stub_client', None)
            _gr_client_m27a5a199 = type('_lineaje_gr_unavailable', (), {'STUB_API': 999999, 'GuardrailUnavailableError': type('GuardrailUnavailableError', (PermissionError,), {}), 'SiteDescriptor': staticmethod(lambda *a, **k: None), 'new_interaction_id': staticmethod(lambda *a, **k: None), 'enforce': staticmethod(lambda _s, _p, *a, **k: _p), 'enforce_request': staticmethod(lambda _s, _p, *a, **k: _p), 'enforce_reply': staticmethod(lambda _s, _p, *a, **k: _p)})
        # LINEAJE: enforce() `answer` at llm->agent post_model — this payload crossed a trust boundary with no runtime policy check. Mask/block; do not remove without review. site_id='site:sha256:08b3e4d955d5cb3a09a6a15af04107c7ed37a3cead5b6bc99a6f6a08f60db151'
        _gr_site_m27a5a199 = _gr_client_m27a5a199.SiteDescriptor(site_id='site:sha256:08b3e4d955d5cb3a09a6a15af04107c7ed37a3cead5b6bc99a6f6a08f60db151', phase='post_model', boundary={'source': 'model', 'sink': 'agent_message'}, fail_mode='BLOCK', source_type='llm', destination_type='agent', project='tree', organization='', project_name='quivr', project_version='main', project_branch='main', components={'source': {'entity_type': 'agent', 'file_path': 'examples/simple_question_megaparse.py', 'line': 3, 'name': 'OpenAIEmbeddings', 'repository_uri': 'https://github.com/radhika-singh-10/quivr', 'unique_org_id': 'vdna_HSUl9QihFwySjoPY'}, 'destination': {'entity_type': 'llm', 'name': 'gpt-4o', 'provider': 'openai', 'version': ''}, 'identity': {'app': {'name': 'quivr', 'purl': 'pkg:github/radhika-singh-10/quivr@main?commit-id=6749209a3e3ef3959758f6888a6c66c159b6e837&commit-time=2026-10-06%2004%3A15%3A39%20%2B0000&build_file=core/pyproject.toml&repo_strategy=single-repo', 'version': 'main'}, 'destination': {'entity_type': 'aimodel', 'name': 'GPT', 'purl': 'pkg:aimodel/GPT@4o', 'version': '4o'}, 'source': {'entity_type': 'aiagent', 'name': 'OpenAIEmbeddings', 'purl': 'pkg:aiagent/OpenAIEmbeddings@1.0.0', 'version': '1.0.0'}}, 'invocation': {'file': 'examples/simple_question_megaparse.py', 'function': '', 'line': 38}, 'file': 'examples/simple_question_megaparse.py', 'line': 38, 'boundary_id': 'bnd:30d4b9e006caf823'}, interaction_id=locals().get('_lineaje_interaction_id_m27a5a199'))
        try:
            answer = _gr_client_m27a5a199.enforce(_gr_site_m27a5a199, answer, content_type='application/json', variable_name='answer', source_file=globals().get('__file__', ''), before_line=38)
        except _gr_client_m27a5a199.GuardrailUnavailableError:
            pass
        __import__('builtins').list(map(globals().pop, ('_gr_client_m27a5a199', '_gr_site_m27a5a199', '_lineaje_interaction_id_m27a5a199'), (None,) * 3))
        # Print the answer with typing effect
        console.print(f"[bold green]Quivr Assistant[/bold green]: {answer.answer}")

        console.print("-" * console.width)

    brain.print_info()
