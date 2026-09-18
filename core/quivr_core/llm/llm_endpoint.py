# Copyright (c) Lineaje, Inc. All rights reserved.
# gr_check() POSTs to GR_SERVICE_URL+/enforce; fail-open unless GRBlockedError.
class GRBlockedError(Exception):
    def __init__(self, policy_id, reason):
        self.policy_id, self.reason = policy_id, reason
        super().__init__("Guardrail block for policy %r: %s" % (policy_id, reason))

def gr_check(data, source_type, destination_type, tenant_id="", timeout=5.0, **context):
    import json as _j, logging as _lg, os as _os, urllib.error as _ue, urllib.request as _ur
    _log = _lg.getLogger("lineaje.gr_client")
    url = _os.environ.get("GR_SERVICE_URL", "")
    if not url:
        return data
    tid = tenant_id or _os.environ.get("GR_TENANT_ID", "")
    bearer = _os.environ.get("GR_BEARER_TOKEN") or _os.environ.get("LINEAJE_PAT_TOKEN") or _os.environ.get("LINEAJE_PAT", "")
    hop_label = source_type + "->" + destination_type
    params_key = "out_params" if destination_type == "agent" else "in_params"
    try:
        headers = {"Content-Type": "application/json"}
        if bearer:
            headers["Authorization"] = "Bearer " + bearer
        body = {"source_type": source_type, "destination_type": destination_type, params_key: {"data": data}}
        for _k, _v in context.items():
            if _v:
                body[_k] = _v
        if tid:
            body["tenant_id"] = tid
        req = _ur.Request(url.rstrip("/") + "/enforce", data=_j.dumps(body).encode(), headers=headers, method="POST")
        with _ur.urlopen(req, timeout=timeout) as resp:
            result = _j.loads(resp.read())
    except Exception as exc:
        if isinstance(exc, _ue.HTTPError) and exc.code == 403:
            try: detail = _j.loads(exc.read()).get("detail", {})
            except Exception: detail = {}
            blocked_by = detail.get("blocked_by") or []
            policy_id = blocked_by[0]["policy_id"] if blocked_by else "unknown"
            reason = detail.get("message", "Request denied by policy enforcement.")
            _log.warning("gr_client[%s]: BLOCKED by policy=%s — %s", hop_label, policy_id, reason)
            if _os.environ.get("GR_BLOCK_MODE", "enforce").lower() == "audit":
                return data
            raise GRBlockedError(policy_id, reason)
        _log.warning("gr_client[%s]: GR service call failed (%s) — failing open", hop_label, exc)
        return data
    if result.get("status") == "escalate":
        _log.warning("gr_client[%s]: escalation flagged — passing through for human review", hop_label)
    return result.get("result", {}).get("data", data)
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
import logging
import os
import time
from typing import Union
from urllib.parse import parse_qs, urlparse

import tiktoken
from langchain_anthropic import ChatAnthropic
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_groq import ChatGroq
from langchain_mistralai import ChatMistralAI
from langchain_openai import AzureChatOpenAI, ChatOpenAI
from pydantic import SecretStr

from quivr_core.brain.info import LLMInfo
from quivr_core.rag.entities.config import DefaultModelSuppliers, LLMEndpointConfig
from quivr_core.rag.utils import model_supports_function_calling

logger = logging.getLogger("quivr_core")


class LLMTokenizer:
    _cache: dict[
        int, tuple["LLMTokenizer", int, float]
    ] = {}  # {hash: (tokenizer, size_bytes, last_access_time)}
    _max_cache_size_mb: int = 50
    _max_cache_count: int = 5  # Default maximum number of cached tokenizers
    _current_cache_size: int = 0
    _default_size: int = 5 * 1024 * 1024

    def __init__(self, tokenizer_hub: str | None, fallback_tokenizer: str):
        self.tokenizer_hub = tokenizer_hub
        self.fallback_tokenizer = fallback_tokenizer

        if self.tokenizer_hub:
            # To prevent the warning
            # huggingface/tokenizers: The current process just got forked, after parallelism has already been used. Disabling parallelism to avoid deadlocks...
            os.environ["TOKENIZERS_PARALLELISM"] = (
                "false"
                if not os.environ.get("TOKENIZERS_PARALLELISM")
                else os.environ["TOKENIZERS_PARALLELISM"]
            )
            try:
                if "text-embedding-ada-002" in self.tokenizer_hub:
                    from transformers import GPT2TokenizerFast

                    self.tokenizer = GPT2TokenizerFast.from_pretrained(
                        self.tokenizer_hub
                    )
                else:
                    from transformers import AutoTokenizer

                    self.tokenizer = AutoTokenizer.from_pretrained(self.tokenizer_hub)
            except OSError:  # if we don't manage to connect to huggingface and/or no cached models are present
                _lineaje_payload = f"Cannot acces the configured tokenizer from {self.tokenizer_hub}, using the default tokenizer {self.fallback_tokenizer}"
                # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — scan flagged AI_DAT_SEC_029 (Enforce decision logging, audit trail, and forensic readiness for AI-driven actions.); AI_DAT_SEC_030 (Enforce minimum six-month log retention for high-risk AI systems); AI_APP_SEC_028 (Do not use LLMs from the organization's disallowed list). Mask/block; do not remove without review. site_id='site:sha256:3431c33498ac41aec0be6ff2899841e2181c4a83051bdd6279f55ad61a90b45d'
                _gr_client = _lineaje_load_gr_client()
                _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:3431c33498ac41aec0be6ff2899841e2181c4a83051bdd6279f55ad61a90b45d', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log')
                _lineaje_payload = _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json')
                logger.warning(
                    _lineaje_payload
                )
                self.tokenizer = tiktoken.get_encoding(self.fallback_tokenizer)
        else:
            self.tokenizer = tiktoken.get_encoding(self.fallback_tokenizer)

        # More accurate size estimation
        self._size_bytes = self._calculate_tokenizer_size()

    def _calculate_tokenizer_size(self) -> int:
        """Calculate size of tokenizer by summing the sizes of its vocabulary and model files"""
        # By default, return a size of 5 MB
        if not hasattr(self.tokenizer, "vocab_files_names") or not hasattr(
            self.tokenizer, "init_kwargs"
        ):
            return self._default_size

        total_size = 0

        # Get the file keys from vocab_files_names
        file_keys = self.tokenizer.vocab_files_names.keys()
        # Look up these files in init_kwargs
        for key in file_keys:
            if file_path := self.tokenizer.init_kwargs.get(key):
                try:
                    total_size += os.path.getsize(file_path)
                except (OSError, FileNotFoundError):
                    _lineaje_payload = f"Could not access tokenizer file: {file_path}"
                    # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — scan flagged AI_DAT_SEC_029 (Enforce decision logging, audit trail, and forensic readiness for AI-driven actions.). Mask/block; do not remove without review. site_id='site:sha256:e8ab572edab51d0716f97ff93d34b6c18e1898068bf4429ab48d2ad7fed9b42f'
                    _gr_client = _lineaje_load_gr_client()
                    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:e8ab572edab51d0716f97ff93d34b6c18e1898068bf4429ab48d2ad7fed9b42f', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log')
                    _lineaje_payload = _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json')
                    logger.debug(_lineaje_payload)

        return total_size if total_size > 0 else self._default_size

    @classmethod
    def load(cls, tokenizer_hub: str, fallback_tokenizer: str):
        cache_key = hash(str(tokenizer_hub))

        # If in cache, update last access time and return
        if cache_key in cls._cache:
            tokenizer, size, _ = cls._cache[cache_key]
            cls._cache[cache_key] = (tokenizer, size, time.time())
            # LINEAJE: enforce() `tokenizer` at agent->user_interface data_egress — scan flagged AI_DAT_SEC_029 (Enforce decision logging, audit trail, and forensic readiness for AI-driven actions.); AI_DAT_SEC_030 (Enforce minimum six-month log retention for high-risk AI systems); AI_APP_SEC_028 (Do not use LLMs from the organization's disallowed list). Mask/block; do not remove without review. site_id='site:sha256:1c87f73511b3705125be7eb1b9ef5b0019ba32a52c86a72c82db0d3ab0159cb0'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:1c87f73511b3705125be7eb1b9ef5b0019ba32a52c86a72c82db0d3ab0159cb0', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface')
            tokenizer = _gr_client.enforce(_gr_site, tokenizer, content_type='text/plain')
            # LINEAJE: enforce() `tokenizer` at agent->user_interface data_egress — scan flagged AI_DAT_SEC_029 (Enforce decision logging, audit trail, and forensic readiness for AI-driven actions.); AI_DAT_SEC_030 (Enforce minimum six-month log retention for high-risk AI systems); AI_APP_SEC_028 (Do not use LLMs from the organization's disallowed list). Mask/block; do not remove without review. site_id='site:sha256:42aa2857bf600e5ddc797debb910096c6af6fec90269378227a80c372d8a984f'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:42aa2857bf600e5ddc797debb910096c6af6fec90269378227a80c372d8a984f', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface')
            tokenizer = _gr_client.enforce(_gr_site, tokenizer, content_type='text/plain')
            try:
                tokenizer = gr_check(tokenizer, "agent", "user_interface", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:42aa2857bf600e5ddc797debb910096c6af6fec90269378227a80c372d8a984f')
            except Exception as _gr_exc:
                if type(_gr_exc).__name__ == "GRBlockedError": raise
                tokenizer = tokenizer
                __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
            return tokenizer

        # Create new instance
        instance = cls(tokenizer_hub, fallback_tokenizer)

        # Check if adding this would exceed either cache limit
        while (
            cls._current_cache_size + instance._size_bytes
            > cls._max_cache_size_mb * 1024 * 1024
            or len(cls._cache) >= cls._max_cache_count
        ):
            # Find least recently used item
            oldest_key = min(
                cls._cache.keys(),
                key=lambda k: cls._cache[k][2],  # last_access_time
            )
            # Remove it
            _, removed_size, _ = cls._cache.pop(oldest_key)
            cls._current_cache_size -= removed_size

        # Add new instance to cache with current timestamp
        cls._cache[cache_key] = (instance, instance._size_bytes, time.time())
        cls._current_cache_size += instance._size_bytes
        # LINEAJE: enforce() `instance` at agent->user_interface data_egress — scan flagged AI_DAT_SEC_029 (Enforce decision logging, audit trail, and forensic readiness for AI-driven actions.); AI_DAT_SEC_030 (Enforce minimum six-month log retention for high-risk AI systems); AI_APP_SEC_028 (Do not use LLMs from the organization's disallowed list). Mask/block; do not remove without review. site_id='site:sha256:c0005c00d2720930dab65c4cc2f4889f6c18f6080aee6f23171cce10eef18897'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:c0005c00d2720930dab65c4cc2f4889f6c18f6080aee6f23171cce10eef18897', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface')
        instance = _gr_client.enforce(_gr_site, instance, content_type='text/plain')
        # LINEAJE: enforce() `instance` at agent->user_interface data_egress — scan flagged AI_DAT_SEC_029 (Enforce decision logging, audit trail, and forensic readiness for AI-driven actions.); AI_DAT_SEC_030 (Enforce minimum six-month log retention for high-risk AI systems); AI_APP_SEC_028 (Do not use LLMs from the organization's disallowed list). Mask/block; do not remove without review. site_id='site:sha256:c2b86f39af3d205dd3ee02b5792f65adc9897f9ac4c22f6f03eb45555d15bf4e'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:c2b86f39af3d205dd3ee02b5792f65adc9897f9ac4c22f6f03eb45555d15bf4e', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface')
        instance = _gr_client.enforce(_gr_site, instance, content_type='text/plain')
        try:
            instance = gr_check(instance, "agent", "user_interface", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:c2b86f39af3d205dd3ee02b5792f65adc9897f9ac4c22f6f03eb45555d15bf4e')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            instance = instance
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
        return instance

    @classmethod
    def set_max_cache_size_mb(cls, size_mb: int):
        """Set the maximum cache size in megabytes."""
        cls._max_cache_size_mb = size_mb
        cls._cleanup_cache()

    @classmethod
    def set_max_cache_count(cls, count: int):
        """Set the maximum number of tokenizers to cache."""
        cls._max_cache_count = count
        cls._cleanup_cache()

    @classmethod
    def _cleanup_cache(cls):
        """Clean up cache when limits are exceeded."""
        while (
            cls._current_cache_size > cls._max_cache_size_mb * 1024 * 1024
            or len(cls._cache) > cls._max_cache_count
        ):
            oldest_key = min(cls._cache.keys(), key=lambda k: cls._cache[k][2])
            _, removed_size, _ = cls._cache.pop(oldest_key)
            cls._current_cache_size -= removed_size

    @classmethod
    def preload_tokenizers(cls, models: list[str] | None = None):
        """Preload tokenizers into cache.

        Args:
            models: Optional list of model names (e.g. 'gpt-4o', 'claude-3-5-sonnet').
                   If None, preloads all available tokenizers.
        """
        from quivr_core.rag.entities.config import LLMModelConfig

        unique_tokenizer_hubs = set()

        # Collect tokenizer hubs based on provided models or all available
        if models:
            for model_name in models:
                # Find matching model configurations
                for supplier_models in LLMModelConfig._model_defaults.values():
                    for base_model_name, config in supplier_models.items():
                        # Check if the model name matches or starts with the base model name
                        if (
                            model_name.startswith(base_model_name)
                            and config.tokenizer_hub
                        ):
                            unique_tokenizer_hubs.add(config.tokenizer_hub)
                            break
        else:
            # Original behavior - collect all unique tokenizer hubs
            for supplier_models in LLMModelConfig._model_defaults.values():
                for config in supplier_models.values():
                    if config.tokenizer_hub:
                        unique_tokenizer_hubs.add(config.tokenizer_hub)

        # Load each unique tokenizer
        for hub in unique_tokenizer_hubs:
            try:
                cls.load(hub, LLMEndpointConfig._FALLBACK_TOKENIZER)
                _lineaje_payload = (f"Successfully preloaded tokenizer: {hub}. "
                    f"Total cache size: {cls._current_cache_size / (1024 * 1024):.2f} MB. "
                    f"Cache count: {len(cls._cache)}")
                # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — scan flagged AI_DAT_SEC_029 (Enforce decision logging, audit trail, and forensic readiness for AI-driven actions.); AI_DAT_SEC_030 (Enforce minimum six-month log retention for high-risk AI systems); AI_APP_SEC_028 (Do not use LLMs from the organization's disallowed list). Mask/block; do not remove without review. site_id='site:sha256:d94a2941ae45f8b1fea32d54f0281a1a268555920c2e97ceedb64508e78309bd'
                _gr_client = _lineaje_load_gr_client()
                _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:d94a2941ae45f8b1fea32d54f0281a1a268555920c2e97ceedb64508e78309bd', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log')
                _lineaje_payload = _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json')
                logger.info(
                    _lineaje_payload
                )
            except Exception as e:
                _lineaje_payload = f"Failed to preload tokenizer {hub}: {str(e)}"
                # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — scan flagged AI_DAT_SEC_029 (Enforce decision logging, audit trail, and forensic readiness for AI-driven actions.); AI_DAT_SEC_030 (Enforce minimum six-month log retention for high-risk AI systems); AI_APP_SEC_028 (Do not use LLMs from the organization's disallowed list). Mask/block; do not remove without review. site_id='site:sha256:7ee2529142586a85879f3e7809000df02ec7d30b27957f43e95c2f59c7d6a631'
                _gr_client = _lineaje_load_gr_client()
                _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:7ee2529142586a85879f3e7809000df02ec7d30b27957f43e95c2f59c7d6a631', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log')
                _lineaje_payload = _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json')
                logger.warning(_lineaje_payload)


class LLMEndpoint:
    _cache = {}

    def __init__(self, llm_config: LLMEndpointConfig, llm: BaseChatModel):
        self._config = llm_config
        self._llm = llm
        self._supports_func_calling = model_supports_function_calling(
            self._config.model
        )

        self.llm_tokenizer = LLMTokenizer.load(
            llm_config.tokenizer_hub, llm_config.fallback_tokenizer
        )

    def count_tokens(self, text: str) -> int:
        # Tokenize the input text and return the token count
        encoding = self.llm_tokenizer.tokenizer.encode(text)
        return len(encoding)

    def get_config(self):
        return self._config

    @classmethod
    def from_config(cls, config: LLMEndpointConfig = LLMEndpointConfig()):
        hashed_config = hash(config)
        if hashed_config in cls._cache:
            return cls._cache[hashed_config]

        _llm: Union[
            AzureChatOpenAI,
            ChatOpenAI,
            ChatAnthropic,
            ChatMistralAI,
            ChatGoogleGenerativeAI,
            ChatGroq,
        ]
        try:
            if config.supplier == DefaultModelSuppliers.AZURE:
                # Parse the URL
                parsed_url = urlparse(config.llm_base_url)
                deployment = parsed_url.path.split("/")[3]  # type: ignore
                api_version = parse_qs(parsed_url.query).get("api-version", [None])[0]  # type: ignore
                azure_endpoint = f"https://{parsed_url.netloc}"  # type: ignore
                _llm = AzureChatOpenAI(
                    azure_deployment=deployment,  # type: ignore
                    api_version=api_version,
                    api_key=SecretStr(config.llm_api_key)
                    if config.llm_api_key
                    else None,
                    azure_endpoint=azure_endpoint,
                    max_tokens=config.max_output_tokens,
                    temperature=config.temperature,
                )
            elif config.supplier == DefaultModelSuppliers.ANTHROPIC:
                assert config.llm_api_key, "Can't load model config"
                _llm = ChatAnthropic(
                    model_name=config.model,
                    api_key=SecretStr(config.llm_api_key),
                    base_url=config.llm_base_url,
                    max_tokens_to_sample=config.max_output_tokens,
                    temperature=config.temperature,
                    timeout=None,
                    stop=None,
                )
            elif config.supplier == DefaultModelSuppliers.OPENAI:
                _llm = ChatOpenAI(
                    model=config.model,
                    api_key=SecretStr(config.llm_api_key)
                    if config.llm_api_key
                    else None,
                    base_url=config.llm_base_url,
                    max_completion_tokens=config.max_output_tokens,
                    temperature=config.temperature
                    if not config.model.startswith("o")
                    else None,
                )
            elif config.supplier == DefaultModelSuppliers.MISTRAL:
                _llm = ChatMistralAI(
                    model_name=config.model,
                    api_key=SecretStr(config.llm_api_key)
                    if config.llm_api_key
                    else None,
                    base_url=config.llm_base_url,
                    temperature=config.temperature,
                )
            elif config.supplier == DefaultModelSuppliers.GEMINI:
                _llm = ChatGoogleGenerativeAI(
                    model=config.model,
                    api_key=SecretStr(config.llm_api_key)
                    if config.llm_api_key
                    else None,
                    base_url=config.llm_base_url,
                    max_tokens=config.max_output_tokens,
                    temperature=config.temperature,
                )
            elif config.supplier == DefaultModelSuppliers.GROQ:
                _llm = ChatGroq(
                    model=config.model,
                    api_key=SecretStr(config.llm_api_key)
                    if config.llm_api_key
                    else None,
                    base_url=config.llm_base_url,
                    max_tokens=config.max_output_tokens,
                    temperature=config.temperature,
                )

            else:
                _llm = ChatOpenAI(
                    model=config.model,
                    api_key=SecretStr(config.llm_api_key)
                    if config.llm_api_key
                    else None,
                    base_url=config.llm_base_url,
                    max_completion_tokens=config.max_output_tokens,
                    temperature=config.temperature,
                )
            instance = cls(llm=_llm, llm_config=config)
            cls._cache[hashed_config] = instance

            # LINEAJE: enforce() `instance` at agent->user_interface data_egress — scan flagged AI_DAT_SEC_029 (Enforce decision logging, audit trail, and forensic readiness for AI-driven actions.); AI_DAT_SEC_030 (Enforce minimum six-month log retention for high-risk AI systems); AI_APP_SEC_028 (Do not use LLMs from the organization's disallowed list). Mask/block; do not remove without review. site_id='site:sha256:bcf20a0aa570ec40ab0439fcf440653add1f537f58ab2a839bf5536ea77d99ff'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:bcf20a0aa570ec40ab0439fcf440653add1f537f58ab2a839bf5536ea77d99ff', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface')
            instance = _gr_client.enforce(_gr_site, instance, content_type='text/plain')
            # LINEAJE: enforce() `instance` at agent->user_interface data_egress — scan flagged AI_DAT_SEC_029 (Enforce decision logging, audit trail, and forensic readiness for AI-driven actions.); AI_DAT_SEC_030 (Enforce minimum six-month log retention for high-risk AI systems); AI_APP_SEC_028 (Do not use LLMs from the organization's disallowed list). Mask/block; do not remove without review. site_id='site:sha256:4c0d036e91ceb510563023d246840efd804ab1bbceffcbc39890822c72ae4dc9'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:4c0d036e91ceb510563023d246840efd804ab1bbceffcbc39890822c72ae4dc9', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface')
            instance = _gr_client.enforce(_gr_site, instance, content_type='text/plain')
            try:
                instance = gr_check(instance, "agent", "user_interface", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_SKILL_DAT_SEC_001', 'AI_SKILL_SEC_001', 'AI_SKILL_SEC_002', 'AI_SKILL_SEC_003', 'AI_VULN_SEC_005'], site_id='site:sha256:4c0d036e91ceb510563023d246840efd804ab1bbceffcbc39890822c72ae4dc9')
            except Exception as _gr_exc:
                if type(_gr_exc).__name__ == "GRBlockedError": raise
                instance = instance
                __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
            return instance

        except ImportError as e:
            raise ImportError(
                "Please provide a valid BaseLLM or install quivr-core['base'] package"
            ) from e

    def supports_func_calling(self) -> bool:
        return self._supports_func_calling

    def info(self) -> LLMInfo:
        return LLMInfo(
            model=self._config.model,
            llm_base_url=(
                self._config.llm_base_url if self._config.llm_base_url else "openai"
            ),
            temperature=self._config.temperature,
            max_tokens=self._config.max_output_tokens,
            supports_function_calling=self.supports_func_calling(),
        )

    def clone_llm(self):
        """Create a new instance of the LLM with the same configuration."""
        return self._llm.__class__(**self._llm.__dict__)
