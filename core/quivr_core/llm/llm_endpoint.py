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

import uuid as _ai_app_sec_035_uuid


def _ai_app_sec_035_log_llm_interaction(
    operation: str,
    model: str,
    request_id: str,
    duration_s: float,
    input_len: int,
    output_len: int,
    status: str,
    prompt_tokens: int | None = None,
    completion_tokens: int | None = None,
    total_tokens: int | None = None,
) -> None:
    """Log LLM interaction metadata only — never log content."""
    logger.info(
        "llm_interaction",
        extra={
            "operation": operation,
            "model": model,
            "request_id": request_id,
            "duration_s": round(duration_s, 4),
            "input_len_chars": input_len,
            "output_len_chars": output_len,
            "status": status,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": total_tokens,
        },
    )


class _ai_app_sec_035_LoggingLLM:
    """Thin wrapper around a BaseChatModel that logs interaction metadata."""

    def __init__(self, llm: "BaseChatModel", model_name: str):
        self._llm = llm
        self._model_name = model_name

    # Proxy attribute access to the underlying LLM so duck-typing works.
    def __getattr__(self, name: str):
        return getattr(self._llm, name)

    def invoke(self, input, config=None, **kwargs):
        request_id = str(_ai_app_sec_035_uuid.uuid4())
        input_str = str(input)
        t0 = time.time()
        try:
            result = self._llm.invoke(input, config=config, **kwargs) if config is not None else self._llm.invoke(input, **kwargs)
            duration = time.time() - t0
            output_str = str(result.content) if hasattr(result, "content") else str(result)
            usage = getattr(result, "usage_metadata", None) or getattr(result, "response_metadata", {}).get("usage", None)
            prompt_tokens = completion_tokens = total_tokens = None
            if usage:
                prompt_tokens = getattr(usage, "input_tokens", None) or (usage.get("prompt_tokens") if isinstance(usage, dict) else None)
                completion_tokens = getattr(usage, "output_tokens", None) or (usage.get("completion_tokens") if isinstance(usage, dict) else None)
                total_tokens = getattr(usage, "total_tokens", None) or (usage.get("total_tokens") if isinstance(usage, dict) else None)
            _ai_app_sec_035_log_llm_interaction(
                operation="invoke",
                model=self._model_name,
                request_id=request_id,
                duration_s=duration,
                input_len=len(input_str),
                output_len=len(output_str),
                status="success",
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=total_tokens,
            )
            return result
        except Exception as exc:
            duration = time.time() - t0
            _ai_app_sec_035_log_llm_interaction(
                operation="invoke",
                model=self._model_name,
                request_id=request_id,
                duration_s=duration,
                input_len=len(input_str),
                output_len=0,
                status=f"error:{type(exc).__name__}",
            )
            raise

    def stream(self, input, config=None, **kwargs):
        request_id = str(_ai_app_sec_035_uuid.uuid4())
        input_str = str(input)
        t0 = time.time()
        chunks = []
        try:
            gen = self._llm.stream(input, config=config, **kwargs) if config is not None else self._llm.stream(input, **kwargs)
            for chunk in gen:
                chunks.append(chunk)
                yield chunk
            duration = time.time() - t0
            output_str = "".join(
                str(c.content) if hasattr(c, "content") else str(c) for c in chunks
            )
            _ai_app_sec_035_log_llm_interaction(
                operation="stream",
                model=self._model_name,
                request_id=request_id,
                duration_s=duration,
                input_len=len(input_str),
                output_len=len(output_str),
                status="success",
            )
        except Exception as exc:
            duration = time.time() - t0
            _ai_app_sec_035_log_llm_interaction(
                operation="stream",
                model=self._model_name,
                request_id=request_id,
                duration_s=duration,
                input_len=len(input_str),
                output_len=sum(len(str(c.content) if hasattr(c, "content") else str(c)) for c in chunks),
                status=f"error:{type(exc).__name__}",
            )
            raise

# Model card / technical documentation references for each GPAI provider.
# TODO: Replace any placeholder URLs with the exact model card URL before deployment.
MODEL_CARD_URL_OPENAI = "https://openai.com/research/"  # OpenAI model cards and research
MODEL_CARD_URL_AZURE_OPENAI = "https://openai.com/research/"  # Azure-hosted OpenAI models
MODEL_CARD_URL_ANTHROPIC = "https://www.anthropic.com/research"  # Anthropic model cards
MODEL_CARD_URL_GEMINI = "https://ai.google.dev/gemini-api/docs"  # Google Gemini technical docs
MODEL_CARD_URL_MISTRAL = "https://docs.mistral.ai/"  # Mistral AI technical documentation

import re as _re

# Organisation disapproved model registry (authoritative data service).
# Models whose normalised identifiers match an entry here are blocked.
_ai_app_sec_006_DISAPPROVED_MODELS: frozenset[str] = frozenset({
    # DeepSeek variants
    "deepseekchat",
    "deepseekr1",
    "deepseekr1distillllama70b",
    "deepseekreasoner",
    "customllmclientnull",
    "usdeepseekr1v10null",
    "openrouternull",
})


def _ai_app_sec_006_normalize(model: str) -> str:
    """Normalise a model identifier for registry comparison.

    Strips case and removes spaces, hyphens, underscores, dots and colons so
    that e.g. "us.deepseek.r1-v1:0" matches "usdeepseekr1v10".
    """
    return _re.sub(r"[\s\-_\.:\u0000]+", "", model).lower()


def _assert_model_approved(model: str) -> None:
    """Raise ValueError if *model* is in the organisation's disapproved registry."""
    normalised = _ai_app_sec_006_normalize(model)
    if any(
        normalised == blocked or normalised.startswith(blocked)
        for blocked in _ai_app_sec_006_DISAPPROVED_MODELS
    ):
        raise ValueError(
            f"Model '{model}' is in the organisation's disapproved model registry "
            "and may not be instantiated."
        )


def _ai_app_sec_006_check_and_build_llm(factory, model: str, **kwargs):
    """Assert model is not disapproved, then construct and return the LLM."""
    _assert_model_approved(model)
    return factory(model=model, **kwargs)


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
                logger.warning(
                    f"Cannot acces the configured tokenizer from {self.tokenizer_hub}, using the default tokenizer {self.fallback_tokenizer}"
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
                    logger.debug(f"Could not access tokenizer file: {file_path}")

        return total_size if total_size > 0 else self._default_size

    @classmethod
    def load(cls, tokenizer_hub: str, fallback_tokenizer: str):
        cache_key = hash(str(tokenizer_hub))

        # If in cache, update last access time and return
        if cache_key in cls._cache:
            tokenizer, size, _ = cls._cache[cache_key]
            cls._cache[cache_key] = (tokenizer, size, time.time())
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
                logger.info(
                    f"Successfully preloaded tokenizer: {hub}. "
                    f"Total cache size: {cls._current_cache_size / (1024 * 1024):.2f} MB. "
                    f"Cache count: {len(cls._cache)}"
                )
            except Exception as e:
                logger.warning(f"Failed to preload tokenizer {hub}: {str(e)}")


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
            _assert_model_approved(config.model)

            if config.supplier == DefaultModelSuppliers.AZURE:
                # Model card / technical docs: MODEL_CARD_URL_AZURE_OPENAI
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
                # Model card / technical docs: MODEL_CARD_URL_ANTHROPIC
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
                # Model card / technical docs: MODEL_CARD_URL_OPENAI
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
                # Model card / technical docs: MODEL_CARD_URL_MISTRAL
                _llm = ChatMistralAI(
                    model_name=config.model,
                    api_key=SecretStr(config.llm_api_key)
                    if config.llm_api_key
                    else None,
                    base_url=config.llm_base_url,
                    temperature=config.temperature,
                )
            elif config.supplier == DefaultModelSuppliers.GEMINI:
                # Model card / technical docs: MODEL_CARD_URL_GEMINI
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
                # Fallback to OpenAI-compatible endpoint.
                # Model card / technical docs: MODEL_CARD_URL_OPENAI
                _llm = ChatOpenAI(
                    model=config.model,
                    api_key=SecretStr(config.llm_api_key)
                    if config.llm_api_key
                    else None,
                    base_url=config.llm_base_url,
                    max_completion_tokens=config.max_output_tokens,
                    temperature=config.temperature,
                )
            _logging_llm = _ai_app_sec_035_LoggingLLM(_llm, config.model)
            instance = cls(llm=_logging_llm, llm_config=config)
            cls._cache[hashed_config] = instance

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
