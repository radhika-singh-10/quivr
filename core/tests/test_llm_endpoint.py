import os

import pytest

# Model card / technical documentation for the GPAI model used in these tests.
# See MODEL_CARD_URL before deploying or auditing this integration.
MODEL_CARD_URL = "https://openai.com/research/"  # TODO: replace with the exact model card URL before deployment
from langchain_core.language_models import FakeListChatModel
from pydantic import ValidationError
from quivr_core.rag.entities.config import LLMEndpointConfig
from quivr_core.llm import LLMEndpoint
import re as _re

_AI_APP_SEC_006_DISAPPROVED_PATTERNS = [
    r"deepseek",
    r"custom.?llm.?client",
    r"openrouter",
]

def _ai_app_sec_006_check_model(model: str) -> None:
    """Raise ValueError if model matches a disapproved model in the registry."""
    normalized = _re.sub(r"[\s\-_\.:\u200b]", "", model).lower()
    for pattern in _AI_APP_SEC_006_DISAPPROVED_PATTERNS:
        if _re.search(pattern, normalized):
            raise ValueError(
                f"Model '{model}' is disapproved by the organization model registry."
            )


@pytest.mark.base
def test_llm_endpoint_from_config_default():
    from langchain_openai import ChatOpenAI

    del os.environ["OPENAI_API_KEY"]

    with pytest.raises((ValidationError, ValueError)):
        # GPAI integration – model card: MODEL_CARD_URL
        _default_cfg = LLMEndpointConfig()
        _ai_app_sec_006_check_model(_default_cfg.model)
        llm = LLMEndpoint.from_config(_default_cfg)

    # Working default
    config = LLMEndpointConfig(llm_api_key="test")
    _ai_app_sec_006_check_model(config.model)
    # GPAI integration – model card: MODEL_CARD_URL
    llm = LLMEndpoint.from_config(config=config)

    assert llm.supports_func_calling()
    assert isinstance(llm._llm, ChatOpenAI)
    assert llm._llm.model_name in llm.get_config().model


@pytest.mark.base
def test_llm_endpoint_from_config():
    from langchain_openai import ChatOpenAI

    config = LLMEndpointConfig(
        model="gpt-4o", llm_api_key="test", llm_base_url="http://localhost:8441"
    )
    _ai_app_sec_006_check_model(config.model)
    # GPAI integration – model card: MODEL_CARD_URL
    llm = LLMEndpoint.from_config(config)

    assert not llm.supports_func_calling()
    assert isinstance(llm._llm, ChatOpenAI)
    assert llm._llm.model_name in llm.get_config().model


def test_llm_endpoint_constructor():
    llm_endpoint = FakeListChatModel(responses=[])
    _ai_app_sec_006_check_model("gpt-4o")
    llm_endpoint = LLMEndpoint(
        llm=llm_endpoint, llm_config=LLMEndpointConfig(model="gpt-4o")
    )

    assert not llm_endpoint.supports_func_calling()
