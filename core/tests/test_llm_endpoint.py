import os

import pytest

# Model card / technical documentation for the GPAI model used in these tests.
# See MODEL_CARD_URL before deploying or auditing this integration.
MODEL_CARD_URL = "https://openai.com/research/"  # TODO: replace with the exact model card URL before deployment
from langchain_core.language_models import FakeListChatModel
from pydantic import ValidationError
from quivr_core.rag.entities.config import LLMEndpointConfig
from quivr_core.llm import LLMEndpoint


@pytest.mark.base
def test_llm_endpoint_from_config_default():
    from langchain_openai import ChatOpenAI

    del os.environ["OPENAI_API_KEY"]

    with pytest.raises((ValidationError, ValueError)):
        # GPAI integration – model card: MODEL_CARD_URL
        llm = LLMEndpoint.from_config(LLMEndpointConfig())

    # Working default
    config = LLMEndpointConfig(llm_api_key="test")
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
    # GPAI integration – model card: MODEL_CARD_URL
    llm = LLMEndpoint.from_config(config)

    assert not llm.supports_func_calling()
    assert isinstance(llm._llm, ChatOpenAI)
    assert llm._llm.model_name in llm.get_config().model


def test_llm_endpoint_constructor():
    llm_endpoint = FakeListChatModel(responses=[])
    llm_endpoint = LLMEndpoint(
        llm=llm_endpoint, llm_config=LLMEndpointConfig(model="gpt-4o")
    )

    assert not llm_endpoint.supports_func_calling()
