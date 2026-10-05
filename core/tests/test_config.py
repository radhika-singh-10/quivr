from quivr_core.rag.entities.config import LLMEndpointConfig, RetrievalConfig

# Model card / technical documentation for the GPAI model used below (gpt-4o).
# See: https://openai.com/research/ for OpenAI model cards and safety documentation.
MODEL_CARD_URL = "https://openai.com/research/"  # TODO: replace with the exact gpt-4o model card URL before deployment


def test_default_llm_config():
    # GPAI model card reference: MODEL_CARD_URL
    config = LLMEndpointConfig()

    assert (
        config.model_dump()
        == LLMEndpointConfig(
            model="claude-3-5-sonnet-20240620",
            llm_base_url=None,
            llm_api_key=None,
            max_context_tokens=2000,
            max_output_tokens=2000,
            temperature=0.7,
            streaming=True,
        ).model_dump()
    )


def test_default_retrievalconfig():
    config = RetrievalConfig()

    assert config.max_files == 20
    assert config.prompt is None
    print("\n\n", config.llm_config, "\n\n")
    print("\n\n", LLMEndpointConfig(), "\n\n")
    assert config.llm_config == LLMEndpointConfig()
