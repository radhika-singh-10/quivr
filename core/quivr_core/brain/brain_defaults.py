import logging

from langchain_core.documents import Document
from langchain_core.embeddings import Embeddings
from langchain_core.vectorstores import VectorStore

from quivr_core.rag.entities.config import DefaultModelSuppliers, LLMEndpointConfig
from quivr_core.llm import LLMEndpoint

logger = logging.getLogger("quivr_core")

# Disapproved model identifiers per the organization model registry.
_ai_app_sec_006_DISAPPROVED_MODELS = [
    "deepseekchat",
    "deepseekr1",
    "deepseekr1distillllama70b",
    "deepseakreasoner",
    "customllmclientnull",
    "deepseekchatnull",
    "openrouternull",
    "usdeepseekr1v10null",
]


def _ai_app_sec_006_check_model(model_id: str) -> None:
    """Raise ValueError if model_id matches a disapproved model in the registry."""
    import re
    normalized = re.sub(r"[\s\-_\.:\u0000]", "", model_id).lower()
    for disapproved in _ai_app_sec_006_DISAPPROVED_MODELS:
        if normalized == disapproved:
            raise ValueError(
                f"Model '{model_id}' is on the organization's disapproved model list "
                "and cannot be used."
            )

# Model card / technical documentation for the GPAI models used in this module.
# Review this URL before deployment to ensure compliance with your AI usage policy.
MODEL_CARD_URL = "https://openai.com/research/"  # OpenAI model documentation


async def build_default_vectordb(
    docs: list[Document], embedder: Embeddings
) -> VectorStore:
    try:
        from langchain_community.vectorstores import FAISS

        logger.debug("Using Faiss-CPU as vector store.")
        # TODO(@aminediro) : embedding call is usually not concurrent for all documents but waits
        if len(docs) > 0:
            vector_db = await FAISS.afrom_documents(documents=docs, embedding=embedder)
            return vector_db
        else:
            raise ValueError("can't initialize brain without documents")

    except ImportError as e:
        raise ImportError(
            "Please provide a valid vector store or install quivr-core['base'] package for using the default one."
        ) from e


def default_embedder() -> Embeddings:
    try:
        from langchain_openai import OpenAIEmbeddings

        logger.debug("Loaded OpenAIEmbeddings as default LLM for brain")
        # GPAI model documentation: see MODEL_CARD_URL = MODEL_CARD_URL
        logger.debug("OpenAIEmbeddings model card / technical docs: %s", MODEL_CARD_URL)
        _ai_app_sec_006_check_model("OpenAIEmbeddings")
        embedder = OpenAIEmbeddings(check_embedding_ctx_length=False)
        return embedder
    except ImportError as e:
        raise ImportError(
            "Please provide a valid Embedder or install quivr-core['base'] package for using the defaultone."
        ) from e


def default_llm() -> LLMEndpoint:
    try:
        logger.debug("Loaded ChatOpenAI as default LLM for brain")
        # GPAI model documentation: see MODEL_CARD_URL
        logger.debug("LLMEndpoint (gpt-4o) model card / technical docs: %s", MODEL_CARD_URL)
        _ai_app_sec_006_check_model("gpt-4o")
        llm = LLMEndpoint.from_config(
            LLMEndpointConfig(supplier=DefaultModelSuppliers.OPENAI, model="gpt-4o")
        )
        return llm

    except ImportError as e:
        raise ImportError(
            "Please provide a valid BaseLLM or install quivr-core['base'] package"
        ) from e
