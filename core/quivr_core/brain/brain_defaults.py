import logging
import os

from langchain_core.documents import Document
from langchain_core.embeddings import Embeddings
from langchain_core.vectorstores import VectorStore

from quivr_core.rag.entities.config import DefaultModelSuppliers, LLMEndpointConfig
from quivr_core.llm import LLMEndpoint

logger = logging.getLogger("quivr_core")


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
    ollama_embed = os.getenv("OLLAMA_EMBED_MODEL")
    if ollama_embed:
        from langchain_community.embeddings import OllamaEmbeddings

        logger.debug("Loaded OllamaEmbeddings as default embedder for brain")
        return OllamaEmbeddings(
            model=ollama_embed,
            base_url=os.getenv("OLLAMA_HOST", "http://localhost:11434"),
        )
    try:
        from langchain_openai import OpenAIEmbeddings

        logger.debug("Loaded OpenAIEmbeddings as default LLM for brain")
        embedder = OpenAIEmbeddings(check_embedding_ctx_length=False)
        return embedder
    except ImportError as e:
        raise ImportError(
            "Please provide a valid Embedder or install quivr-core['base'] package for using the defaultone."
        ) from e


def default_llm() -> LLMEndpoint:
    ollama_model = os.getenv("OLLAMA_CHAT_MODEL")
    if ollama_model:
        # ChatOpenAI requires a key even when talking to Ollama's OpenAI-compatible API.
        os.environ.setdefault("OPENAI_API_KEY", "ollama")
        host = os.getenv("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
        logger.debug("Loaded Ollama ChatOpenAI as default LLM for brain")
        llm = LLMEndpoint.from_config(
            LLMEndpointConfig(
                model=ollama_model,
                llm_api_key="ollama",
                llm_base_url=f"{host}/v1",
                max_output_tokens=8192,
                temperature=0.7,
            )
        )
        llm._supports_func_calling = False
        return llm
    try:
        logger.debug("Loaded ChatOpenAI as default LLM for brain")
        llm = LLMEndpoint.from_config(
            LLMEndpointConfig(supplier=DefaultModelSuppliers.OPENAI, model="gpt-4o")
        )
        return llm

    except ImportError as e:
        raise ImportError(
            "Please provide a valid BaseLLM or install quivr-core['base'] package"
        ) from e
