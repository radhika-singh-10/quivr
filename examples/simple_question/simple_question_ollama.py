"""simple_question example, backed by local Ollama instead of OpenAI."""

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
        print("answer QuivrQARAGLangGraph :", answer.answer)
