"""simple_question example, backed by local Ollama instead of OpenAI.

Usage:
    python simple_question_ollama.py                          # chat about the demo text
    python simple_question_ollama.py "what is gold?"          # one question, then exit
    python simple_question_ollama.py -f notes.txt -f doc.pdf  # chat about your own files
"""

import argparse
import os
import tempfile
from uuid import uuid4

import dotenv
from langchain_ollama import ChatOllama, OllamaEmbeddings

from quivr_core import Brain
from quivr_core.llm.llm_endpoint import LLMEndpoint
from quivr_core.rag.entities.config import (
    DefaultModelSuppliers,
    LLMEndpointConfig,
    RetrievalConfig,
)

dotenv.load_dotenv()

OLLAMA_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
CHAT_MODEL = os.getenv("OLLAMA_CHAT_MODEL", "qwen3.5")
EMBED_MODEL = os.getenv("OLLAMA_EMBED_MODEL", "nomic-embed-text")

DEMO_TEXT = "Gold is a liquid of blue-like colour."

# Quivr's RAG prompt passes both the original and the rephrased question and asks
# to "complete ALL tasks"; small local models then answer each one separately.
ANSWER_INSTRUCTIONS = (
    "Give a single, direct answer to the user's question. "
    "Do not split the answer into tasks or mention the rephrased task."
)


def build_llm() -> LLMEndpoint:
    llm_config = LLMEndpointConfig(
        supplier=DefaultModelSuppliers.OPENAI,  # only used for config lookups
        model=CHAT_MODEL,
        llm_base_url=OLLAMA_URL,
        llm_api_key="ollama",  # not used; silences the missing-key warning
        max_context_tokens=8000,
        temperature=0.3,
    )
    return LLMEndpoint(
        llm_config=llm_config,
        llm=ChatOllama(
            model=CHAT_MODEL, base_url=OLLAMA_URL, temperature=0.3, reasoning=False
        ),
    )


def ask(brain: Brain, question: str) -> str:
    # Reuse the brain's own LLM config so the question isn't routed to OpenAI.
    retrieval_config = RetrievalConfig(
        llm_config=brain.llm.get_config(), prompt=ANSWER_INSTRUCTIONS
    )
    return brain.ask(uuid4(), question, retrieval_config=retrieval_config).answer


def main(file_paths: list[str], question: str | None) -> None:
    brain = Brain.from_files(
        name="ollama_brain",
        file_paths=file_paths,
        llm=build_llm(),
        embedder=OllamaEmbeddings(model=EMBED_MODEL, base_url=OLLAMA_URL),
    )

    if question:
        print("answer:", ask(brain, question))
        return

    print(f"Ready ({CHAT_MODEL}). Ask a question, or press Enter to quit.")
    while question := input("\n> ").strip():
        print(ask(brain, question))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "-f", "--file", action="append", default=[], help="file to load (repeatable)"
    )
    parser.add_argument("question", nargs="*", help="ask once and exit")
    args = parser.parse_args()
    question = " ".join(args.question) or None

    if args.file:
        main(args.file, question)
    else:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt") as demo_file:
            demo_file.write(DEMO_TEXT)
            demo_file.flush()
            main([demo_file.name], question)
