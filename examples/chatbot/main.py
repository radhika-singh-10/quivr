import os
import shutil
import tempfile
from pathlib import Path
from uuid import uuid4

import chainlit as cl
from langchain_ollama import ChatOllama, OllamaEmbeddings
from quivr_core import Brain, register_processor
from quivr_core.files.file import FileExtension
from quivr_core.llm import LLMEndpoint
from quivr_core.processor.implementations.simple_txt_processor import SimpleTxtProcessor
from quivr_core.rag.entities.config import LLMEndpointConfig, RetrievalConfig

# Parse .txt locally. Megaparse is the default and tries Quivr's hosted NATS,
# which fails with "nodename nor servname provided" when that host is down.
register_processor(FileExtension.txt, SimpleTxtProcessor, override=True)

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
# Llama models refuse any question once the retrieved context contains PII
# (SSNs, card numbers), even when the question is about something else.
OLLAMA_CHAT_MODEL = os.getenv("OLLAMA_CHAT_MODEL", "qwen3.5")
OLLAMA_EMBED_MODEL = os.getenv("OLLAMA_EMBED_MODEL", "nomic-embed-text")

# Quivr's RAG prompt passes both the original and the rephrased question and asks
# to "complete ALL tasks"; local models then answer each one separately.
ANSWER_INSTRUCTIONS = (
    "Give a single, direct answer to the user's question. "
    "Do not split the answer into tasks or mention the rephrased task."
)


def ollama_llm() -> LLMEndpoint:
    llm = LLMEndpoint(
        llm_config=LLMEndpointConfig(
            model=OLLAMA_CHAT_MODEL,
            llm_api_key="ollama",  # not used; silences the missing-key warning
            llm_base_url=OLLAMA_HOST,
            max_context_tokens=16000,
            max_output_tokens=8192,
            temperature=0.7,
        ),
        # reasoning=False keeps thinking models (qwen3.5) from streaming their
        # chain of thought into the answer.
        llm=ChatOllama(
            model=OLLAMA_CHAT_MODEL,
            base_url=OLLAMA_HOST,
            temperature=0.7,
            reasoning=False,
        ),
    )
    # Local models usually cannot satisfy cited_answer tool calls.
    llm._supports_func_calling = False
    return llm


def ollama_embedder() -> OllamaEmbeddings:
    return OllamaEmbeddings(model=OLLAMA_EMBED_MODEL, base_url=OLLAMA_HOST)


async def load_brain(files) -> None:
    """Replace the session's brain with one built from `files` only."""
    txt_files = [f for f in files if f.name.lower().endswith(".txt")]
    skipped = [f.name for f in files if f not in txt_files]
    if skipped:
        await cl.Message(
            content=f"Skipping {', '.join(skipped)}: only .txt files are supported."
        ).send()
    if not txt_files:
        return

    names = ", ".join(f"`{f.name}`" for f in txt_files)
    msg = cl.Message(content=f"Processing {names}...")
    await msg.send()

    # Copy under the original names so sources show "report.txt", not "tmpab12report.txt".
    upload_dir = Path(tempfile.mkdtemp(prefix="quivr_upload_"))
    file_paths = []
    for f in txt_files:
        path = upload_dir / Path(f.name).name
        shutil.copy(f.path, path)
        file_paths.append(str(path))

    brain = await Brain.afrom_files(
        name="user_brain",
        file_paths=file_paths,
        llm=ollama_llm(),
        embedder=ollama_embedder(),
    )

    previous_dir = cl.user_session.get("upload_dir")
    if previous_dir:
        shutil.rmtree(previous_dir, ignore_errors=True)
    cl.user_session.set("upload_dir", str(upload_dir))
    cl.user_session.set("brain", brain)

    msg.content = (
        f"Processing {names} done ({OLLAMA_CHAT_MODEL}). You can now ask questions!\n"
        "Attach new files to any message to replace these documents."
    )
    await msg.update()


@cl.on_chat_start
async def on_chat_start():
    files = None

    # Wait for the user to upload a file
    while files is None:
        files = await cl.AskFileMessage(
            content="Please upload one or more .txt files to begin!",
            accept=["text/plain"],
            max_size_mb=20,
            max_files=10,
            timeout=180,
        ).send()

    await load_brain(files)


@cl.on_chat_end
async def on_chat_end():
    upload_dir = cl.user_session.get("upload_dir")
    if upload_dir:
        shutil.rmtree(upload_dir, ignore_errors=True)


@cl.on_message
async def main(message: cl.Message):
    # Files attached to a message replace the documents the brain answers from.
    attached = [el for el in message.elements if getattr(el, "path", None)]
    if attached:
        await load_brain(attached)
        if not message.content.strip():
            return

    brain = cl.user_session.get("brain")  # type: Brain
    if brain is None:
        await cl.Message(content="Please upload a file first.").send()
        return

    path_config = "basic_rag_workflow.yaml"
    retrieval_config = RetrievalConfig.from_yaml(path_config)
    # Keep the YAML workflow, but do not let it fall back to OpenAI.
    retrieval_config.llm_config = brain.llm.get_config()
    retrieval_config.prompt = ANSWER_INSTRUCTIONS

    # Prepare the message for streaming
    msg = cl.Message(content="", elements=[])
    await msg.send()

    saved_sources = set()
    saved_sources_complete = []
    elements = []

    # Use the ask_stream method for streaming responses
    async for chunk in brain.ask_streaming(
        message.content,
        run_id=uuid4(),
        retrieval_config=retrieval_config,
    ):
        await msg.stream_token(chunk.answer)
        for source in chunk.metadata.sources:
            if source.page_content not in saved_sources:
                saved_sources.add(source.page_content)
                saved_sources_complete.append(source)

    # Chainlit merges elements that share a name into one side panel, so give
    # each chunk its own name.
    sources = ""
    for i, source in enumerate(saved_sources_complete, start=1):
        name = f"{source.metadata['original_file_name']} #{i}"
        elements.append(cl.Text(name=name, content=source.page_content, display="side"))
        sources += f"- {name}\n"
    msg.elements = elements
    msg.content = msg.content + f"\n\nSources:\n{sources}"
    await msg.update()
