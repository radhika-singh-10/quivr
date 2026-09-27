import asyncio
import base64
import logging
import os
import re
from pathlib import Path
from pprint import PrettyPrinter
from typing import Any, AsyncGenerator, Callable, Dict, Self, Type, Union
from uuid import UUID, uuid4

from langchain_core.documents import Document
from langchain_core.embeddings import Embeddings
from langchain_core.messages import AIMessage, HumanMessage
from langchain_core.vectorstores import VectorStore
from langchain_community.embeddings import HuggingFaceEmbeddings
from rich.console import Console
from rich.panel import Panel

from quivr_core.brain.info import BrainInfo, ChatHistoryInfo
from quivr_core.brain.serialization import (
    BrainSerialized,
    EmbedderConfig,
    FAISSConfig,
    LocalStorageConfig,
    TransparentStorageConfig,
)
from quivr_core.files.file import load_qfile
from quivr_core.llm import LLMEndpoint
from quivr_core.processor.registry import get_processor_class
from quivr_core.rag.entities.chat import ChatHistory
from quivr_core.rag.entities.config import RetrievalConfig
from quivr_core.rag.entities.models import (
    LangchainMetadata,
    ParsedRAGChunkResponse,
    ParsedRAGResponse,
    QuivrKnowledge,
    SearchResult,
)
from quivr_core.rag.quivr_rag import QuivrQARAG
from quivr_core.rag.quivr_rag_langgraph import QuivrQARAGLangGraph
from quivr_core.storage.local_storage import LocalStorage, TransparentStorage
from quivr_core.storage.storage_base import StorageBase

from .brain_defaults import build_default_vectordb

import re

import re

logger = logging.getLogger("quivr_core")

# Known prompt injection / role-override patterns
_INJECTION_PATTERNS = re.compile(
    r"(ignore (previous|all|above|prior)|disregard|forget (previous|all|above|prior)"
    r"|you are now|act as|pretend (you are|to be)|system:|<system>|\[system\]"
    r"|###\s*(system|instruction|prompt)|<\|im_start\||<\|im_end\|>"
    r"|\bDAN\b|jailbreak|override (instructions?|prompt|system)"
    r"|new instructions?:|\[INST\]|\[/INST\])",
    re.IGNORECASE,
)


def _sanitize_input(value: str, field_name: str = "input") -> str:
    """Sanitize user-supplied input before it reaches the LLM.

    Raises ValueError and logs a warning if injection patterns are detected.
    Returns the original value (stripped) if it is clean.
    """
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string")
    stripped = value.strip()
    if _INJECTION_PATTERNS.search(stripped):
        logger.warning(
            "Potential prompt injection detected in %s: %r — request blocked.",
            field_name,
            stripped[:200],
        )
        raise ValueError(
            f"Input rejected: {field_name} contains disallowed instruction-like patterns."
        )
    return stripped


def _wrap_user_question(question: str) -> str:
    """Wrap the sanitized user question in structural delimiters so the model
    can clearly distinguish the fixed instruction context from user-provided data."""
    return f"<user_question>\n{question}\n</user_question>"

import re


def sanitize_leetspeak(text: str) -> str:
    """
    Detect and replace leetspeak-obfuscated prompts, system commands, or
    executables with a safe placeholder.
    Leetspeak maps digits/symbols to letters, e.g. 4->a, 3->e, 1->i/l,
    0->o, 5->s, 7->t, etc.
    """
    # Normalise common leet substitutions to plain ASCII for detection
    leet_map = str.maketrans("4831057@$", "aebiotsas")

    def _normalise(s: str) -> str:
        return s.lower().translate(leet_map)

    # Patterns that indicate prompt-injection or command execution intent
    _INJECTION_PATTERNS = [
        # Instruction-style directives
        r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|commands?)",
        r"(system|assistant|user)\s*:\s*",
        r"you\s+are\s+(now\s+)?(a|an)\s+",
        r"act\s+as\s+(a|an)\s+",
        r"disregard\s+(all\s+)?(previous|prior|above)",
        r"do\s+not\s+follow",
        r"override\s+(the\s+)?(system|instructions?|prompt)",
        r"new\s+instructions?",
        r"forget\s+(all\s+)?(previous|prior|above)",
        # Shell / executable patterns
        r"(exec|eval|system|popen|subprocess|shell_exec|passthru|cmd|powershell|bash|sh)\s*[\(\[]",
        r"(rm|del|format|mkfs|dd|wget|curl|chmod|chown|sudo|su)\s+",
        r"<\s*script[^>]*>",
        r"javascript\s*:",
    ]

    # Tokenise into whitespace-separated words; check each word after
    # leet-normalisation, then check the full normalised text for multi-word
    # patterns.
    normalised = _normalise(text)

    for pattern in _INJECTION_PATTERNS:
        if re.search(pattern, normalised, re.IGNORECASE):
            return "<leetspeak_prompts_removed>"

    return text


# Patterns for dynamic code execution primitives that must be removed from LLM output
_DANGEROUS_PATTERNS = re.compile(
    r"(?m)^.*"
    r"(?:"
    r"\beval\s*\("
    r"|\bexec\s*\("
    r"|\bexecfile\s*\("
    r"|\bcompile\s*\("
    r"|\b__import__\s*\("
    r"|subprocess\.(?:call|run|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True"
    r"|os\.system\s*\("
    r"|os\.popen\s*\("
    r"|commands\.getoutput\s*\("
    r"|\beval\b"
    r"|\bFunction\s*\("
    r"|setTimeout\s*\("
    r"|setInterval\s*\("
    r"|new\s+Function\s*\("
    r"|bash\s+-c"
    r"|\$\(.*\)"
    r").*$"
)


def sanitize_llm_output(text: str) -> str:
    """
    Sanitize LLM output by removing lines that contain dynamic code execution
    primitives such as eval, exec, subprocess(shell=True), JS eval, bash eval, etc.
    Args:
        text (str): The raw LLM output text.
    Returns:
        str: The sanitized text with dangerous lines removed.
    """
    lines = text.splitlines(keepends=True)
    sanitized_lines = []
    for line in lines:
        if _DANGEROUS_PATTERNS.search(line):
            logger.warning(
                "Removed potentially dangerous line from LLM output: %s",
                line.rstrip(),
            )
        else:
            sanitized_lines.append(line)
    return "".join(sanitized_lines)


# ---------------------------------------------------------------------------
# Prompt-injection sanitisation helpers
# ---------------------------------------------------------------------------

# Invisible / zero-width Unicode characters used to hide text
_INVISIBLE_CHARS_RE = re.compile(
    r"[\u00ad\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff\u2028\u2029]"
)

# Common direct prompt-injection phrases (case-insensitive)
_INJECTION_PHRASES_RE = re.compile(
    r"(ignore (all |previous |prior |above |the above |your )?(instructions?|prompts?|context|rules?|system|constraints?)"
    r"|disregard (all |previous |prior |above |the above |your )?(instructions?|prompts?|context|rules?|system|constraints?)"
    r"|forget (all |previous |prior |above |the above |your )?(instructions?|prompts?|context|rules?|system|constraints?)"
    r"|you are now|act as (a |an )?|new (role|persona|identity|instructions?)"
    r"|system prompt|<\|im_start\||<\|im_end\||\[INST\]|\[/INST\]"
    r"|###\s*(instruction|system|human|assistant))",
    re.IGNORECASE,
)

# Shell / OS command patterns
_SHELL_CMD_RE = re.compile(
    r"(\$\(|`[^`]+`|\beval\b|\bexec\b|\bos\.system\b|\bsubprocess\b"
    r"|\brm\s+-rf\b|\bcurl\b.*\bhttp|\bwget\b.*\bhttp"
    r"|\bpowershell\b|\bcmd\.exe\b|\b/bin/(sh|bash|zsh)\b)",
    re.IGNORECASE,
)

# Leetspeak substitution table (reverse: leet → normal)
_LEET_TABLE = str.maketrans("013456789@$", "oieashgtbas")


def _decode_leet(text: str) -> str:
    """Return a rough plain-text version of a leetspeak string."""
    return text.translate(_LEET_TABLE)


def _extract_base64_strings(text: str) -> list[str]:
    """Return decoded text for every plausible base64 blob found in *text*."""
    decoded: list[str] = []
    # Base64 tokens that are at least 20 chars long
    for token in re.findall(r"[A-Za-z0-9+/]{20,}={0,2}", text):
        try:
            candidate = base64.b64decode(token + "==").decode("utf-8", errors="ignore")
            if candidate.isprintable() or len(candidate) > 10:
                decoded.append(candidate)
        except Exception:
            pass
    return decoded


def _is_malicious_chunk(text: str) -> bool:
    """
    Return True when *text* appears to contain a prompt-injection attempt.
    Checks performed:
      1. Invisible / zero-width characters
      2. Direct injection phrases
      3. Shell / OS commands
      4. Base64-encoded injection phrases or shell commands
      5. Leetspeak-obfuscated injection phrases
    """
    # 1. Invisible characters
    if _INVISIBLE_CHARS_RE.search(text):
        logger.warning("Prompt-injection guard: invisible characters detected in chunk.")
        return True

    # 2. Direct injection phrases
    if _INJECTION_PHRASES_RE.search(text):
        logger.warning("Prompt-injection guard: injection phrase detected in chunk.")
        return True

    # 3. Shell commands
    if _SHELL_CMD_RE.search(text):
        logger.warning("Prompt-injection guard: shell command pattern detected in chunk.")
        return True

    # 4. Base64-encoded payloads
    for decoded in _extract_base64_strings(text):
        if _INJECTION_PHRASES_RE.search(decoded) or _SHELL_CMD_RE.search(decoded):
            logger.warning(
                "Prompt-injection guard: base64-encoded malicious content detected in chunk."
            )
            return True

    # 5. Leetspeak obfuscation
    leet_decoded = _decode_leet(text)
    if _INJECTION_PHRASES_RE.search(leet_decoded):
        logger.warning("Prompt-injection guard: leetspeak-obfuscated injection detected in chunk.")
        return True

    return False


def _sanitize_chunk(doc: Document) -> Document | None:
    """
    Return *None* if the document chunk is considered malicious,
    otherwise return the chunk with invisible characters stripped.
    """
    text = doc.page_content
    if _is_malicious_chunk(text):
        return None
    # Strip invisible characters even from benign chunks
    clean_text = _INVISIBLE_CHARS_RE.sub("", text)
    if clean_text != text:
        doc = Document(page_content=clean_text, metadata=doc.metadata)
    return doc


# ---------------------------------------------------------------------------

async def process_files(
    storage: StorageBase, skip_file_error: bool, **processor_kwargs: dict[str, Any]
) -> list[Document]:
    """
    Process files in storage.
    This function takes a StorageBase and return a list of langchain documents.
    Args:
        storage (StorageBase): The storage containing the files to process.
        skip_file_error (bool): Whether to skip files that cannot be processed.
        processor_kwargs (dict[str, Any]): Additional arguments for the processor.
    Returns:
        list[Document]: List of processed documents in the Langchain Document format.
    Raises:
        ValueError: If a file cannot be processed and skip_file_error is False.
        Exception: If no processor is found for a file of a specific type and skip_file_error is False.
    """

    knowledge = []
    for file in await storage.get_files():
        try:
            if file.file_extension:
                processor_cls = get_processor_class(file.file_extension)
                logger.debug(f"processing {file} using class {processor_cls.__name__}")
                processor = processor_cls(**processor_kwargs)
                docs = await processor.process_file(file)
                sanitized_chunks = []
                for chunk in docs.chunks:
                    clean_content = sanitize_leetspeak(chunk.page_content)
                    if clean_content != chunk.page_content:
                        logger.warning(
                            "Leetspeak-obfuscated prompt detected and removed "
                            "in chunk from file %s",
                            file,
                        )
                        chunk = Document(
                            page_content=clean_content,
                            metadata=chunk.metadata,
                        )
                    sanitized_chunks.append(chunk)
                knowledge.extend(sanitized_chunks)
            else:
                logger.error(f"can't find processor for {file}")
                if skip_file_error:
                    continue
                else:
                    raise ValueError(f"can't parse {file}. can't find file extension")
        except KeyError as e:
            if skip_file_error:
                continue
            else:
                raise Exception(f"Can't parse {file}. No available processor") from e

    return knowledge


class Brain:
    """
    A class representing a Brain.
    This class allows for the creation of a Brain, which is a collection of knowledge one wants to retrieve information from.
    A Brain is set to:
    * Store files in the storage of your choice (local, S3, etc.)
    * Process the files in the storage to extract text and metadata in a wide range of format.
    * Store the processed files in the vector store of your choice (FAISS, PGVector, etc.) - default to FAISS.
    * Create an index of the processed files.
    * Use the *Quivr* workflow for the retrieval augmented generation.
    A Brain is able to:
    * Search for information in the vector store.
    * Answer questions about the knowledges in the Brain.
    * Stream the answer to the question.
    Attributes:
        name (str): The name of the brain.
        id (UUID): The unique identifier of the brain.
        storage (StorageBase): The storage used to store the files.
        llm (LLMEndpoint): The language model used to generate the answer.
        vector_db (VectorStore): The vector store used to store the processed files.
        embedder (Embeddings): The embeddings used to create the index of the processed files.
    """

    def __init__(
        self,
        *,
        name: str,
        llm: LLMEndpoint,
        id: UUID | None = None,
        vector_db: VectorStore | None = None,
        embedder: Embeddings | None = None,
        storage: StorageBase | None = None,
        workspace_id: UUID | None = None,
        chat_id: UUID | None = None,
    ):
        self.id = id
        self.name = name
        self.storage = storage
        self.workspace_id = workspace_id
        self.chat_id = chat_id
        # Chat history
        self._chats = self._init_chats()
        self.default_chat = list(self._chats.values())[0]

        # RAG dependencies:
        self.llm = llm
        self.vector_db = vector_db
        self.embedder = embedder

    def __repr__(self) -> str:
        pp = PrettyPrinter(width=80, depth=None, compact=False, sort_dicts=False)
        return pp.pformat(self.info())

    def print_info(self):
        console = Console()
        tree = self.info().to_tree()
        panel = Panel(tree, title="Brain Info", expand=False, border_style="bold")
        console.print(panel)

    @classmethod
    def load(cls, folder_path: str | Path) -> Self:
        """
        Load a brain from a folder path.
        Args:
            folder_path (str | Path): The path to the folder containing the brain.
        Returns:
            Brain: The brain loaded from the folder path.
        Example:
        ```python
        brain_loaded = Brain.load("path/to/brain")
        brain_loaded.print_info()
        ```
        """
        if isinstance(folder_path, str):
            folder_path = Path(folder_path)
        if not folder_path.exists():
            raise ValueError(f"path {folder_path} doesn't exist")

        # Load brainserialized
        with open(os.path.join(folder_path, "config.json"), "r") as f:
            bserialized = BrainSerialized.model_validate_json(f.read())

        storage: StorageBase | None = None
        # Loading storage
        if bserialized.storage_config.storage_type == "transparent_storage":
            storage = TransparentStorage.load(bserialized.storage_config)
        elif bserialized.storage_config.storage_type == "local_storage":
            storage = LocalStorage.load(bserialized.storage_config)
        else:
            raise ValueError("unknown storage")

        # Load Embedder
        if bserialized.embedding_config.embedder_type == "openai_embedding":
            from langchain_openai import OpenAIEmbeddings  # GPAI integration; see MODEL_CARD_URL

            embedder = OpenAIEmbeddings(**bserialized.embedding_config.config)  # model card: MODEL_CARD_URL
        else:
            raise ValueError("unknown embedder")

        # Load vector db
        if bserialized.vectordb_config.vectordb_type == "faiss":
            from langchain_community.vectorstores import FAISS

            vector_db = FAISS.load_local(
                folder_path=bserialized.vectordb_config.vectordb_folder_path,
                embeddings=embedder,
                allow_dangerous_deserialization=True,
            )
        else:
            raise ValueError("Unsupported vectordb")

        return cls(
            id=bserialized.id,
            name=bserialized.name,
            embedder=embedder,
            llm=LLMEndpoint.from_config(bserialized.llm_config),
            storage=storage,
            vector_db=vector_db,
        )

    async def save(self, folder_path: str | Path):
        """
        Save the brain to a folder path.
        Args:
            folder_path (str | Path): The path to the folder where the brain will be saved.
        Returns:
            str: The path to the folder where the brain was saved.
        Example:
        ```python
        await brain.save("path/to/brain")
        ```
        """
        if isinstance(folder_path, str):
            folder_path = Path(folder_path)

        brain_path = os.path.join(folder_path, f"brain_{self.id}")
        os.makedirs(brain_path, exist_ok=True)

        from langchain_community.vectorstores import FAISS

        if isinstance(self.vector_db, FAISS):
            vectordb_path = os.path.join(brain_path, "vector_store")
            os.makedirs(vectordb_path, exist_ok=True)
            self.vector_db.save_local(folder_path=vectordb_path)
            vector_store = FAISSConfig(vectordb_folder_path=vectordb_path)
        else:
            raise Exception("can't serialize other vector stores for now")

        if isinstance(self.embedder, OpenAIEmbeddings):
            embedder_config = EmbedderConfig(
                config=self.embedder.dict(exclude={"openai_api_key"})
            )
        else:
            raise Exception("can't serialize embedder other than openai for now")

        storage_config: Union[LocalStorageConfig, TransparentStorageConfig]
        # TODO : each instance should know how to serialize/deserialize itself
        if isinstance(self.storage, LocalStorage):
            serialized_files = {
                f.id: f.serialize() for f in await self.storage.get_files()
            }
            storage_config = LocalStorageConfig(
                storage_path=self.storage.dir_path, files=serialized_files
            )
        elif isinstance(self.storage, TransparentStorage):
            serialized_files = {
                f.id: f.serialize() for f in await self.storage.get_files()
            }
            storage_config = TransparentStorageConfig(files=serialized_files)
        else:
            raise Exception("can't serialize storage. not supported for now")

        bserialized = BrainSerialized(
            id=self.id,
            name=self.name,
            chat_history=self.chat_history.get_chat_history(),
            llm_config=self.llm.get_config(),
            vectordb_config=vector_store,
            embedding_config=embedder_config,
            storage_config=storage_config,
        )

        with open(os.path.join(brain_path, "config.json"), "w") as f:
            f.write(bserialized.model_dump_json())
        return brain_path

    def info(self) -> BrainInfo:
        # TODO: dim of embedding
        # "embedder": {},
        chats_info = ChatHistoryInfo(
            nb_chats=len(self._chats),
            current_default_chat=self.default_chat.id,
            current_chat_history_length=len(self.default_chat),
        )

        return BrainInfo(
            brain_id=self.id,
            brain_name=self.name,
            files_info=self.storage.info() if self.storage else None,
            chats_info=chats_info,
            llm_info=self.llm.info(),
        )

    @property
    def chat_history(self) -> ChatHistory:
        return self.default_chat

    def _init_chats(self) -> Dict[UUID, ChatHistory]:
        chat_id = uuid4()
        default_chat = ChatHistory(chat_id=chat_id, brain_id=self.id)
        return {chat_id: default_chat}

    @classmethod
    async def afrom_files(
        cls,
        *,
        name: str,
        file_paths: list[str | Path],
        vector_db: VectorStore | None = None,
        storage: StorageBase = TransparentStorage(),
        llm: LLMEndpoint | None = None,
        embedder: Embeddings | None = None,
        skip_file_error: bool = False,
        processor_kwargs: dict[str, Any] | None = None,
    ):
        """
        Create a brain from a list of file paths.
        Args:
            name (str): The name of the brain.
            file_paths (list[str | Path]): The list of file paths to add to the brain.
            vector_db (VectorStore | None): The vector store used to store the processed files.
            storage (StorageBase): The storage used to store the files.
            llm (LLMEndpoint | None): The language model used to generate the answer.
            embedder (Embeddings | None): The embeddings used to create the index of the processed files.
            skip_file_error (bool): Whether to skip files that cannot be processed.
            processor_kwargs (dict[str, Any] | None): Additional arguments for the processor.
        Returns:
            Brain: The brain created from the file paths.
        Example:
        ```python
        brain = await Brain.afrom_files(name="My Brain", file_paths=["file1.pdf", "file2.pdf"])
        brain.print_info()
        ```
        """
        if llm is None:
            llm = default_llm()

        if embedder is None:
            embedder = default_embedder()

        processor_kwargs = processor_kwargs or {}

        brain_id = uuid4()

        # TODO: run in parallel using tasks

        for path in file_paths:
            file = await load_qfile(brain_id, path)
            await storage.upload_file(file)

        logger.debug(f"uploaded all files to {storage}")

        # Parse files
        docs = await process_files(
            storage=storage,
            skip_file_error=skip_file_error,
            **processor_kwargs,
        )

        # Building brain's vectordb
        if vector_db is None:
            vector_db = await build_default_vectordb(docs, embedder)
        else:
            await vector_db.aadd_documents(docs)

        logger.debug(f"added {len(docs)} chunks to vectordb")

        return cls(
            id=brain_id,
            name=name,
            storage=storage,
            llm=llm,
            embedder=embedder,
            vector_db=vector_db,
        )

    @classmethod
    def from_files(
        cls,
        *,
        name: str,
        file_paths: list[str | Path],
        vector_db: VectorStore | None = None,
        storage: StorageBase = TransparentStorage(),
        llm: LLMEndpoint | None = None,
        embedder: Embeddings | None = None,
        skip_file_error: bool = False,
        processor_kwargs: dict[str, Any] | None = None,
    ) -> Self:
        loop = asyncio.get_event_loop()
        return loop.run_until_complete(
            cls.afrom_files(
                name=name,
                file_paths=file_paths,
                vector_db=vector_db,
                storage=storage,
                llm=llm,
                embedder=embedder,
                skip_file_error=skip_file_error,
                processor_kwargs=processor_kwargs,
            )
        )

    @classmethod
    async def afrom_langchain_documents(
        cls,
        *,
        name: str,
        langchain_documents: list[Document],
        vector_db: VectorStore | None = None,
        storage: StorageBase = TransparentStorage(),
        llm: LLMEndpoint | None = None,
        embedder: Embeddings | None = None,
    ) -> Self:
        """
        Create a brain from a list of langchain documents.
        Args:
            name (str): The name of the brain.
            langchain_documents (list[Document]): The list of langchain documents to add to the brain.
            vector_db (VectorStore | None): The vector store used to store the processed files.
            storage (StorageBase): The storage used to store the files.
            llm (LLMEndpoint | None): The language model used to generate the answer.
            embedder (Embeddings | None): The embeddings used to create the index of the processed files.
        Returns:
            Brain: The brain created from the langchain documents.
        Example:
        ```python
        from langchain_core.documents import Document
        documents = [Document(page_content="Hello, world!")]
        brain = await Brain.afrom_langchain_documents(name="My Brain", langchain_documents=documents)
        brain.print_info()
        ```
        """

        if llm is None:
            llm = default_llm()

        if embedder is None:
            embedder = default_embedder()

        brain_id = uuid4()

        # Building brain's vectordb
        if vector_db is None:
            vector_db = await build_default_vectordb(langchain_documents, embedder)
        else:
            await vector_db.aadd_documents(langchain_documents)

        return cls(
            id=brain_id,
            name=name,
            storage=storage,
            llm=llm,
            embedder=embedder,
            vector_db=vector_db,
        )

    async def asearch(
        self,
        query: str | Document,
        n_results: int = 5,
        filter: Callable | Dict[str, Any] | None = None,
        fetch_n_neighbors: int = 20,
    ) -> list[SearchResult]:
        """
        Search for relevant documents in the brain based on a query.
        Args:
            query (str | Document): The query to search for.
            n_results (int): The number of results to return.
            filter (Callable | Dict[str, Any] | None): The filter to apply to the search.
            fetch_n_neighbors (int): The number of neighbors to fetch.
        Returns:
            list[SearchResult]: The list of retrieved chunks.
        Example:
        ```python
        brain = Brain.from_files(name="My Brain", file_paths=["file1.pdf", "file2.pdf"])
        results = await brain.asearch("Why everybody loves Quivr?")
        for result in results:
            print(result.chunk.page_content)
        ```
        """
        if not self.vector_db:
            raise ValueError("No vector db configured for this brain")

        result = await self.vector_db.asimilarity_search_with_score(
            query, k=n_results, filter=filter, fetch_k=fetch_n_neighbors
        )

        return [SearchResult(chunk=d, distance=s) for d, s in result]

    def get_chat_history(self, chat_id: UUID):
        return self._chats[chat_id]

    # TODO(@aminediro)
    def add_file(self) -> None:
        # add it to storage
        # add it to vectorstore
        raise NotImplementedError

    # ---------------------------------------------------------------------------
    # Prompt-injection guardrail
    # ---------------------------------------------------------------------------
    @staticmethod
    def _sanitize_prompt_injection(value: str, field_name: str = "input") -> str:
        """Raise ValueError if *value* looks like a prompt-injection attempt.

        Checks for the most common injection patterns (ignore/override/forget
        previous instructions, role-switching directives, jailbreak markers).
        Extend the pattern list as new attack vectors are discovered.
        """
        import re

        _INJECTION_PATTERNS = [
            r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?",
            r"disregard\s+(all\s+)?(previous|prior|above)\s+instructions?",
            r"forget\s+(all\s+)?(previous|prior|above)\s+instructions?",
            r"override\s+(all\s+)?(previous|prior|above)\s+instructions?",
            r"you\s+are\s+now\s+(a|an|the)\b",
            r"act\s+as\s+(a|an|the)\b",
            r"pretend\s+(you\s+are|to\s+be)\b",
            r"do\s+not\s+follow\s+(your\s+)?(previous|prior|original)\s+instructions?",
            r"system\s*:\s*you\s+are",
            r"<\s*system\s*>",
            r"\[\s*system\s*\]",
            r"###\s*instruction",
            r"jailbreak",
            r"dan\s+mode",
            r"developer\s+mode",
        ]

        lowered = value.lower()
        for pattern in _INJECTION_PATTERNS:
            if re.search(pattern, lowered):
                raise ValueError(
                    f"Prompt injection detected in '{field_name}': "
                    f"input blocked by security guardrail."
                )
        return value

    # ---------------------------------------------------------------------------

    async def ask_streaming(
        self,
        question: str,
        run_id: UUID,
        system_prompt: str | None = None,
        retrieval_config: RetrievalConfig | None = None,
        rag_pipeline: Type[Union[QuivrQARAG, QuivrQARAGLangGraph]] | None = None,
        list_files: list[QuivrKnowledge] | None = None,
        chat_history: ChatHistory | None = None,
        **input_kwargs,
    ) -> AsyncGenerator[ParsedRAGChunkResponse, ParsedRAGChunkResponse]:
        """
        Ask a question to the brain and get a streamed generated answer.
        Args:
            question (str): The question to ask.
            retrieval_config (RetrievalConfig | None): The retrieval configuration (see RetrievalConfig docs).
            rag_pipeline (Type[Union[QuivrQARAG, QuivrQARAGLangGraph]] | None): The RAG pipeline to use.
        list_files (list[QuivrKnowledge] | None): The list of files to include in the RAG pipeline.
            chat_history (ChatHistory | None): The chat history to use.
        Returns:
            AsyncGenerator[ParsedRAGChunkResponse, ParsedRAGChunkResponse]: The streamed generated answer.
        Example:
        ```python
        brain = Brain.from_files(name="My Brain", file_paths=["file1.pdf", "file2.pdf"])
        async for chunk in brain.ask_streaming("What is the meaning of life?"):
            print(chunk.answer)
        ```
        """
        # --- Prompt-injection guardrail ---
        question = self._sanitize_prompt_injection(question, "question")
        if system_prompt is not None:
            system_prompt = self._sanitize_prompt_injection(system_prompt, "system_prompt")
        # --- End guardrail ---

        llm = self.llm

        # If you passed a different llm model we'll override the brain  one
        if retrieval_config:
            if retrieval_config.llm_config != self.llm.get_config():
                llm = LLMEndpoint.from_config(config=retrieval_config.llm_config)
        else:
            retrieval_config = RetrievalConfig(llm_config=self.llm.get_config())

        rag_instance = QuivrQARAGLangGraph(
            retrieval_config=retrieval_config, llm=llm, vector_store=self.vector_db
        )

        chat_history = self.default_chat if chat_history is None else chat_history
        list_files = [] if list_files is None else list_files

        full_answer = ""

        metadata = LangchainMetadata(
            langfuse_trace_id=str(run_id),
            langfuse_user_id=str(self.workspace_id),
            langfuse_session_id=str(self.chat_id),
        )

        async for response in rag_instance.answer_astream(
            run_id=run_id,
            question=question,
            system_prompt=system_prompt or None,
            history=chat_history,
            list_files=list_files,
            metadata=metadata,
            **input_kwargs,
        ):
            # Sanitize LLM output to remove dynamic code execution primitives
            sanitized_answer = sanitize_llm_output(response.answer)
            response = ParsedRAGChunkResponse(
                answer=sanitized_answer,
                metadata=response.metadata,
                last_chunk=response.last_chunk,
            )
            # Format output to be correct servicedf;j
            if not response.last_chunk:
                yield response
            full_answer += response.answer

        # TODO : add sources, metdata etc  ...
        chat_history.append(HumanMessage(content=question))
        chat_history.append(AIMessage(content=full_answer))
        yield response

    async def aask(
        self,
        run_id: UUID,
        question: str,
        system_prompt: str | None = None,
        retrieval_config: RetrievalConfig | None = None,
        rag_pipeline: Type[Union[QuivrQARAG, QuivrQARAGLangGraph]] | None = None,
        list_files: list[QuivrKnowledge] | None = None,
        chat_history: ChatHistory | None = None,
        **input_kwargs,
    ) -> ParsedRAGResponse:
        """
        Synchronous version that asks a question to the brain and gets a generated answer.
        Args:
            question (str): The question to ask.
            retrieval_config (RetrievalConfig | None): The retrieval configuration (see RetrievalConfig docs).
            rag_pipeline (Type[Union[QuivrQARAG, QuivrQARAGLangGraph]] | None): The RAG pipeline to use.
            list_files (list[QuivrKnowledge] | None): The list of files to include in the RAG pipeline.
            chat_history (ChatHistory | None): The chat history to use.
        Returns:
            ParsedRAGResponse: The generated answer.
        """
        # question_language = detect_language(question) -- Commented until we use it
        full_answer = ""
        metadata = None

        async for response in self.ask_streaming(
            run_id=run_id,
            question=question,
            system_prompt=system_prompt,
            retrieval_config=retrieval_config,
            rag_pipeline=rag_pipeline,
            list_files=list_files,
            chat_history=chat_history,
            **input_kwargs,
        ):
            full_answer += response.answer
            if response.metadata:
                metadata = response.metadata

        return ParsedRAGResponse(answer=sanitize_llm_output(full_answer), metadata=metadata)

    def ask(
        self,
        run_id: UUID,
        question: str,
        system_prompt: str | None = None,
        retrieval_config: RetrievalConfig | None = None,
        rag_pipeline: Type[Union[QuivrQARAG, QuivrQARAGLangGraph]] | None = None,
        list_files: list[QuivrKnowledge] | None = None,
        chat_history: ChatHistory | None = None,
    ) -> ParsedRAGResponse:
        """
        Fully synchronous version that asks a question to the brain and gets a generated answer.
        Args:
            question (str): The question to ask.
            system_prompt (str | None): The system prompt to use.
            retrieval_config (RetrievalConfig | None): The retrieval configuration (see RetrievalConfig docs).
            rag_pipeline (Type[Union[QuivrQARAG, QuivrQARAGLangGraph]] | None): The RAG pipeline to use.
            list_files (list[QuivrKnowledge] | None): The list of files to include in the RAG pipeline.
            chat_history (ChatHistory | None): The chat history to use.
        Returns:
            ParsedRAGResponse: The generated answer.
        """
        logger.info(
            "LLM request (sync)",
            extra={
                "run_id": str(run_id),
                "question": question,
                "system_prompt": system_prompt,
            },
        )
        loop = asyncio.get_event_loop()
        response = loop.run_until_complete(
            self.aask(
                run_id=run_id,
                question=question,
                system_prompt=system_prompt,
                retrieval_config=retrieval_config,
                rag_pipeline=rag_pipeline,
                list_files=list_files,
                chat_history=chat_history,
            )
        )
        logger.info(
            "LLM response (sync)",
            extra={
                "run_id": str(run_id),
                "answer": response.answer,
                "metadata": str(response.metadata),
            },
        )
        return response
