import logging
import re
from operator import itemgetter
from typing import AsyncGenerator, Optional, Sequence

# TODO(@aminediro): this is the only dependency to langchain package, we should remove it
from langchain.retrievers import ContextualCompressionRetriever
from langchain_core.callbacks import Callbacks
from langchain_core.documents import BaseDocumentCompressor, Document
from langchain_core.messages import AIMessage, HumanMessage
from langchain_core.messages.ai import AIMessageChunk
from langchain_core.output_parsers import StrOutputParser
from langchain_core.runnables import RunnableLambda, RunnablePassthrough
from langchain_core.vectorstores import VectorStore

from quivr_core.llm import LLMEndpoint

# Model card / technical documentation reference for the GPAI model integration (LLMEndpoint).
# TODO: Replace with the exact model card URL for the model deployed before going to production.
# Examples: https://openai.com/research/ (OpenAI), https://www.anthropic.com/research (Anthropic),
#           https://ai.google.dev/gemini-api/docs (Gemini)
_ai_iac_024_MODEL_CARD_URL: str = "https://openai.com/research/"  # TODO: set to the exact model card URL

# Disapproved LLM models — blocked per organization registry
_ai_app_sec_006_DISAPPROVED_MODELS: list[str] = [
    "deepseekchat",
    "deepseekr1",
    "deepseekr1distillllama70b",
    "deepseekreasoner",
    "customllmclientnull",
    "deepseekChatnull",
    "openrouternull",
    "usdeepseekr1v10null",
]


def _ai_app_sec_006_normalize_model_name(name: str) -> str:
    """Normalize a model identifier for registry comparison."""
    if not name:
        return ""
    return re.sub(r"[\s\-_\.:\u00b7]", "", name).lower()


def _ai_app_sec_006_is_disapproved(model_name: str) -> bool:
    """Return True if the model matches any disapproved registry entry."""
    normalized = _ai_app_sec_006_normalize_model_name(model_name)
    return any(
        normalized == _ai_app_sec_006_normalize_model_name(blocked)
        for blocked in _ai_app_sec_006_DISAPPROVED_MODELS
    )
from quivr_core.rag.entities.chat import ChatHistory
from quivr_core.rag.entities.config import RetrievalConfig
from quivr_core.rag.entities.models import (
    ParsedRAGChunkResponse,
    ParsedRAGResponse,
    QuivrKnowledge,
    RAGResponseMetadata,
    cited_answer,
)
from quivr_core.rag.prompts import TemplatePromptName, custom_prompts
from quivr_core.rag.utils import (
    LangfuseService,
    combine_documents,
    format_file_list,
    get_chunk_metadata,
    parse_chunk_response,
    parse_response,
)

import re

import re

logger = logging.getLogger("quivr_core")


def sanitize_input(text: str) -> str:
    """
    Sanitize user-supplied input to block common prompt injection patterns.
    Raises ValueError if a clear injection attempt is detected; otherwise
    strips suspicious directives and returns the cleaned text.
    """
    if not isinstance(text, str):
        return text
    # Patterns that indicate prompt injection attempts
    injection_patterns = [
        r"(?i)(ignore\s+(all\s+)?(previous|prior|above)\s+instructions?)",
        r"(?i)(disregard\s+(all\s+)?(previous|prior|above)\s+instructions?)",
        r"(?i)(forget\s+(all\s+)?(previous|prior|above)\s+instructions?)",
        r"(?i)(you\s+are\s+now\s+(?!a\s+helpful))",
        r"(?i)(act\s+as\s+(if\s+you\s+are|a)\s+(?!helpful))",
        r"(?i)(system\s*:\s*you\s+are)",
        r"(?i)(\[INST\]|\[/INST\]|<\|im_start\|>|<\|im_end\|>)",
        r"(?i)(jailbreak|dan\s+mode|developer\s+mode)",
    ]
    for pattern in injection_patterns:
        if re.search(pattern, text):
            raise ValueError(
                f"Potential prompt injection detected and blocked in user input."
            )
    return text


def sanitize_chat_history(messages):
    """
    Sanitize each message's content in a list of chat history messages.
    """
    sanitized = []
    for msg in messages:
        if hasattr(msg, 'content') and isinstance(msg.content, str):
            sanitized_content = sanitize_input(msg.content)
            # Reconstruct the same message type with sanitized content
            msg = msg.__class__(content=sanitized_content)
        sanitized.append(msg)
    return sanitized

# Patterns for dynamic code execution primitives that must be stripped from LLM output
_DANGEROUS_PATTERNS = re.compile(
    r"(?m)^[^\n]*"
    r"(?:"
    r"\beval\s*\("
    r"|\bexec\s*\("
    r"|\bsubprocess\s*\.\s*\w*\s*\([^)]*shell\s*=\s*True"
    r"|\bos\.system\s*\("
    r"|\bos\.popen\s*\("
    r"|\bcommands\.getoutput\s*\("
    r"|\bpickle\.loads\s*\("
    r"|\bcompile\s*\("
    r"|\b__import__\s*\("
    r"|\bimportlib\.import_module\s*\("
    r"|<script[^>]*>[\s\S]*?</script>"
    r")"
    r"[^\n]*$"
)


def sanitize_llm_output(text: str) -> str:
    """Remove lines containing dynamic code execution primitives from LLM output."""
    if not text:
        return text
    sanitized = _DANGEROUS_PATTERNS.sub("", text)
    # Collapse multiple consecutive blank lines introduced by removal
    sanitized = re.sub(r"\n{3,}", "\n\n", sanitized)
    return sanitized
langfuse_service = LangfuseService()
langfuse_handler = langfuse_service.get_handler()


# Leetspeak substitution map for normalizing obfuscated text before injection checks
_ai_app_sec_040_LEET_MAP: dict[str, str] = {
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s",
    "6": "g", "7": "t", "8": "b", "9": "q", "@": "a",
    "$": "s", "!": "i", "|_|": "u", "+": "t",
}

# Injection keywords to look for after leet-normalisation
_ai_app_sec_040_INJECTION_KEYWORDS = re.compile(
    r"(?i)("
    r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?"
    r"|disregard\s+(all\s+)?(previous|prior|above)\s+instructions?"
    r"|forget\s+(all\s+)?(previous|prior|above)\s+instructions?"
    r"|you\s+are\s+now\s+"
    r"|act\s+as\s+(if\s+you\s+are|a)\s+"
    r"|system\s*:\s*you\s+are"
    r"|jailbreak|dan\s+mode|developer\s+mode"
    r")"
)


def _ai_app_sec_040_normalize_leet(text: str) -> str:
    """Return a leet-decoded copy of *text* for injection-pattern matching."""
    result = text
    # Multi-char substitutions first
    result = result.replace("|_|", "u")
    for leet_char, normal_char in _ai_app_sec_040_LEET_MAP.items():
        if leet_char == "|_|":
            continue
        result = result.replace(leet_char, normal_char)
    return result


def _ai_app_sec_040_check_base64_injections(text: str) -> str:
    """Decode any base64-looking tokens in *text* and replace those that
    contain injection keywords with '<hidden_prompts_removed>'."""
    import base64 as _b64
    PLACEHOLDER = "<hidden_prompts_removed>"
    # Match base64 tokens: at least 20 chars of [A-Za-z0-9+/] optionally padded with =
    b64_pattern = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")

    def _replace_if_injection(m: re.Match) -> str:
        token = m.group(0)
        # Pad to a multiple of 4 so b64decode doesn't raise
        padded = token + "=" * (-len(token) % 4)
        try:
            decoded = _b64.b64decode(padded).decode("utf-8", errors="ignore")
        except Exception:
            return token
        if _ai_app_sec_040_INJECTION_KEYWORDS.search(decoded):
            return PLACEHOLDER
        return token

    return b64_pattern.sub(_replace_if_injection, text)


def _sanitize_document_content(text: str) -> str:
    """
    Replace hidden or invisible prompt patterns with '<hidden_prompts_removed>'.
    Covers:
      - Zero-width / invisible Unicode characters (ZWSP, ZWNJ, ZWJ, BOM, soft-hyphen, etc.)
      - Runs of whitespace-only content that span a significant portion of the text
        (white-on-white style padding blocks)
      - HTML/CSS tiny-font or white-colour spans commonly used for prompt injection
        e.g. <span style="font-size:0">...</span> or color:#fff / color:white
      - Null bytes and other non-printable control characters (except normal whitespace)
    """
    HIDDEN_PROMPT_PLACEHOLDER = "<hidden_prompts_removed>"

    # 1. Remove null bytes and non-printable control characters
    #    (keep normal whitespace: space, tab, newline, carriage-return)
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", HIDDEN_PROMPT_PLACEHOLDER, text)

    # 2. Strip zero-width / invisible Unicode characters
    invisible_unicode = (
        "\u200b"  # zero-width space
        "\u200c"  # zero-width non-joiner
        "\u200d"  # zero-width joiner
        "\u200e"  # left-to-right mark
        "\u200f"  # right-to-left mark
        "\u202a-\u202e"  # directional formatting
        "\u2060"  # word joiner
        "\u2061-\u2064"  # invisible math operators
        "\ufeff"  # BOM / zero-width no-break space
        "\u00ad"  # soft hyphen
        "\u034f"  # combining grapheme joiner
        "\u115f\u1160"  # Hangul fillers
        "\u3164"  # Hangul filler
        "\uffa0"  # halfwidth Hangul filler
    )
    text = re.sub(rf"[{invisible_unicode}]+", HIDDEN_PROMPT_PLACEHOLDER, text)

    # 3. HTML/CSS-based hidden text patterns
    #    a) font-size 0 or very small (0px, 0pt, 0em, 0rem, 1px, 1pt)
    text = re.sub(
        r"<[^>]*style\s*=\s*['\"][^'\"]*font-size\s*:\s*0[^'\"]*['\"][^>]*>.*?</[^>]+>",
        HIDDEN_PROMPT_PLACEHOLDER,
        text,
        flags=re.IGNORECASE | re.DOTALL,
    )
    #    b) color white / #fff / #ffffff (white-on-white)
    text = re.sub(
        r"<[^>]*style\s*=\s*['\"][^'\"]*color\s*:\s*(?:white|#fff(?:fff)?)[^'\"]*['\"][^>]*>.*?</[^>]+>",
        HIDDEN_PROMPT_PLACEHOLDER,
        text,
        flags=re.IGNORECASE | re.DOTALL,
    )
    #    c) visibility:hidden or display:none
    text = re.sub(
        r"<[^>]*style\s*=\s*['\"][^'\"]*(?:visibility\s*:\s*hidden|display\s*:\s*none)[^'\"]*['\"][^>]*>.*?</[^>]+>",
        HIDDEN_PROMPT_PLACEHOLDER,
        text,
        flags=re.IGNORECASE | re.DOTALL,
    )

    # 4. Large blocks of whitespace-only padding (white-on-white trick without HTML)
    #    Replace 20+ consecutive whitespace characters (spaces/tabs) with placeholder
    text = re.sub(r"[ \t]{20,}", HIDDEN_PROMPT_PLACEHOLDER, text)

    # 5. Leetspeak-obfuscated injection patterns
    #    Normalise leet substitutions and check for injection keywords; if found,
    #    replace the entire text with the placeholder so the payload is neutralised.
    leet_normalised = _ai_app_sec_040_normalize_leet(text)
    if _ai_app_sec_040_INJECTION_KEYWORDS.search(leet_normalised):
        text = HIDDEN_PROMPT_PLACEHOLDER

    # 6. Base64-encoded injection payloads
    text = _ai_app_sec_040_check_base64_injections(text)

    return text


class IdempotentCompressor(BaseDocumentCompressor):
    def compress_documents(
        self,
        documents: Sequence[Document],
        query: str,
        callbacks: Optional[Callbacks] = None,
    ) -> Sequence[Document]:
        sanitized = []
        for doc in documents:
            clean_content = _sanitize_document_content(doc.page_content)
            if clean_content != doc.page_content:
                doc = Document(page_content=clean_content, metadata=doc.metadata)
            sanitized.append(doc)
        return sanitized


import hashlib as _hashlib
import re as _re

# ---------------------------------------------------------------------------
# _ai_app_sec_067_: prompt-injection guard helpers
# ---------------------------------------------------------------------------
_ai_app_sec_067_INJECTION_PATTERNS = _re.compile(
    r"(?i)(ignore (previous|above|prior|all) instructions?"
    r"|you are now"
    r"|act as"
    r"|system\s*:"
    r"|<\s*/?system\s*>"
    r"|\[\s*system\s*\]"
    r"|###\s*instruction"
    r"|forget (everything|all)"
    r"|disregard"
    r"|override"
    r"|jailbreak"
    r"|prompt injection)"
)


def _ai_app_sec_067_check_injection(value: str, field_name: str = "input") -> str:
    """Raise ValueError and log if value matches known prompt-injection patterns."""
    if _ai_app_sec_067_INJECTION_PATTERNS.search(value):
        logger.warning(
            "Prompt injection attempt detected",
            extra={
                "field": field_name,
                "input_length": len(value),
                "input_hash": _hashlib.sha256(value.encode()).hexdigest(),
            },
        )
        raise ValueError(
            f"Input rejected: possible prompt injection detected in '{field_name}'."
        )
    return value


def _ai_app_sec_067_sanitize_question(question: str) -> str:
    """Sanitize and structurally delimit a user question before LLM use."""
    _ai_app_sec_067_check_injection(question, field_name="question")
    # Wrap in structural delimiters so the model can distinguish data from instructions
    return f"<user_question>{question}</user_question>"


def _ai_app_sec_067_log_chunk(label: str, chunk_id: int, answer_len: int, rolling_len: int, question_hash: str) -> None:
    """Log chunk metadata only — never log raw user input or model output."""
    logger.debug(
        label,
        extra={
            "chunk_id": chunk_id,
            "answer_len": answer_len,
            "rolling_msg_len": rolling_len,
            "question_hash": question_hash,
        },
    )


class QuivrQARAG:
    """
    QuivrQA RAG is a class that provides a RAG interface to the QuivrQA system.
    """

    def __init__(
        self,
        *,
        retrieval_config: RetrievalConfig,
        llm: LLMEndpoint,
        vector_store: VectorStore,
        reranker: BaseDocumentCompressor | None = None,
    ):
        model_name = getattr(retrieval_config.llm_config, "model", None)
        if model_name and _ai_app_sec_006_is_disapproved(model_name):
            raise ValueError(
                f"Model '{model_name}' is on the organization's disapproved LLM list and cannot be used."
            )
        self.retrieval_config = retrieval_config
        self.vector_store = vector_store
        # LLM model card / technical documentation: see _ai_iac_024_MODEL_CARD_URL
        self.llm_endpoint = llm  # Model card reference: _ai_iac_024_MODEL_CARD_URL
        self.reranker = reranker if reranker is not None else IdempotentCompressor()

    @property
    def retriever(self):
        """
        Retriever is a function that retrieves the documents from the vector store.
        """
        return self.vector_store.as_retriever()

    def filter_history(
        self,
        chat_history: ChatHistory,
    ):
        """
        Filter out the chat history to only include the messages that are relevant to the current question

        Takes in a chat_history= [HumanMessage(content='Qui est REDACTED ? '), AIMessage(content="REDACTED est une salariée travaillant pour l'entreprise Quivr en tant qu'AI Engineer, sous la direction de son supérieur hiérarchique, REDACTED."), HumanMessage(content='Dis moi en plus sur elle'), AIMessage(content=''), HumanMessage(content='Dis moi en plus sur elle'), AIMessage(content="Désolé, je n'ai pas d'autres informations sur REDACTED à partir des fichiers fournis.")]
        Returns a filtered chat_history with in priority: first max_tokens, then max_history where a Human message and an AI message count as one pair
        a token is 4 characters
        """
        total_tokens = 0
        total_pairs = 0
        filtered_chat_history: list[AIMessage | HumanMessage] = []
        for human_message, ai_message in chat_history.iter_pairs():
            # TODO: replace with tiktoken
            message_tokens = (len(human_message.content) + len(ai_message.content)) // 4
            if (
                total_tokens + message_tokens
                > self.retrieval_config.llm_config.max_output_tokens
                or total_pairs >= self.retrieval_config.max_history
            ):
                break
            filtered_chat_history.append(human_message)
            filtered_chat_history.append(ai_message)
            total_tokens += message_tokens
            total_pairs += 1

        return filtered_chat_history[::-1]

    def build_chain(self, files: str):
        """
        Builds the chain for the QuivrQA RAG.
        """
        compression_retriever = ContextualCompressionRetriever(
            base_compressor=self.reranker, base_retriever=self.retriever
        )

        loaded_memory = RunnablePassthrough.assign(
            chat_history=RunnableLambda(
                lambda x: sanitize_chat_history(
                    self.filter_history(x["chat_history"])
                ),
            ),
            question=lambda x: sanitize_input(x["question"]),
        )

        standalone_question = {
            "standalone_question": {
                "question": lambda x: x["question"],
                "chat_history": itemgetter("chat_history"),
            }
            | custom_prompts[TemplatePromptName.DEFAULT_DOCUMENT_PROMPT]
            | self.llm_endpoint._llm
            | StrOutputParser(),
        }

        # Now we retrieve the documents
        retrieved_documents = {
            "docs": itemgetter("standalone_question") | compression_retriever,
            "question": lambda x: x["standalone_question"],
            "custom_instructions": lambda x: self.retrieval_config.prompt,
        }

        final_inputs = {
            "context": lambda x: combine_documents(x["docs"]),
            "question": itemgetter("question"),
            "custom_instructions": itemgetter("custom_instructions"),
            "files": lambda _: files,  # TODO: shouldn't be here
        }

        # Bind the llm to cited_answer if model supports it
        llm = self.llm_endpoint._llm
        if self.llm_endpoint.supports_func_calling():
            llm = self.llm_endpoint._llm.bind_tools(
                [cited_answer],
                tool_choice="any",
            )

        answer = {
            "answer": final_inputs
            | custom_prompts[TemplatePromptName.RAG_ANSWER_PROMPT]
            | llm,
            "docs": itemgetter("docs"),
        }

        return loaded_memory | standalone_question | retrieved_documents | answer

    def answer(
        self,
        question: str,
        history: ChatHistory,
        list_files: list[QuivrKnowledge],
        metadata: dict[str, str] = {},
    ) -> ParsedRAGResponse:
        """
        Answers a question using the QuivrQA RAG synchronously.
        """
        concat_list_files = format_file_list(
            list_files, self.retrieval_config.max_files
        )
        conversational_qa_chain = self.build_chain(concat_list_files)
        safe_question = _ai_app_sec_067_sanitize_question(sanitize_input(question))
        raw_llm_response = conversational_qa_chain.invoke(
            {
                "question": safe_question,
                "chat_history": history,
                "custom_instructions": (self.retrieval_config.prompt),
            },
            config={"metadata": metadata, "callbacks": [langfuse_handler]},
        )
        response = parse_response(
            raw_llm_response, self.retrieval_config.llm_config.model
        )
        response.answer = sanitize_llm_output(response.answer)
        return response

    async def answer_astream(
        self,
        question: str,
        history: ChatHistory,
        list_files: list[QuivrKnowledge],
        metadata: dict[str, str] = {},
    ) -> AsyncGenerator[ParsedRAGChunkResponse, ParsedRAGChunkResponse]:
        """
        Answers a question using the QuivrQA RAG asynchronously.
        """
        concat_list_files = format_file_list(
            list_files, self.retrieval_config.max_files
        )
        conversational_qa_chain = self.build_chain(concat_list_files)

        rolling_message = AIMessageChunk(content="")
        sources = []
        prev_answer = ""
        chunk_id = 0

        safe_question = _ai_app_sec_067_sanitize_question(sanitize_input(question))
        _ai_app_sec_067_question_hash = _hashlib.sha256(question.encode()).hexdigest()
        async for chunk in conversational_qa_chain.astream(
            {
                "question": safe_question,
                "chat_history": history,
                "custom_personality": (self.retrieval_config.prompt),
            },
            config={"metadata": metadata, "callbacks": [langfuse_handler]},
        ):
            # Could receive this anywhere so we need to save it for the last chunk
            if "docs" in chunk:
                sources = chunk["docs"] if "docs" in chunk else []

            if "answer" in chunk:
                rolling_message, answer_str = parse_chunk_response(
                    rolling_message,
                    chunk,
                    self.llm_endpoint.supports_func_calling(),
                )

                if len(answer_str) > 0:
                    if self.llm_endpoint.supports_func_calling():
                        diff_answer = answer_str[len(prev_answer) :]
                        if len(diff_answer) > 0:
                            safe_diff = sanitize_llm_output(diff_answer)
                            parsed_chunk = ParsedRAGChunkResponse(
                                answer=safe_diff,
                                metadata=RAGResponseMetadata(),
                            )
                            prev_answer += diff_answer

                            _ai_app_sec_067_log_chunk(
                                "answer_astream func_calling=True",
                                chunk_id=chunk_id,
                                answer_len=len(safe_diff),
                                rolling_len=len(str(rolling_message.content)),
                                question_hash=_ai_app_sec_067_question_hash,
                            )
                            yield parsed_chunk
                    else:
                        safe_answer = sanitize_llm_output(answer_str)
                        parsed_chunk = ParsedRAGChunkResponse(
                            answer=safe_answer,
                            metadata=RAGResponseMetadata(),
                        )
                        _ai_app_sec_067_log_chunk(
                            "answer_astream func_calling=False",
                            chunk_id=chunk_id,
                            answer_len=len(safe_answer),
                            rolling_len=len(str(rolling_message.content)),
                            question_hash=_ai_app_sec_067_question_hash,
                        )
                        yield parsed_chunk

                    chunk_id += 1

        # Last chunk provides metadata
        last_chunk = ParsedRAGChunkResponse(
            answer="",
            metadata=get_chunk_metadata(rolling_message, sources),
            last_chunk=True,
        )
        _ai_app_sec_067_log_chunk(
            "answer_astream last_chunk",
            chunk_id=chunk_id,
            answer_len=0,
            rolling_len=len(str(rolling_message.content)),
            question_hash=_ai_app_sec_067_question_hash,
        )
        yield last_chunk
