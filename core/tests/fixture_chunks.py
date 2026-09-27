import asyncio
import json
import re
from uuid import uuid4

from langchain_core.embeddings import DeterministicFakeEmbedding
from langchain_core.messages.ai import AIMessageChunk
from langchain_core.vectorstores import InMemoryVectorStore
from quivr_core.rag.entities.chat import ChatHistory
from quivr_core.rag.entities.config import LLMEndpointConfig, RetrievalConfig

# Model card / technical documentation for the GPAI model used below.
# See the official OpenAI research page for gpt-4o details and usage policy.
MODEL_CARD_URL = "https://openai.com/research/"  # TODO: replace with the exact gpt-4o model card URL before deployment
from quivr_core.llm import LLMEndpoint
from quivr_core.rag.quivr_rag_langgraph import QuivrQARAGLangGraph


DANGEROUS_PATTERNS = [
    r"\beval\s*\(",
    r"\bexec\s*\(",
    r"\bsubprocess\s*\.\s*\w*\s*\([^)]*shell\s*=\s*True",
    r"\b__import__\s*\(",
    r"\bcompile\s*\(",
    r"\bexecfile\s*\(",
    r"\binput\s*\(",
    r"\bos\.system\s*\(",
    r"\bos\.popen\s*\(",
    r"\beval\b",
    r"\bFunction\s*\(",
    r"setTimeout\s*\(",
    r"setInterval\s*\(",
    r"new\s+Function\s*\(",
]


def sanitize_llm_output(text: str) -> str:
    """Remove lines containing dynamic code execution primitives from LLM output."""
    import re
    if not text:
        return text
    lines = text.splitlines(keepends=True)
    safe_lines = []
    for line in lines:
        is_dangerous = any(re.search(pattern, line) for pattern in DANGEROUS_PATTERNS)
        if not is_dangerous:
            safe_lines.append(line)
    return "".join(safe_lines)


def sanitize_input(value):
    """Sanitize a string value to block prompt injection attempts."""
    if value is None:
        return None
    if not isinstance(value, str):
        return value
    # Block common prompt injection patterns
    injection_patterns = [
        r"(?i)(ignore\s+(all\s+)?(previous|prior|above)\s+instructions)",
        r"(?i)(disregard\s+(all\s+)?(previous|prior|above)\s+instructions)",
        r"(?i)(forget\s+(all\s+)?(previous|prior|above)\s+instructions)",
        r"(?i)(you\s+are\s+now\s+[a-z])",
        r"(?i)(act\s+as\s+(a\s+)?[a-z])",
        r"(?i)(system\s*:\s*)",
        r"(?i)(\[\s*system\s*\])",
        r"(?i)(new\s+instructions?\s*:)",
        r"(?i)(override\s+(previous\s+)?instructions?)",
        r"(?i)(jailbreak)",
        r"(?i)(prompt\s+injection)",
    ]
    for pattern in injection_patterns:
        if re.search(pattern, value):
            raise ValueError(
                f"Prompt injection attempt detected and blocked in input: {value[:80]!r}"
            )
    return value


def sanitize_chat_history(chat_history):
    """Sanitize chat history messages to block prompt injection."""
    if chat_history is None:
        return chat_history
    # If it's iterable with messages, sanitize each message content
    if hasattr(chat_history, 'messages'):
        for msg in chat_history.messages:
            if hasattr(msg, 'content') and isinstance(msg.content, str):
                sanitize_input(msg.content)
    return chat_history


async def main():
    retrieval_config = RetrievalConfig(llm_config=LLMEndpointConfig(model="gpt-4o-mini"))
    embedder = DeterministicFakeEmbedding(size=20)
    vec = InMemoryVectorStore(embedder)

    llm = LLMEndpoint.from_config(retrieval_config.llm_config)
    chat_history = ChatHistory(uuid4(), uuid4())
    rag_pipeline = QuivrQARAGLangGraph(
        retrieval_config=retrieval_config, llm=llm, vector_store=vec
    )

    conversational_qa_chain = rag_pipeline.build_chain()

    # Sanitize all user-supplied inputs before passing to the LLM pipeline
    safe_user_message = sanitize_input("What is NLP, give a very long detailed answer")
    safe_chat_history = sanitize_chat_history(chat_history)
    safe_custom_personality = sanitize_input(None)

    with open("response.jsonl", "w") as f:
        async for event in conversational_qa_chain.astream_events(
            {
                "messages": [
                    ("user", safe_user_message),
                ],
                "chat_history": safe_chat_history,
                "custom_personality": safe_custom_personality,
            },
            version="v1",
            config={"metadata": {}},
        ):
            kind = event["event"]
            if (
                kind == "on_chat_model_stream"
                and event["metadata"]["langgraph_node"] == "generate"
            ):
                chunk = event["data"]["chunk"]
                sanitized_chunk = {}
                for k, v in chunk.items():
                    if isinstance(v, AIMessageChunk):
                        v_dict = v.dict()
                        if "content" in v_dict and isinstance(v_dict["content"], str):
                            v_dict["content"] = sanitize_llm_output(v_dict["content"])
                        sanitized_chunk[k] = v_dict
                    elif isinstance(v, str):
                        sanitized_chunk[k] = sanitize_llm_output(v)
                    else:
                        sanitized_chunk[k] = v
                f.write(json.dumps(sanitized_chunk) + "\n")


asyncio.run(main())
