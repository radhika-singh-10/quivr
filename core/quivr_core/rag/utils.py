import logging
import re
from typing import Any, Dict, List, Tuple, no_type_check

from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage
from langchain_core.messages.ai import AIMessageChunk
from langchain_core.prompts import format_document
from langfuse.callback import CallbackHandler

from quivr_core.rag.entities.config import WorkflowConfig
from quivr_core.rag.entities.models import (
    ChatLLMMetadata,
    ParsedRAGResponse,
    QuivrKnowledge,
    RAGResponseMetadata,
    RawRAGResponse,
)
from quivr_core.rag.prompts import TemplatePromptName, custom_prompts

# TODO(@aminediro): define a types packages where we clearly define IO types
# This should be used for serialization/deseriallization later


import re

logger = logging.getLogger("quivr_core")


def sanitize_input_2(text: str) -> str:
    """Strip common prompt-injection patterns from user-supplied text."""
    import re
    # Remove attempts to override system instructions
    patterns = [
        r"(?i)ignore\s+(all\s+)?(previous|prior|above)\s+instructions?",
        r"(?i)disregard\s+(all\s+)?(previous|prior|above)\s+instructions?",
        r"(?i)forget\s+(all\s+)?(previous|prior|above)\s+instructions?",
        r"(?i)you\s+are\s+now\s+(?:a|an|the)\s+",
        r"(?i)act\s+as\s+(?:a|an|the)\s+",
        r"(?i)new\s+instructions?\s*:",
        r"(?i)system\s*:\s*",
        r"(?i)<\s*/?\s*(?:system|instructions?|prompt)\s*>",
    ]
    sanitized = text
    for pattern in patterns:
        sanitized = re.sub(pattern, "[FILTERED]", sanitized)
    return sanitized

# Known prompt injection patterns: role overrides, delimiter abuse, instruction keywords
_INJECTION_PATTERNS = re.compile(
    r"(\bsystem\b|\buser\b|\bassistant\b|\bhuman\b)\s*:\s*"
    r"|<\s*(system|user|assistant|human|instruction|prompt)\s*>"
    r"|\[\s*(INST|SYS|SYSTEM|USER|ASSISTANT)\s*\]"
    r"|###\s*(Instruction|System|Human|Assistant)"
    r"|ignore (previous|above|prior|all) instructions?"
    r"|you are now|pretend (you are|to be)|act as (a |an )?(different|new)?",
    re.IGNORECASE,
)


def sanitize_input(value: str, field_name: str = "input") -> str:
    """Sanitize user-supplied or config-supplied string values before prompt inclusion.

    Raises ValueError and logs a warning if injection patterns are detected.
    Returns the original value if it passes validation.
    """
    if not isinstance(value, str):
        raise TypeError(f"Expected str for {field_name}, got {type(value).__name__}")
    if _INJECTION_PATTERNS.search(value):
        logger.warning(
            "Potential prompt injection detected in %s: %r — request blocked.",
            field_name,
            value[:200],
        )
        raise ValueError(
            f"Input for '{field_name}' contains disallowed patterns and was rejected."
        )
    return value

# Patterns that indicate dynamic code execution primitives in LLM output
_DANGEROUS_PATTERNS = [
    re.compile(r'\beval\s*\(', re.IGNORECASE),
    re.compile(r'\bexec\s*\(', re.IGNORECASE),
    re.compile(r'\bexecfile\s*\(', re.IGNORECASE),
    re.compile(r'\bcompile\s*\(', re.IGNORECASE),
    re.compile(r'\b__import__\s*\(', re.IGNORECASE),
    re.compile(r'subprocess\.(?:call|run|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True', re.IGNORECASE | re.DOTALL),
    re.compile(r'\bos\.system\s*\(', re.IGNORECASE),
    re.compile(r'\bos\.popen\s*\(', re.IGNORECASE),
    re.compile(r'\bcommands\.getoutput\s*\(', re.IGNORECASE),
    # JavaScript / bash eval
    re.compile(r'\beval\s*`', re.IGNORECASE),
    re.compile(r'\$\(\s*eval\b', re.IGNORECASE),
]


def sanitize_llm_output(text: str) -> str:
    """Remove lines from LLM output that contain dynamic code execution primitives.

    Args:
        text: The raw text returned by the LLM.

    Returns:
        The sanitized text with dangerous lines removed.
    """
    if not text:
        return text
    lines = text.splitlines(keepends=True)
    sanitized_lines = []
    for line in lines:
        if any(pattern.search(line) for pattern in _DANGEROUS_PATTERNS):
            logger.warning(
                "Removed potentially dangerous line from LLM output: %r", line.rstrip()
            )
        else:
            sanitized_lines.append(line)
    return "".join(sanitized_lines)


def model_supports_function_calling(model_name: str):
    models_not_supporting_function_calls: list[str] = ["llama2", "test", "ollama3"]

    return model_name not in models_not_supporting_function_calls


def format_history_to_openai_mesages(
    tuple_history: List[Tuple[str, str]], system_message: str, question: str
) -> List[BaseMessage]:
    """Format the chat history into a list of Base Messages"""
    messages = []
    messages.append(SystemMessage(content=system_message))
    for human, ai in tuple_history:
        messages.append(HumanMessage(content=human))
        messages.append(AIMessage(content=ai))
    sanitized_question = sanitize_input(question, field_name="question")
    # Wrap user data in XML delimiters to structurally separate it from system instructions
    user_data_block = f"<user_input>\n{sanitized_question}\n</user_input>"
    messages.append(HumanMessage(content=user_data_block))
    return messages


def cited_answer_filter(tool):
    return tool["name"] == "cited_answer"


def _coerce_citations(raw: Any) -> list[int]:
    """Keep only integer citation IDs. Local models often stream "[1]" as ["[", "1", "]"]."""
    if raw is None:
        return []
    if not isinstance(raw, list):
        raw = [raw]

    citations: list[int] = []
    for item in raw:
        if isinstance(item, bool):
            continue
        if isinstance(item, int):
            citations.append(item)
            continue
        if isinstance(item, str):
            stripped = item.strip().strip("[]")
            if stripped.isdigit() or (
                stripped.startswith("-") and stripped[1:].isdigit()
            ):
                citations.append(int(stripped))
    return citations


def get_chunk_metadata(
    msg: AIMessageChunk, sources: list[Any] | None = None
) -> RAGResponseMetadata:
    metadata = {"sources": sources or []}

    if not msg.tool_calls:
        return RAGResponseMetadata(**metadata, metadata_model=None)

    all_citations = []
    all_followup_questions = []

    for tool_call in msg.tool_calls:
        if tool_call.get("name") == "cited_answer" and "args" in tool_call:
            args = tool_call["args"]
            all_citations.extend(_coerce_citations(args.get("citations", [])))
            followups = args.get("followup_questions", [])
            if isinstance(followups, list):
                all_followup_questions.extend(
                    [q for q in followups if isinstance(q, str)]
                )

    metadata["citations"] = all_citations
    metadata["followup_questions"] = all_followup_questions[:3]  # Limit to 3

    return RAGResponseMetadata(**metadata, metadata_model=None)


def get_prev_message_str(msg: AIMessageChunk) -> str:
    if msg.tool_calls:
        cited_answer = next(x for x in msg.tool_calls if cited_answer_filter(x))
        if "args" in cited_answer and "answer" in cited_answer["args"]:
            return cited_answer["args"]["answer"]
    return ""


# TODO: CONVOLUTED LOGIC !
# TODO(@aminediro): redo this
@no_type_check
def parse_chunk_response(
    rolling_msg: AIMessageChunk,
    raw_chunk: AIMessageChunk,
    supports_func_calling: bool,
    previous_content: str = "",
) -> Tuple[AIMessageChunk, str, str]:
    """Parse a chunk response
    Args:
        rolling_msg: The accumulated message so far
        raw_chunk: The new chunk to add
        supports_func_calling: Whether function calling is supported
        previous_content: The previous content string
    Returns:
        Tuple of (updated rolling message, new content only, full content)
    """
    rolling_msg += raw_chunk

    tool_calls = rolling_msg.tool_calls

    if not supports_func_calling or not tool_calls:
        new_content = sanitize_llm_output(raw_chunk.content)  # Just the new chunk's content
        full_content = sanitize_llm_output(rolling_msg.content)  # The full accumulated content
        return rolling_msg, new_content, full_content

    current_answers = get_answers_from_tool_calls(tool_calls)
    full_answer = "\n\n".join(current_answers)
    if not full_answer:
        full_answer = previous_content

    full_answer = sanitize_llm_output(full_answer)
    new_content = full_answer[len(previous_content) :]

    return rolling_msg, new_content, full_answer


def get_answers_from_tool_calls(tool_calls):
    answers = []
    for tool_call in tool_calls:
        if tool_call.get("name") == "cited_answer":
            args = tool_call.get("args", {})
            if isinstance(args, dict):
                answers.append(sanitize_llm_output(args.get("answer", "")))
            else:
                logger.warning(f"Expected dict for tool_call args, got {type(args)}")
    return answers


@no_type_check
def parse_response(raw_response: RawRAGResponse, model_name: str) -> ParsedRAGResponse:
    answers = []
    sources = raw_response["docs"] if "docs" in raw_response else []

    metadata = RAGResponseMetadata(
        sources=sources, metadata_model=ChatLLMMetadata(name=model_name)
    )

    if (
        model_supports_function_calling(model_name)
        and "tool_calls" in raw_response["answer"]
        and raw_response["answer"].tool_calls
    ):
        all_citations = []
        all_followup_questions = []
        for tool_call in raw_response["answer"].tool_calls:
            if "args" in tool_call:
                args = tool_call["args"]
                if "citations" in args:
                    all_citations.extend(_coerce_citations(args["citations"]))
                if "followup_questions" in args:
                    all_followup_questions.extend(args["followup_questions"])
                if "answer" in args:
                    answers.append(sanitize_llm_output(args["answer"]))
        metadata.citations = all_citations
        metadata.followup_questions = all_followup_questions
    else:
        answers.append(sanitize_llm_output(raw_response["answer"].content))

    answer_str = "\n".join(answers)
    parsed_response = ParsedRAGResponse(answer=answer_str, metadata=metadata)
    return parsed_response


def combine_documents(
    docs,
    document_prompt=custom_prompts[TemplatePromptName.DEFAULT_DOCUMENT_PROMPT],
    document_separator="\n\n",
):
    # for each docs, add an index in the metadata to be able to cite the sources
    for doc, index in zip(docs, range(len(docs)), strict=False):
        doc.metadata["index"] = index
    doc_strings = [format_document(doc, document_prompt) for doc in docs]
    return document_separator.join(doc_strings)


def format_file_list(
    list_files_array: list[QuivrKnowledge], max_files: int = 20
) -> str:
    list_files = [file.file_name or file.url for file in list_files_array]
    files: list[str] = list(filter(lambda n: n is not None, list_files))  # type: ignore
    files = files[:max_files]

    files_str = "\n".join(files) if list_files_array else "None"
    return files_str


def collect_tools(workflow_config: WorkflowConfig):
    validated_tools = "Available tools which can be activated:\n"
    for i, tool in enumerate(workflow_config.validated_tools):
        safe_name = sanitize_input(str(tool.name), field_name=f"validated_tool[{i}].name")
        safe_desc = sanitize_input(str(tool.description), field_name=f"validated_tool[{i}].description")
        validated_tools += "Tool " + str(i + 1) + " name: " + safe_name + "\n"
        validated_tools += "Tool " + str(i + 1) + " description: " + safe_desc + "\n\n"

    activated_tools = "Activated tools which can be deactivated:\n"
    for i, tool in enumerate(workflow_config.activated_tools):
        safe_name = sanitize_input(str(tool.name), field_name=f"activated_tool[{i}].name")
        safe_desc = sanitize_input(str(tool.description), field_name=f"activated_tool[{i}].description")
        activated_tools += "Tool " + str(i + 1) + " name: " + safe_name + "\n"
        activated_tools += "Tool " + str(i + 1) + " description: " + safe_desc + "\n\n"

    return validated_tools, activated_tools


def format_dict(kv: Dict[str, str]) -> str:
    return "\n".join([f"{k}: {v}" for k, v in kv.items() if v is not None and v != ""])


class LangfuseService:
    def __init__(self):
        self.langfuse_handler = CallbackHandler()

    def get_handler(self):
        return self.langfuse_handler
