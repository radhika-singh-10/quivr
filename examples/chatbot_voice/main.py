import tempfile
import os
import logging
import time
import uuid
import chainlit as cl

logger = logging.getLogger(__name__)
from quivr_core import Brain
from quivr_core.models import KnowledgeBrain
from quivr_core.llm import LLMEndpoint
from quivr_core.llm.llm_endpoint import LLMEndpointConfig
from quivr_core.rag.entities.config import RetrievalConfig
from openai import AsyncOpenAI
from chainlit.element import Element

from io import BytesIO
import re


def remove_leetspeak(text: str) -> str:
    """Detect and replace leetspeak-obfuscated prompts/commands with a safe placeholder."""
    # Map common leet substitutions back to latin letters for detection
    leet_map = str.maketrans({
        '0': 'o', '1': 'i', '3': 'e', '4': 'a',
        '5': 's', '6': 'g', '7': 't', '8': 'b', '@': 'a',
        '$': 's', '!': 'i', '+': 't', '|': 'i',
    })
    normalized = text.lower().translate(leet_map)

    # Patterns that indicate prompt-injection or system commands in leet
    suspicious_patterns = [
        r'\bignore\b.*\b(previous|above|prior|all)\b.*\b(instructions?|prompts?|commands?)\b',
        r'\b(system|admin|root)\b.*\b(prompt|command|instruction|override)\b',
        r'\b(exec|execute|run|eval|shell|cmd|bash|sh|powershell)\b',
        r'\b(sudo|chmod|chown|passwd|rm\s+-rf|wget|curl)\b',
        r'\b(you\s+are\s+now|act\s+as|pretend\s+to\s+be|your\s+new\s+role)\b',
        r'\b(disregard|forget|bypass|override|jailbreak)\b.*\b(instructions?|rules?|guidelines?|policy|policies)\b',
        r'\b(reveal|output|print|show|display)\b.*\b(system\s+prompt|instructions?|secret|password|token|key)\b',
        r'\b(do\s+not\s+follow|stop\s+following)\b.*\b(instructions?|rules?|guidelines?)\b',
    ]

    for pattern in suspicious_patterns:
        if re.search(pattern, normalized, re.IGNORECASE | re.DOTALL):
            return '<leetspeak_prompts_removed>'

    return text
import re

# Patterns that indicate dynamic code execution primitives
_DANGEROUS_PATTERNS = re.compile(
    r'\b(eval|exec)\s*\(',                          # Python/JS eval(...) or exec(...)
    re.IGNORECASE
)
_DANGEROUS_SHELL_PATTERNS = re.compile(
    r'subprocess\.(?:call|run|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True',
    re.IGNORECASE | re.DOTALL
)
_DANGEROUS_BASH_PATTERNS = re.compile(
    r'(?:^|\s)eval\s+["\']',                         # bash: eval "..."
    re.IGNORECASE
)


def sanitize_llm_output(text: str) -> str:
    """Remove lines containing dynamic code execution primitives from LLM output."""
    if not text:
        return text
    sanitized_lines = []
    for line in text.splitlines(keepends=True):
        if (
            _DANGEROUS_PATTERNS.search(line)
            or _DANGEROUS_SHELL_PATTERNS.search(line)
            or _DANGEROUS_BASH_PATTERNS.search(line)
        ):
            # Skip this line — it contains a dangerous primitive
            continue
        sanitized_lines.append(line)
    return "".join(sanitized_lines)


@cl.on_chat_start
async def on_chat_start():
    files = None

    # Wait for the user to upload a file
    while files is None:
        files = await cl.AskFileMessage(
            content="Please upload a text .txt file to begin!",
            accept=["text/plain"],
            max_size_mb=20,
            timeout=180,
        ).send()

    file = files[0]

    msg = cl.Message(content=f"Processing `{file.name}`...")
    await msg.send()

    with open(file.path, "r", encoding="utf-8") as f:
        text = f.read()

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=file.name, delete=False
    ) as temp_file:
        temp_file.write(text)
        temp_file.flush()
        temp_file_path = temp_file.name

    llm_config = LLMEndpointConfig(model="gpt-4o-mini")
    llm = LLMEndpoint.from_config(llm_config)
    brain = Brain.from_files(name="user_brain", file_paths=[temp_file_path], llm=llm)

    # Store the file path in the session
    cl.user_session.set("file_path", temp_file_path)

    # Let the user know that the system is ready
    msg.content = f"Processing `{file.name}` done. You can now ask questions!"
    await msg.update()

    cl.user_session.set("brain", brain)


@cl.on_message
async def main(message: cl.Message):

    task_list = cl.TaskList(name="State")
    task_list.status = "Running..."

    think = cl.Task(title="Thinking", status=cl.TaskStatus.RUNNING)
    await task_list.add_task(think)

    tts = cl.Task(title="Text to speech")
    await task_list.add_task(tts)

    await task_list.send()

    brain = cl.user_session.get("brain")  # type: Brain
    path_config = "basic_rag_workflow.yaml"
    retrieval_config = RetrievalConfig.from_yaml(path_config)

    if brain is None:
        await cl.Message(content="Please upload a file first.").send()
        return

    # Prepare the message for streaming
    msg = cl.Message(content="", elements=[], author="Quivr", type="assistant_message")
    await msg.send()

    saved_sources = set()
    saved_sources_complete = []
    elements = []

    # Use the ask_stream method for streaming responses
    safe_message_content = remove_leetspeak(message.content)
    async for chunk in brain.ask_streaming(safe_message_content, retrieval_config=retrieval_config):
        safe_answer = sanitize_llm_output(chunk.answer)
        await msg.stream_token(safe_answer)
        for source in chunk.metadata.sources:
            if source.page_content not in saved_sources:
                safe_page_content = remove_leetspeak(source.page_content)
                saved_sources.add(safe_page_content)
                saved_sources_complete.append(source)
                print(source)
                elements.append(cl.Text(name=source.metadata["original_file_name"], content=safe_page_content, display="side"))
    
    think.status = cl.TaskStatus.DONE
    tts.status = cl.TaskStatus.RUNNING
    await task_list.update()
    
    safe_msg_content = sanitize_llm_output(msg.content)
    audio_file = await text_to_speech(safe_msg_content)
    elements.append(cl.Audio(content=audio_file, auto_play=True, mime="audio/mpeg"))

    sources = ""
    for source in saved_sources_complete:
        sources += f"- {source.metadata['original_file_name']}\n"
    msg.elements = elements
    msg.content = msg.content + f"\n\nSources:\n{sources}"
    await msg.update()

    tts.status = cl.TaskStatus.DONE
    task_list.status = "Done"
    await task_list.update()
    await cl.sleep(1)
    await task_list.remove()

async_openai_client = AsyncOpenAI(api_key=os.environ.get("OPENAI_API_KEY"))

@cl.step(type="tool", name="Speech to text")
async def speech_to_text(audio_file):
    # GPAI model: whisper-1 — model card: MODEL_CARD_URL (https://openai.com/research/whisper)
    response = await async_openai_client.audio.transcriptions.create(
        model="whisper-1", file=audio_file
    )

    return sanitize_llm_output(response.text)

@cl.step(type="tool", name="Text to speech")
async def text_to_speech(text):
    _tts_request_id = str(uuid.uuid4())
    _tts_model = "tts-1"
    _tts_input_len = len(text) if text else 0
    logger.info(
        "LLM request",
        extra={
            "operation": "audio.speech.create",
            "model": _tts_model,
            "request_id": _tts_request_id,
            "input_length": _tts_input_len,
        },
    )
    _tts_start = time.monotonic()
    _tts_error = None
    try:
        response = await async_openai_client.audio.speech.create(
            model=_tts_model, voice="alloy", input=text
        )
    except Exception as _e:
        _tts_error = type(_e).__name__
        raise
    finally:
        logger.info(
            "LLM result",
            extra={
                "operation": "audio.speech.create",
                "model": _tts_model,
                "request_id": _tts_request_id,
                "duration_seconds": round(time.monotonic() - _tts_start, 3),
                "output_length": len(response.content) if not _tts_error else 0,
                "status": _tts_error if _tts_error else "success",
            },
        )

    return response.content


@cl.on_audio_chunk
async def on_audio_chunk(chunk: cl.AudioChunk):
    if chunk.isStart:
        buffer = BytesIO()
        # This is required for whisper to recognize the file type
        buffer.name = f"input_audio.{chunk.mimeType.split('/')[1]}"
        # Initialize the session for a new audio stream
        cl.user_session.set("audio_buffer", buffer)
        cl.user_session.set("audio_mime_type", chunk.mimeType)

    # Write the chunks to a buffer and transcribe the whole audio at the end
    cl.user_session.get("audio_buffer").write(chunk.data)


@cl.on_audio_end
async def on_audio_end(elements: list[Element]):
    # Get the audio buffer from the session
    task_list = cl.TaskList(name="State")
    task_list.status = "Running..."

    stt = cl.Task(title="Speech to text", status=cl.TaskStatus.RUNNING)
    await task_list.add_task(stt)

    await task_list.send()

    audio_buffer: BytesIO = cl.user_session.get("audio_buffer")
    audio_buffer.seek(0)  # Move the file pointer to the beginning
    audio_file = audio_buffer.read()
    audio_mime_type: str = cl.user_session.get("audio_mime_type")

    input_audio_el = cl.Audio(
        mime=audio_mime_type, content=audio_file, name=audio_buffer.name
    )
    await cl.Message(
        author="You",
        type="user_message",
        content="",
        elements=[input_audio_el, *elements],
    ).send()

    whisper_input = (audio_buffer.name, audio_file, audio_mime_type)
    transcription = await speech_to_text(whisper_input)
    transcription = remove_leetspeak(transcription)

    msg = cl.Message(author="You", content=transcription, elements=elements)

    stt.status = cl.TaskStatus.DONE
    task_list.status = "Done"
    await task_list.update()
    await cl.sleep(1)
    await task_list.remove()

    await main(message=msg)