# Copyright (c) Lineaje, Inc. All rights reserved.
# gr_check() POSTs to GR_SERVICE_URL+/enforce; fail-open unless GRBlockedError.
class GRBlockedError(Exception):
    def __init__(self, policy_id, reason):
        self.policy_id, self.reason = policy_id, reason
        super().__init__("Guardrail block for policy %r: %s" % (policy_id, reason))

def gr_check(data, source_type, destination_type, tenant_id="", timeout=5.0, **context):
    import json as _j, logging as _lg, os as _os, urllib.error as _ue, urllib.request as _ur
    _log = _lg.getLogger("lineaje.gr_client")
    url = _os.environ.get("GR_SERVICE_URL", "")
    if not url:
        return data
    tid = tenant_id or _os.environ.get("GR_TENANT_ID", "")
    bearer = _os.environ.get("GR_BEARER_TOKEN") or _os.environ.get("LINEAJE_PAT_TOKEN") or _os.environ.get("LINEAJE_PAT", "")
    hop_label = source_type + "->" + destination_type
    params_key = "out_params" if destination_type == "agent" else "in_params"
    try:
        headers = {"Content-Type": "application/json"}
        if bearer:
            headers["Authorization"] = "Bearer " + bearer
        body = {"source_type": source_type, "destination_type": destination_type, params_key: {"data": data}}
        for _k, _v in context.items():
            if _v:
                body[_k] = _v
        if tid:
            body["tenant_id"] = tid
        req = _ur.Request(url.rstrip("/") + "/enforce", data=_j.dumps(body).encode(), headers=headers, method="POST")
        with _ur.urlopen(req, timeout=timeout) as resp:
            result = _j.loads(resp.read())
    except Exception as exc:
        if isinstance(exc, _ue.HTTPError) and exc.code == 403:
            try: detail = _j.loads(exc.read()).get("detail", {})
            except Exception: detail = {}
            blocked_by = detail.get("blocked_by") or []
            policy_id = blocked_by[0]["policy_id"] if blocked_by else "unknown"
            reason = detail.get("message", "Request denied by policy enforcement.")
            _log.warning("gr_client[%s]: BLOCKED by policy=%s — %s", hop_label, policy_id, reason)
            if _os.environ.get("GR_BLOCK_MODE", "enforce").lower() == "audit":
                return data
            raise GRBlockedError(policy_id, reason)
        _log.warning("gr_client[%s]: GR service call failed (%s) — failing open", hop_label, exc)
        return data
    if result.get("status") == "escalate":
        _log.warning("gr_client[%s]: escalation flagged — passing through for human review", hop_label)
    return result.get("result", {}).get("data", data)
from flask import Flask, render_template, request, jsonify, session
import openai
import base64
import os
import requests
from dotenv import load_dotenv
from quivr_core import Brain
from quivr_core.rag.entities.config import RetrievalConfig
from tempfile import NamedTemporaryFile
from werkzeug.utils import secure_filename
from asyncio import to_thread
import asyncio


UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"txt"}

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.secret_key = "secret"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["CACHE_TYPE"] = "SimpleCache"  # In-memory cache for development
app.config["CACHE_DEFAULT_TIMEOUT"] = 60 * 60  # 1 hour cache timeout
load_dotenv()

openai.api_key = os.getenv("OPENAI_API_KEY")

brains = {}


@app.route("/")
def index():
    _lineaje_payload = "index.html"
    try:
        _lineaje_payload = gr_check(_lineaje_payload, "tool", "user_interface", site_id='site:sha256:18bf20fc401de42f1a26ebc99253024d153cb0334ae5b1d4c904de9da96da05b')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        _lineaje_payload = _lineaje_payload
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'tool->user_interface' — passing data through unchecked")
    return render_template("index.html")


def run_in_event_loop(func, *args, **kwargs):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    if asyncio.iscoroutinefunction(func):
        result = loop.run_until_complete(func(*args, **kwargs))
    else:
        result = func(*args, **kwargs)
    loop.close()
    try:
        result = gr_check(result, "agent", "user_interface", site_id='site:sha256:ffcbc0cc7116dfd3069669ce4b02abc06e13efebed2eef28bb263a3fa6709777')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        result = result
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
    return result


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/upload", methods=["POST"])
async def upload_file():
    if "file" not in request.files:
        return "No file part", 400

    file = request.files["file"]

    if file.filename == "":
        return "No selected file", 400
    if not (file and file.filename and allowed_file(file.filename)):
        return "Invalid file type", 400

    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    file.save(filepath)

    _lineaje_payload = f"File uploaded and saved at: {filepath}"
    try:
        import asyncio as _gr_asyncio
        _lineaje_payload = await _gr_asyncio.to_thread(gr_check, _lineaje_payload, "agent", "log", site_id='site:sha256:e4b5b8f0a47e56169b0697dc231075350ebd17cad0545da6936da16622911761')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        _lineaje_payload = _lineaje_payload
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
    print(f"File uploaded and saved at: {filepath}")

    _lineaje_payload = "Creating brain instance..."
    try:
        import asyncio as _gr_asyncio
        _lineaje_payload = await _gr_asyncio.to_thread(gr_check, _lineaje_payload, "agent", "log", site_id='site:sha256:e4b5b8f0a47e56169b0697dc231075350ebd17cad0545da6936da16622911761')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        _lineaje_payload = _lineaje_payload
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
    print("Creating brain instance...")

    brain: Brain = await to_thread(
        run_in_event_loop, Brain.from_files, name="user_brain", file_paths=[filepath]
    )

    # Store brain instance in cache
    session_id = session.sid if hasattr(session, "sid") else os.urandom(16).hex()
    session["session_id"] = session_id
    # cache.set(session_id, brain)  # Store the brain instance in the cache
    brains[session_id] = brain
    _lineaje_payload = f"Brain instance created and stored in cache for session ID: {session_id}"
    try:
        import asyncio as _gr_asyncio
        _lineaje_payload = await _gr_asyncio.to_thread(gr_check, _lineaje_payload, "agent", "log", site_id='site:sha256:e4b5b8f0a47e56169b0697dc231075350ebd17cad0545da6936da16622911761')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        _lineaje_payload = _lineaje_payload
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
    print(f"Brain instance created and stored in cache for session ID: {session_id}")

    _lineaje_payload = {"message": "Brain created successfully"}
    try:
        import asyncio as _gr_asyncio
        _lineaje_payload = await _gr_asyncio.to_thread(gr_check, _lineaje_payload, "agent", "user_interface", site_id='site:sha256:7467efaf379c851ac52761b8eb98d9f5f8f584782411e28625360ea59f1917ad')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        _lineaje_payload = _lineaje_payload
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
    return jsonify({"message": "Brain created successfully"})


@app.route("/ask", methods=["POST"])
async def ask():
    if "audio_data" not in request.files:
        return "Missing audio data", 400

    # Retrieve the brain instance from the cache using the session ID
    session_id = session.get("session_id")
    if not session_id:
        return "Session ID not found. Upload a file first.", 400

    brain = brains.get(session_id)
    if not brain:
        return "Brain instance not found in dict. Upload a file first.", 400

    _lineaje_payload = "Brain instance loaded from cache."
    try:
        import asyncio as _gr_asyncio
        _lineaje_payload = await _gr_asyncio.to_thread(gr_check, _lineaje_payload, "agent", "log", site_id='site:sha256:e4b5b8f0a47e56169b0697dc231075350ebd17cad0545da6936da16622911761')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        _lineaje_payload = _lineaje_payload
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
    print("Brain instance loaded from cache.")

    _lineaje_payload = "Speech to text..."
    try:
        import asyncio as _gr_asyncio
        _lineaje_payload = await _gr_asyncio.to_thread(gr_check, _lineaje_payload, "agent", "log", site_id='site:sha256:e4b5b8f0a47e56169b0697dc231075350ebd17cad0545da6936da16622911761')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        _lineaje_payload = _lineaje_payload
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
    print("Speech to text...")
    audio_file = request.files["audio_data"]
    transcript = transcribe_audio_file(audio_file)
    try:
        import asyncio as _gr_asyncio
        transcript = await _gr_asyncio.to_thread(gr_check, transcript, "agent", "log", site_id='site:sha256:e4b5b8f0a47e56169b0697dc231075350ebd17cad0545da6936da16622911761')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        transcript = transcript
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
    print("Transcript result: ", transcript)

    _lineaje_payload = "Getting response..."
    try:
        import asyncio as _gr_asyncio
        _lineaje_payload = await _gr_asyncio.to_thread(gr_check, _lineaje_payload, "agent", "log", site_id='site:sha256:e4b5b8f0a47e56169b0697dc231075350ebd17cad0545da6936da16622911761')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        _lineaje_payload = _lineaje_payload
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
    print("Getting response...")
    quivr_response = await to_thread(run_in_event_loop, brain.ask, transcript)

    _lineaje_payload = "Text to speech..."
    try:
        import asyncio as _gr_asyncio
        _lineaje_payload = await _gr_asyncio.to_thread(gr_check, _lineaje_payload, "agent", "log", site_id='site:sha256:e4b5b8f0a47e56169b0697dc231075350ebd17cad0545da6936da16622911761')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        _lineaje_payload = _lineaje_payload
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
    print("Text to speech...")
    audio_base64 = synthesize_speech(quivr_response.answer)

    _lineaje_payload = "Done"
    try:
        import asyncio as _gr_asyncio
        _lineaje_payload = await _gr_asyncio.to_thread(gr_check, _lineaje_payload, "agent", "log", site_id='site:sha256:e4b5b8f0a47e56169b0697dc231075350ebd17cad0545da6936da16622911761')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        _lineaje_payload = _lineaje_payload
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
    print("Done")
    _lineaje_payload = {"audio_base64": audio_base64}
    try:
        import asyncio as _gr_asyncio
        _lineaje_payload = await _gr_asyncio.to_thread(gr_check, _lineaje_payload, "agent", "user_interface", site_id='site:sha256:7467efaf379c851ac52761b8eb98d9f5f8f584782411e28625360ea59f1917ad')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        _lineaje_payload = _lineaje_payload
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
    return jsonify({"audio_base64": audio_base64})


def transcribe_audio_file(audio_file):
    with NamedTemporaryFile(suffix=".webm", delete=False) as temp_audio_file:
        audio_file.save(temp_audio_file)
        temp_audio_file_path = temp_audio_file.name

    try:
        with open(temp_audio_file_path, "rb") as f:
            transcript_response = openai.audio.transcriptions.create(
                model="whisper-1", file=f
            )
        transcript = transcript_response.text
    finally:
        try:
            temp_audio_file_path = gr_check(temp_audio_file_path, "agent", "system", site_id='site:sha256:0d83b71901cb8fa94db9955de9d711bd8f6cc102c4e0cc055fe2e4c7796575d2')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            temp_audio_file_path = temp_audio_file_path
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->system' — passing data through unchecked")
        os.unlink(temp_audio_file_path)

    try:
        transcript = gr_check(transcript, "agent", "user_interface", site_id='site:sha256:45d3f7815a6db56c52bfb948a2a4b8b25a763e9f475f49d8e92bd33bc52600b6')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        transcript = transcript
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
    return transcript


def synthesize_speech(text):
    speech_response = openai.audio.speech.create(
        model="tts-1", voice="nova", input=text
    )
    audio_content = speech_response.content
    try:
        audio_content = gr_check(audio_content, "llm", "agent", site_id='site:sha256:d151e4dec8781b7e44ba87e5d785df70851e5c3ea9447e43ea30412b4bc684ba')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        audio_content = audio_content
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'llm->agent' — passing data through unchecked")
    audio_base64 = base64.b64encode(audio_content).decode("utf-8")
    try:
        audio_base64 = gr_check(audio_base64, "agent", "user_interface", site_id='site:sha256:a9c6367d4a467e0baab232b2cad6d3af14b1edb1e01b63fe4f12c646492c79a2')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError": raise
        audio_base64 = audio_base64
        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked")
    return audio_base64


if __name__ == "__main__":
    app.run(debug=True)
