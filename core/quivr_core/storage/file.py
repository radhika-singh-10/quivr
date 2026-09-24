# Copyright (c) Lineaje, Inc. All rights reserved.
# gr_check() POSTs to GR_SERVICE_URL+/enforce; fail-open unless GRBlockedError.
class GRBlockedError(Exception):
    def __init__(self, policy_id, reason):
        self.policy_id, self.reason = policy_id, reason
        super().__init__("Guardrail block for policy %r: %s" % (policy_id, reason))

def gr_check(data, source_type, destination_type, tenant_id="", timeout=5.0, **context):
    import json as _j, logging as _lg, os as _os, urllib.error as _ue, urllib.request as _ur
    _log = _lg.getLogger("lineaje.gr_client")
    hop_label = source_type + "->" + destination_type
    _prior = getattr(gr_check, "_blocked", None)
    if _prior:
        _log.warning("gr_client[%s]: skipping POST /enforce — request already blocked (%s)", hop_label, _prior[1])
        raise GRBlockedError(_prior[0], _prior[1])
    def _blk(o):
        if isinstance(o, dict):
            return any(_blk(o.get(k)) for k in ("skill_path", "skill_file", "path", "file_path", "data", "skill_manifest_path"))
        s = str(o or "")
        b = s.replace("\\", "/").rsplit("/", 1)[-1].lower()
        if b.endswith(".md.blocked"): return True
        try:
            if b in ("skill.md", "skills.md") and _os.path.isfile(str(o) + ".blocked"): return True
        except Exception:
            pass
        return False
    if _blk(data) or _blk(context):
        _log.warning("gr_client[%s]: quarantined skill (*.blocked) — not loaded, GR not called", hop_label)
        gr_check._blocked = ("blocked_manifest", "quarantined skill must not be read, downloaded, or loaded")
        raise GRBlockedError("blocked_manifest", "quarantined skill must not be read, downloaded, or loaded")
    url = _os.environ.get("GR_SERVICE_URL", "")
    if not url:
        return data
    tid = tenant_id or _os.environ.get("GR_TENANT_ID", "")
    # Refresh token first: the GR service exchanges it for the access JWT it
    # calls the Data Service policy API with; a lineaje_pat_ PAT only
    # identifies the caller and cannot be exchanged.
    bearer = _os.environ.get("GR_BEARER_TOKEN") or _os.environ.get("LINEAJE_REFRESH_TOKEN") or _os.environ.get("LINEAJE_PAT_TOKEN") or _os.environ.get("LINEAJE_PAT", "")
    params_key = "out_params" if destination_type == "agent" else "in_params"
    def _gr_js(o):
        # JSON form of non-JSON payloads (LangChain Document, pydantic models, ...).
        if hasattr(o, "page_content"):
            return {"page_content": o.page_content, "metadata": getattr(o, "metadata", None) or {}}
        for _m in ("model_dump", "dict", "to_dict"):
            _f = getattr(o, _m, None)
            if callable(_f):
                try:
                    return _f()
                except Exception:
                    pass
        if isinstance(o, (set, tuple)):
            return list(o)
        return str(o)
    def _gr_back(orig, new):
        # Map the (possibly masked) JSON back onto the caller's own objects.
        if new == _j.loads(_j.dumps(orig, default=_gr_js)):
            return orig
        if isinstance(orig, (list, tuple)) and isinstance(new, list) and len(orig) == len(new):
            _out = [_gr_back(a, b) for a, b in zip(orig, new)]
            return tuple(_out) if isinstance(orig, tuple) else _out
        if hasattr(orig, "page_content") and isinstance(new, dict) and "page_content" in new:
            import copy as _cp
            _c = _cp.copy(orig)
            _c.page_content = new["page_content"]
            if isinstance(new.get("metadata"), dict) and hasattr(_c, "metadata"):
                _c.metadata = new["metadata"]
            return _c
        if orig is None or isinstance(orig, (str, int, float, bool, dict, list)):
            return new
        _log.warning("gr_client[%s]: masked result cannot be applied to %s — returning original", hop_label, type(orig).__name__)
        return orig
    try:
        headers = {"Content-Type": "application/json"}
        if bearer:
            headers["Authorization"] = "Bearer " + bearer
        _sent = _j.loads(_j.dumps(data, default=_gr_js))
        body = {"source_type": source_type, "destination_type": destination_type, params_key: {"data": _sent}}
        for _k, _v in context.items():
            if _v:
                body[_k] = _v
        if tid:
            body["tenant_id"] = tid
        _base = url.rstrip("/")
        if _base.lower().endswith("/enforce"): _base = _base[: -len("/enforce")].rstrip("/")
        req = _ur.Request(_base + "/enforce", data=_j.dumps(body, default=_gr_js).encode(), headers=headers, method="POST")
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
            gr_check._blocked = (policy_id, reason)
            raise GRBlockedError(policy_id, reason)
        _log.warning("gr_client[%s]: GR service call failed (%s) — failing open", hop_label, exc)
        return data
    if result.get("status") == "escalate":
        _log.warning("gr_client[%s]: escalation flagged — passing through for human review", hop_label)
    if not isinstance(result.get("result"), dict) or "data" not in result["result"]:
        return data
    return _gr_back(data, result["result"]["data"])
import hashlib
import mimetypes
import os
import warnings
from contextlib import asynccontextmanager
from enum import Enum
from pathlib import Path
from typing import Any, AsyncGenerator, AsyncIterable
from uuid import UUID, uuid4

import aiofiles


class FileExtension(str, Enum):
    txt = ".txt"
    pdf = ".pdf"
    docx = ".docx"


def get_file_extension(file_path: Path) -> FileExtension | str:
    try:
        mime_type, _ = mimetypes.guess_type(file_path.name)
        if mime_type:
            mime_ext = mimetypes.guess_extension(mime_type)
            if mime_ext:
                return FileExtension(mime_ext)
        return FileExtension(file_path.suffix)
    except ValueError:
        warnings.warn(
            f"File {file_path.name} extension isn't recognized. Make sure you have registered a parser for {file_path.suffix}",
            stacklevel=2,
        )
        return file_path.suffix


async def load_qfile(brain_id: UUID, path: str | Path):
    if not isinstance(path, Path):
        path = Path(path)

    if not path.exists():
        raise FileExistsError(f"file {path} doesn't exist")

    file_size = os.stat(path).st_size

    async with aiofiles.open(path, mode="rb") as f:
        try:
            import asyncio as _gr_asyncio
            f = await _gr_asyncio.to_thread(gr_check, f, "file_storage", "agent", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_076', 'AI_APP_SEC_078', 'AI_APP_SEC_079', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_DAT_SEC_039', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_027', 'AI_VULN_SEC_002', 'AI_VULN_SEC_005', 'AI_VULN_SEC_006', 'AI_VULN_SEC_007'], site_id='site:sha256:8ed9c602e795496b8e5a7903680130a5bcbceb0cece8a54563a642c7f03a88c4')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            f = f
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'file_storage->agent' — passing data through unchecked")
        file_sha1 = hashlib.sha1(await f.read()).hexdigest()

    try:
        # NOTE: when loading from existing storage, file name will be uuid
        id = UUID(path.name)
    except ValueError:
        id = uuid4()

    return QuivrFile(
        id=id,
        brain_id=brain_id,
        path=path,
        original_filename=path.name,
        file_extension=get_file_extension(path),
        file_size=file_size,
        file_sha1=file_sha1,
    )


class QuivrFile:
    __slots__ = [
        "id",
        "brain_id",
        "path",
        "original_filename",
        "file_size",
        "file_extension",
        "file_sha1",
    ]

    def __init__(
        self,
        id: UUID,
        original_filename: str,
        path: Path,
        brain_id: UUID,
        file_sha1: str,
        file_extension: FileExtension | str,
        file_size: int | None = None,
    ) -> None:
        self.id = id
        self.brain_id = brain_id
        self.path = path
        self.original_filename = original_filename
        self.file_size = file_size
        self.file_extension = file_extension
        self.file_sha1 = file_sha1

    @asynccontextmanager
    async def open(self) -> AsyncGenerator[AsyncIterable[bytes], None]:
        # TODO(@aminediro) : match on path type
        f = await aiofiles.open(self.path, mode="rb")
        try:
            import asyncio as _gr_asyncio
            f = await _gr_asyncio.to_thread(gr_check, f, "file_storage", "agent", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_070', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_076', 'AI_APP_SEC_078', 'AI_APP_SEC_079', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_DAT_SEC_039', 'AI_IAC_002', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_027', 'AI_VULN_SEC_002', 'AI_VULN_SEC_005', 'AI_VULN_SEC_006', 'AI_VULN_SEC_007'], site_id='site:sha256:a0981e69d2f31936333289aa3433ba710153de1b8ebb4c61943617f7775da1bb')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError": raise
            f = f
            __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'file_storage->agent' — passing data through unchecked")
        try:
            yield f
        finally:
            await f.close()

    @property
    def metadata(self) -> dict[str, Any]:
        return {
            "qfile_id": self.id,
            "qfile_path": self.path,
            "original_file_name": self.original_filename,
            "file_md4": self.file_sha1,
            "file_size": self.file_size,
        }
