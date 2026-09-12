"""
Analysis Router
Runs the blocking pipeline in a thread pool executor to avoid blocking
the async event loop and hitting Render's 30-second timeout.
Accepts optional cot_template_id to guide analysis with a CoT template.
"""

import json
import logging
import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import Optional
from fastapi import APIRouter, UploadFile, File, Form, HTTPException
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/analysis", tags=["analysis"])

_executor = ThreadPoolExecutor(max_workers=4)


class LogTextRequest(BaseModel):
    log_text: str
    full_rca: bool = True
    cot_template_id: Optional[str] = None   # ← CoT template to apply


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post("/upload")
async def upload_and_analyze(
    file: UploadFile = File(...),
    full_rca: bool = Form(default=True),
    cot_template_id: Optional[str] = Form(default=None),
):
    content = await file.read()
    if len(content) > 20 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File too large (max 20 MB)")
    filename = file.filename or "upload"
    log_text = await _decode_upload(content, filename)
    return await _run_analysis_async(log_text, full_rca,
                                     filename=filename,
                                     cot_template_id=cot_template_id)


@router.post("/text")
async def analyze_text(request: LogTextRequest):
    if not request.log_text.strip():
        raise HTTPException(status_code=400, detail="log_text cannot be empty")
    return await _run_analysis_async(request.log_text, request.full_rca,
                                     cot_template_id=request.cot_template_id)


@router.post("/quick")
async def quick_parse(request: LogTextRequest):
    if not request.log_text.strip():
        raise HTTPException(status_code=400, detail="log_text cannot be empty")
    try:
        loop   = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            _executor,
            lambda: _sync_quick_summary(request.log_text, request.cot_template_id)
        )
        return JSONResponse(content=result)
    except Exception as e:
        logger.exception("Quick parse failed")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/stream")
async def analyze_stream(request: LogTextRequest):
    """SSE streaming — sends heartbeats while pipeline runs."""
    if not request.log_text.strip():
        raise HTTPException(status_code=400, detail="log_text cannot be empty")

    log_text        = request.log_text
    full_rca        = request.full_rca
    cot_template_id = request.cot_template_id

    async def event_gen():
        yield _sse({"status": "started",
                    "message": "Parsing log...",
                    "cot_active": bool(cot_template_id)})

        loop = asyncio.get_event_loop()

        # Quick parse first (fast)
        try:
            quick = await loop.run_in_executor(
                _executor,
                lambda: _sync_quick_summary(log_text, cot_template_id)
            )
            n = len(quick.get("failures", []))
            cot_msg = ""
            if quick.get("cot_template"):
                cot_msg = f" | CoT: {quick['cot_template']['name']}"
            yield _sse({"status": "parsed",
                        "failures_found": n,
                        "layers": quick.get("layers_found", []),
                        "cot_template": quick.get("cot_template"),
                        "message": f"Found {n} failure points.{cot_msg} Generating RCA..."})
        except Exception as e:
            yield _sse({"status": "error", "message": str(e)})
            return

        if not full_rca:
            quick["filename"] = "input"
            yield _sse({"status": "done", "result": quick})
            return

        cot_hint = f" with CoT '{quick['cot_template']['name']}'" \
                   if quick.get("cot_template") else ""
        yield _sse({"status": "rca_start",
                    "message": f"Running LLM RCA{cot_hint} (20-40s)..."})
        try:
            result = await loop.run_in_executor(
                _executor,
                lambda: _sync_full_pipeline(log_text, cot_template_id)
            )
            result["filename"] = "input"
            yield _sse({"status": "done", "result": result})
        except Exception as e:
            logger.exception("Stream pipeline failed")
            yield _sse({"status": "error", "message": str(e)})

    return StreamingResponse(
        event_gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── Sync workers ──────────────────────────────────────────────────────────────

def _sync_full_pipeline(log_text: str,
                        cot_template_id: Optional[str] = None) -> dict:
    from app.services.analysis_pipeline import get_pipeline
    return get_pipeline().run(log_text, cot_template_id=cot_template_id)


def _sync_quick_summary(log_text: str,
                        cot_template_id: Optional[str] = None) -> dict:
    from app.services.analysis_pipeline import get_pipeline
    return get_pipeline().get_quick_summary(log_text,
                                            cot_template_id=cot_template_id)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _sse(payload: dict) -> str:
    return f"data: {json.dumps(payload)}\n\n"


async def _decode_upload(content: bytes, filename: str) -> str:
    fname_lower = filename.lower()
    is_pcap_ext = fname_lower.endswith(".pcap") or fname_lower.endswith(".pcapng")
    from app.parsers.pcap_parser import is_pcap, parse_pcap
    if is_pcap_ext or is_pcap(content):
        try:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(_executor, parse_pcap, content)
        except Exception as e:
            raise HTTPException(status_code=422, detail=f"PCAP parse error: {e}")
    try:
        return content.decode("utf-8", errors="replace")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Could not read file: {e}")


async def _run_analysis_async(log_text: str, full_rca: bool,
                               filename: str = "input",
                               cot_template_id: Optional[str] = None) -> JSONResponse:
    try:
        loop = asyncio.get_event_loop()
        fn   = (lambda: _sync_full_pipeline(log_text, cot_template_id)) \
               if full_rca else \
               (lambda: _sync_quick_summary(log_text, cot_template_id))
        result = await loop.run_in_executor(_executor, fn)
        result["filename"] = filename
        return JSONResponse(content=result)
    except Exception as e:
        logger.exception("Analysis pipeline failed")
        raise HTTPException(status_code=500, detail=str(e))
