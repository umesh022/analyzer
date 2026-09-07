"""
Analysis Router
Runs the blocking pipeline in a thread pool executor to avoid blocking
the async event loop and hitting Render's 30-second timeout.
Also provides a streaming SSE endpoint for progressive result delivery.
"""

import json
import logging
import asyncio
from concurrent.futures import ThreadPoolExecutor
from fastapi import APIRouter, UploadFile, File, Form, HTTPException
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/analysis", tags=["analysis"])

# Thread pool for CPU/blocking work (regex parsing, LLM calls via sync Groq SDK)
_executor = ThreadPoolExecutor(max_workers=4)


class LogTextRequest(BaseModel):
    log_text: str
    full_rca: bool = True


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post("/upload")
async def upload_and_analyze(
    file: UploadFile = File(...),
    full_rca: bool = Form(default=True),
):
    """Upload a log file or PCAP/PCAPNG — runs pipeline in thread pool."""
    content = await file.read()
    if len(content) > 20 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File too large (max 20 MB)")
    filename = file.filename or "upload"
    log_text = await _decode_upload(content, filename)
    return await _run_analysis_async(log_text, full_rca, filename=filename)


@router.post("/text")
async def analyze_text(request: LogTextRequest):
    """Analyze pasted log text — runs pipeline in thread pool."""
    if not request.log_text.strip():
        raise HTTPException(status_code=400, detail="log_text cannot be empty")
    return await _run_analysis_async(request.log_text, request.full_rca)


@router.post("/quick")
async def quick_parse(request: LogTextRequest):
    """Fast parse-only — no LLM RCA. Still runs in thread pool."""
    if not request.log_text.strip():
        raise HTTPException(status_code=400, detail="log_text cannot be empty")
    try:
        loop   = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            _executor, _sync_quick_summary, request.log_text
        )
        return JSONResponse(content=result)
    except Exception as e:
        logger.exception("Quick parse failed")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/stream")
async def analyze_stream(request: LogTextRequest):
    """
    SSE streaming endpoint — sends progressive status updates then the
    full result. Prevents Render 30s timeout by sending heartbeat tokens
    while the pipeline runs.
    """
    if not request.log_text.strip():
        raise HTTPException(status_code=400, detail="log_text cannot be empty")

    log_text = request.log_text
    full_rca = request.full_rca

    async def event_gen():
        # Immediately send a heartbeat so Render doesn't close the connection
        yield _sse({"status": "started", "message": "Parsing log..."})

        loop = asyncio.get_event_loop()

        # Step 1 — quick parse in thread pool (fast, no LLM)
        try:
            quick = await loop.run_in_executor(
                _executor, _sync_quick_summary, log_text
            )
            yield _sse({"status": "parsed",
                        "failures_found": len(quick.get("failures", [])),
                        "layers": quick.get("layers_found", []),
                        "message": f"Found {len(quick.get('failures', []))} failure points. Generating RCA..."})
        except Exception as e:
            yield _sse({"status": "error", "message": str(e)})
            return

        if not full_rca:
            quick["filename"] = "input"
            yield _sse({"status": "done", "result": quick})
            return

        # Step 2 — full RCA in thread pool (slow, LLM calls)
        yield _sse({"status": "rca_start",
                    "message": "Running LLM analysis (this may take 20-40s)..."})
        try:
            result = await loop.run_in_executor(
                _executor, _sync_full_pipeline, log_text
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


# ── Sync workers (run inside thread pool) ─────────────────────────────────────

def _sync_full_pipeline(log_text: str) -> dict:
    from app.services.analysis_pipeline import get_pipeline
    return get_pipeline().run(log_text)


def _sync_quick_summary(log_text: str) -> dict:
    from app.services.analysis_pipeline import get_pipeline
    return get_pipeline().get_quick_summary(log_text)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _sse(payload: dict) -> str:
    return f"data: {json.dumps(payload)}\n\n"


async def _decode_upload(content: bytes, filename: str) -> str:
    fname_lower = filename.lower()
    is_pcap_ext = fname_lower.endswith(".pcap") or fname_lower.endswith(".pcapng")
    from app.parsers.pcap_parser import is_pcap, parse_pcap
    if is_pcap_ext or is_pcap(content):
        logger.info(f"PCAP: {filename} ({len(content)} bytes)")
        try:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(_executor,
                                              parse_pcap, content)
        except Exception as e:
            raise HTTPException(status_code=422, detail=f"PCAP parse error: {e}")
    try:
        return content.decode("utf-8", errors="replace")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Could not read file: {e}")


async def _run_analysis_async(log_text: str, full_rca: bool,
                               filename: str = "input") -> JSONResponse:
    """Run the pipeline in a thread pool and return a JSONResponse."""
    try:
        loop = asyncio.get_event_loop()
        fn   = _sync_full_pipeline if full_rca else _sync_quick_summary
        result = await loop.run_in_executor(_executor, fn, log_text)
        result["filename"] = filename
        return JSONResponse(content=result)
    except Exception as e:
        logger.exception("Analysis pipeline failed")
        raise HTTPException(status_code=500, detail=str(e))
