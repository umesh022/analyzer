"""
Analysis Router
FastAPI routes for log upload and analysis.
Supports plain-text logs AND binary PCAP/PCAPNG files.
"""

import logging
from fastapi import APIRouter, UploadFile, File, Form, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/analysis", tags=["analysis"])


class LogTextRequest(BaseModel):
    log_text: str
    full_rca: bool = True


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post("/upload")
async def upload_and_analyze(
    file: UploadFile = File(...),
    full_rca: bool = Form(default=True),
):
    """
    Upload a log file or PCAP/PCAPNG and run full analysis pipeline.
    Accepts: .log .txt .csv .pcap .pcapng (up to 20 MB)
    """
    content = await file.read()
    if len(content) > 20 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File too large (max 20 MB)")

    filename = file.filename or "upload"
    log_text = await _decode_upload(content, filename)
    return await _run_analysis(log_text, full_rca, filename=filename)


@router.post("/text")
async def analyze_text(request: LogTextRequest):
    """Analyze raw log text submitted as JSON."""
    if not request.log_text.strip():
        raise HTTPException(status_code=400, detail="log_text cannot be empty")
    return await _run_analysis(request.log_text, request.full_rca)


@router.post("/quick")
async def quick_parse(request: LogTextRequest):
    """Fast parse-only — returns failures without LLM RCA (no Groq call)."""
    try:
        from app.services.analysis_pipeline import get_pipeline
        result = get_pipeline().get_quick_summary(request.log_text)
        return JSONResponse(content=result)
    except Exception as e:
        logger.exception("Quick parse failed")
        raise HTTPException(status_code=500, detail=str(e))


# ── Helpers ───────────────────────────────────────────────────────────────────

async def _decode_upload(content: bytes, filename: str) -> str:
    """
    Determine file type and return a plain-text log string.
    PCAP/PCAPNG → parsed via pcap_parser → text log.
    Everything else → UTF-8 decode.
    """
    fname_lower = filename.lower()
    is_pcap_ext = fname_lower.endswith(".pcap") or fname_lower.endswith(".pcapng")

    # Also detect by magic bytes even if extension is wrong
    from app.parsers.pcap_parser import is_pcap, parse_pcap
    if is_pcap_ext or is_pcap(content):
        logger.info(f"PCAP file detected: {filename} ({len(content)} bytes)")
        try:
            log_text = parse_pcap(content)
            logger.info(f"PCAP parsed: {log_text.count(chr(10))} lines extracted")
            return log_text
        except Exception as e:
            logger.error(f"PCAP parse failed: {e}")
            raise HTTPException(status_code=422,
                                detail=f"PCAP parse error: {e}")

    # Plain text
    try:
        return content.decode("utf-8", errors="replace")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Could not read file: {e}")


async def _run_analysis(log_text: str, full_rca: bool,
                        filename: str = "input") -> JSONResponse:
    try:
        from app.services.analysis_pipeline import get_pipeline
        pipeline = get_pipeline()
        result = pipeline.run(log_text) if full_rca else pipeline.get_quick_summary(log_text)
        result["filename"] = filename
        return JSONResponse(content=result)
    except Exception as e:
        logger.exception("Analysis pipeline failed")
        raise HTTPException(status_code=500, detail=str(e))
