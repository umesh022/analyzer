"""
Chat Router
Strictly grounded to the uploaded log analysis.
Every request MUST carry analysis_context (the parsed result JSON).
If no log has been analyzed the assistant refuses to answer.
"""

import logging
import json
from typing import List, Optional
from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/chat", tags=["chat"])

# Sent back when user asks without uploading a log first
NO_LOG_MSG = (
    "⚠️ No log has been analyzed yet.\n\n"
    "Please upload or paste your log file on the left panel and click "
    "**Analyze Logs** first. I can only answer questions about your specific "
    "log data — I am not a general-purpose assistant."
)


class ChatMessage(BaseModel):
    role: str       # "user" | "assistant"
    content: str


class ChatRequest(BaseModel):
    messages: List[ChatMessage]
    analysis_context: Optional[str] = None   # JSON string of ParseResult
    log_snippet: Optional[str] = None         # first 3000 chars of the raw log
    use_rag: bool = True
    stream: bool = False


# ── Helpers ───────────────────────────────────────────────────────────────────

def _has_analysis(request: ChatRequest) -> bool:
    """
    Return True when a log has been submitted — regardless of whether
    any 3GPP failure patterns were matched.
    A log with 0 failures is still a valid, analyzable log.
    """
    # Raw log text was sent directly
    if request.log_snippet and request.log_snippet.strip():
        return True
    # Analysis result JSON was sent
    if not request.analysis_context:
        return False
    try:
        ctx = json.loads(request.analysis_context)
        # Accept any result that has parse_summary with at least 1 line
        summary = ctx.get("parse_summary", {})
        if summary.get("total_lines", 0) > 0:
            return True
        # Or has failures list (even empty)
        if "failures" in ctx:
            return True
        # Or has the raw filename (upload happened)
        if ctx.get("filename"):
            return True
        return False
    except Exception:
        return False


def _build_grounded_context(request: ChatRequest,
                             rag_context: str) -> str:
    """
    Assemble the full grounding context string injected into every system message.
    Contains: parsed failures, chain analysis, layers, raw log snippet, RAG spec refs.
    """
    parts: List[str] = []

    # ── Analysis result ───────────────────────────────────────────────────────
    if request.analysis_context:
        try:
            ctx = json.loads(request.analysis_context)

            # Summary line
            summary = ctx.get("parse_summary", {})
            total_failures = summary.get("total_failures", 0)
            parts.append(
                f"=== ANALYZED LOG SUMMARY ===\n"
                f"Total lines: {summary.get('total_lines', '?')}  |  "
                f"Failures found: {total_failures}  |  "
                f"Layers affected: {', '.join(ctx.get('layers_found', []))}"
            )

            # Note when 0 failures detected — log may still contain useful data
            if total_failures == 0:
                parts.append(
                    "NOTE: No 3GPP failure patterns were auto-detected in this log. "
                    "The raw log text is included below — answer the user's question "
                    "by reading the raw log directly."
                )

            # Failure list
            failures = ctx.get("failures", [])
            if failures:
                f_lines = ["", "DETECTED FAILURE POINTS:"]
                for i, f in enumerate(failures[:20], 1):
                    f_lines.append(
                        f"  {i}. [Line {f.get('line_number')}] [{f.get('layer')}] "
                        f"{f.get('failure_type')}  cause={f.get('cause','N/A')}  "
                        f"spec={f.get('spec_reference','N/A')}  sev={f.get('severity')}"
                    )
                parts.append("\n".join(f_lines))

            # Chain analysis
            chain = ctx.get("chain_analysis", {})
            if chain.get("chains"):
                c_lines = ["", "FAILURE CHAIN ANALYSIS:"]
                c_lines.append(f"  Root layer: {chain.get('root_layer','unknown')}")
                c_lines.append(f"  Affected layers: {', '.join(chain.get('affected_layers',[]))}")
                for c in chain["chains"]:
                    c_lines.append(f"  Chain: {c.get('chain')}")
                    c_lines.append(f"    → {c.get('description')}")
                    c_lines.append(f"    → Likely root: {c.get('likely_root')}")
                parts.append("\n".join(c_lines))

            # RCA report
            rca = ctx.get("rca_report", "")
            if rca:
                parts.append("\nRCA REPORT EXCERPT (first 1500 chars):\n" + rca[:1500])

        except Exception as e:
            logger.warning(f"Could not parse analysis_context: {e}")

    # ── Full raw log (up to 6000 chars so LLM can read any field) ────────────
    if request.log_snippet:
        parts.append(
            "\nFULL RAW LOG (up to 6000 chars — read this to answer any question "
            "about the log content):\n```\n"
            + request.log_snippet[:6000]
            + "\n```"
        )

    # ── 3GPP spec RAG ─────────────────────────────────────────────────────────
    if rag_context:
        parts.append("\n" + rag_context)

    return "\n".join(parts)


def _rag_query(last_user_msg: str) -> str:
    """Query the vector store with the user's message, return context string."""
    if not last_user_msg:
        return ""
    try:
        from app.rag.vector_store import get_vector_store
        store = get_vector_store()
        if not store.is_populated():
            return ""
        chunks = store.query(last_user_msg, n_results=3)
        if not chunks:
            return ""
        lines = ["RELEVANT 3GPP SPEC REFERENCES (from knowledge base):"]
        for c in chunks:
            lines.append(f"[{c['source']}]: {c['text'][:400]}")
        return "\n".join(lines)
    except Exception as e:
        logger.warning(f"RAG query failed: {e}")
        return ""


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post("/message")
async def chat_message(request: ChatRequest):
    """Non-streaming chat — strictly grounded to uploaded log."""
    if not _has_analysis(request):
        return {"response": NO_LOG_MSG, "rag_used": False}

    messages = [{"role": m.role, "content": m.content} for m in request.messages]
    last_user = next((m["content"] for m in reversed(messages) if m["role"] == "user"), "")

    rag_ctx   = _rag_query(last_user) if request.use_rag else ""
    grounded  = _build_grounded_context(request, rag_ctx)

    try:
        from app.services.groq_llm import get_llm_service
        response_text = await get_llm_service().chat(
            messages=messages,
            rag_context="",           # merged into grounded below
            analysis_context=grounded,
        )
        return {"response": response_text, "rag_used": bool(rag_ctx)}
    except Exception as e:
        logger.exception("Chat message failed")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/stream")
async def chat_stream(request: ChatRequest):
    """Streaming SSE chat — strictly grounded to uploaded log."""
    if not _has_analysis(request):
        async def _no_log():
            yield f"data: {json.dumps({'token': NO_LOG_MSG})}\n\n"
            yield "data: [DONE]\n\n"
        return StreamingResponse(_no_log(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache",
                                          "X-Accel-Buffering": "no"})

    messages = [{"role": m.role, "content": m.content} for m in request.messages]
    last_user = next((m["content"] for m in reversed(messages) if m["role"] == "user"), "")

    rag_ctx  = _rag_query(last_user) if request.use_rag else ""
    grounded = _build_grounded_context(request, rag_ctx)

    async def event_generator():
        try:
            from app.services.groq_llm import get_llm_service
            async for token in get_llm_service().stream_chat(
                messages=messages,
                rag_context="",
                analysis_context=grounded,
            ):
                yield f"data: {json.dumps({'token': token})}\n\n"
            yield "data: [DONE]\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'error': str(e)})}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get("/mcp-tools")
async def list_mcp_tools():
    from app.mcp.tool_registry import registry
    return {"tools": registry.list_tools()}


@router.post("/mcp-call")
async def call_mcp_tool(body: dict):
    from app.mcp.tool_registry import registry
    tool_name  = body.get("tool_name")
    parameters = body.get("parameters", {})
    if not tool_name:
        raise HTTPException(status_code=400, detail="tool_name is required")
    return registry.call(tool_name, parameters).to_dict()
