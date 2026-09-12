"""
3GPP Log Analyzer — FastAPI Application
Heavy initialisation (vector store, embedding model) runs in a background
thread so the server becomes ready immediately.
"""

import os
import logging
import threading
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
)
logger = logging.getLogger(__name__)

BASE_DIR      = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC_DIR    = os.path.join(BASE_DIR, "static")
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")


# ── Background init ───────────────────────────────────────────────────────────

def _init_vector_store():
    """Load / build the RAG vector store in a background thread."""
    kb_path = os.getenv("KNOWLEDGE_BASE_PATH", "./knowledge_base")
    db_path = os.getenv("CHROMA_DB_PATH",      "./chroma_db")
    try:
        from app.rag.vector_store import get_vector_store
        store = get_vector_store(db_path=db_path)
        if not store.is_populated():
            logger.info("RAG: vector store empty — ingesting knowledge base...")
            count = store.ingest_knowledge_base(kb_path)
            logger.info(f"RAG: ingested {count} chunks")
        else:
            logger.info("RAG: vector store already populated")
    except Exception as e:
        logger.error(f"RAG init failed: {e} — continuing without RAG")


# ── Lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("=== 3GPP Log Analyzer starting ===")

    groq_key = os.getenv("GROQ_API_KEY", "")
    if not groq_key:
        logger.warning("GROQ_API_KEY not set — LLM calls will fail")
    else:
        logger.info(f"Groq LLM: model={os.getenv('GROQ_MODEL', 'groq/compound-mini')}")

    # Kick off heavy init in background — server is ready immediately
    t = threading.Thread(target=_init_vector_store, daemon=True)
    t.start()
    logger.info("=== Startup complete (RAG loading in background) ===")

    yield
    logger.info("=== 3GPP Log Analyzer shutting down ===")


# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="3GPP Log Analyzer",
    description=(
        "Analyzes 3GPP protocol logs, detects failure points per 3GPP specifications, "
        "generates RCA using Groq + RAG + MCP tools."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

from app.routers import analysis, chat, admin

app.include_router(analysis.router)
app.include_router(chat.router)
app.include_router(admin.router)


# ── UI ────────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index():
    html_path = os.path.join(TEMPLATES_DIR, "index.html")
    with open(html_path, "r", encoding="utf-8") as f:
        content = f.read()
    return HTMLResponse(content=content)


@app.get("/health")
async def health():
    return {"status": "ok", "service": "3GPP Log Analyzer"}
