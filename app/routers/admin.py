"""
Admin Router
Endpoints for managing the RAG knowledge base and system status.
"""

import logging
import os
from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/admin", tags=["admin"])


@router.post("/rebuild-index")
async def rebuild_index():
    """Re-ingest all knowledge base documents into the vector store."""
    from app.rag.vector_store import get_vector_store
    kb_path = os.getenv("KNOWLEDGE_BASE_PATH", "./knowledge_base")
    try:
        store = get_vector_store()
        count = store.ingest_knowledge_base(kb_path)
        return {"status": "ok", "chunks_ingested": count, "kb_path": kb_path}
    except Exception as e:
        logger.exception("Knowledge base rebuild failed")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/status")
async def get_status():
    """Return system health and configuration status."""
    from app.rag.vector_store import get_vector_store

    groq_key_set = bool(os.getenv("GROQ_API_KEY"))
    model        = os.getenv("GROQ_MODEL", "openai/gpt-oss-20b")
    kb_path      = os.getenv("KNOWLEDGE_BASE_PATH", "./knowledge_base")
    db_path      = os.getenv("CHROMA_DB_PATH", "./chroma_db")

    # Check KB files
    import glob
    kb_files = glob.glob(os.path.join(kb_path, "**/*.md"), recursive=True)
    kb_files += glob.glob(os.path.join(kb_path, "**/*.txt"), recursive=True)

    # Check vector store
    vector_count = 0
    try:
        store = get_vector_store(db_path=db_path)
        from app.rag.vector_store import _store
        if _store and _store._collection:
            vector_count = _store._collection.count()
    except Exception:
        pass

    return {
        "groq_api_key_configured": groq_key_set,
        "groq_model": model,
        "groq_provider": "GroqCloud (api.groq.com)",
        "knowledge_base_files": len(kb_files),
        "vector_store_chunks": vector_count,
        "vector_store_path": db_path,
        "knowledge_base_path": kb_path,
    }
