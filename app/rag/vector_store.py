"""
RAG Vector Store — pure Python, no ChromaDB dependency.
Uses sentence-transformers for embeddings and numpy for cosine similarity.
Persists the index as a JSON + npy file pair so restarts are fast.
"""

import os
import json
import glob
import logging
from pathlib import Path
from typing import List, Dict, Optional

import numpy as np
from sentence_transformers import SentenceTransformer

logger = logging.getLogger(__name__)

CHUNK_SIZE    = 500
CHUNK_OVERLAP = 100


# ── Chunker ───────────────────────────────────────────────────────────────────

def _chunk_text(text: str, source: str) -> List[Dict]:
    chunks, start, idx = [], 0, 0
    while start < len(text):
        snippet = text[start : start + CHUNK_SIZE].strip()
        if snippet:
            chunks.append({"id": f"{source}_{idx}", "source": source,
                           "text": snippet, "chunk_index": idx})
            idx += 1
        start += CHUNK_SIZE - CHUNK_OVERLAP
    return chunks


# ── Store ─────────────────────────────────────────────────────────────────────

class VectorStore:
    """
    Minimal vector store backed by numpy cosine similarity.
    Index is saved as:
      <db_path>/meta.json   — list of {id, source, text, chunk_index}
      <db_path>/vecs.npy    — float32 matrix (N, dim)
    """

    def __init__(self, db_path: str = "./chroma_db",
                 embed_model: str = "all-MiniLM-L6-v2"):
        self.db_path    = db_path
        self._meta_file = os.path.join(db_path, "meta.json")
        self._vecs_file = os.path.join(db_path, "vecs.npy")
        self._embedder: Optional[SentenceTransformer] = None
        self._embed_model = embed_model

        # In-memory index
        self._meta: List[Dict] = []
        self._vecs: Optional[np.ndarray] = None  # shape (N, dim)

        os.makedirs(db_path, exist_ok=True)
        self._load()

    # ── Embedder ──────────────────────────────────────────────────────────────

    def _get_embedder(self) -> SentenceTransformer:
        if self._embedder is None:
            logger.info(f"Loading embedding model: {self._embed_model}")
            self._embedder = SentenceTransformer(self._embed_model)
        return self._embedder

    def _embed(self, texts: List[str]) -> np.ndarray:
        return self._get_embedder().encode(
            texts, show_progress_bar=False, normalize_embeddings=True
        ).astype(np.float32)

    # ── Persistence ───────────────────────────────────────────────────────────

    def _load(self):
        if os.path.exists(self._meta_file) and os.path.exists(self._vecs_file):
            with open(self._meta_file, "r", encoding="utf-8") as f:
                self._meta = json.load(f)
            self._vecs = np.load(self._vecs_file)
            logger.info(f"Loaded {len(self._meta)} chunks from {self.db_path}")

    def _save(self):
        with open(self._meta_file, "w", encoding="utf-8") as f:
            json.dump(self._meta, f, ensure_ascii=False)
        np.save(self._vecs_file, self._vecs)
        logger.info(f"Saved {len(self._meta)} chunks to {self.db_path}")

    # ── Public API ────────────────────────────────────────────────────────────

    def is_populated(self) -> bool:
        return bool(self._meta)

    def ingest_knowledge_base(self, kb_path: str) -> int:
        files = (glob.glob(os.path.join(kb_path, "**/*.md"),  recursive=True) +
                 glob.glob(os.path.join(kb_path, "**/*.txt"), recursive=True))
        if not files:
            logger.warning(f"No knowledge base files found in {kb_path}")
            return 0

        all_chunks: List[Dict] = []
        for fpath in files:
            source = Path(fpath).stem
            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    content = f.read()
                chunks = _chunk_text(content, source)
                all_chunks.extend(chunks)
                logger.info(f"  {source}: {len(chunks)} chunks")
            except Exception as e:
                logger.error(f"Error reading {fpath}: {e}")

        if not all_chunks:
            return 0

        texts = [c["text"] for c in all_chunks]
        logger.info(f"Embedding {len(texts)} chunks…")
        vecs = self._embed(texts)

        self._meta = all_chunks
        self._vecs = vecs
        self._save()
        return len(all_chunks)

    def query(self, query_text: str, n_results: int = 5) -> List[Dict]:
        if not self.is_populated():
            return []

        q_vec = self._embed([query_text])[0]          # (dim,) already normalised
        # cosine similarity = dot product when both are normalised
        scores = self._vecs @ q_vec                    # (N,)
        top_k  = min(n_results, len(self._meta))
        top_idx = np.argpartition(scores, -top_k)[-top_k:]
        top_idx = top_idx[np.argsort(scores[top_idx])[::-1]]

        return [
            {
                "text":     self._meta[i]["text"],
                "source":   self._meta[i]["source"],
                "distance": float(1 - scores[i]),   # distance = 1 - similarity
            }
            for i in top_idx
        ]

    def build_context(self, failures: List[Dict], top_k: int = 4) -> str:
        if not failures:
            return ""
        query = " ".join(
            f"{f.get('layer','')} {f.get('failure_type','')} {f.get('cause','')}"
            for f in failures[:5]
        )
        chunks = self.query(query, n_results=top_k)
        if not chunks:
            return ""
        lines = ["=== 3GPP Specification Context (RAG) ==="]
        for i, c in enumerate(chunks, 1):
            lines.append(f"\n[{i}] Source: {c['source']}")
            lines.append(c["text"])
        return "\n".join(lines)


# ── Singleton ─────────────────────────────────────────────────────────────────

_store: Optional[VectorStore] = None

def get_vector_store(db_path: str = "./chroma_db",
                     embed_model: str = "all-MiniLM-L6-v2") -> VectorStore:
    global _store
    if _store is None:
        _store = VectorStore(db_path=db_path, embed_model=embed_model)
    return _store
