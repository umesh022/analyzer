"""
RAG Vector Store — zero-dependency pure Python implementation.
Uses TF-IDF + cosine similarity instead of sentence-transformers/torch.
This keeps RAM usage under 100 MB, making it safe for Render free tier (512 MB).

The tradeoff vs. dense embeddings: slightly lower semantic recall, but
perfectly adequate for 3GPP spec retrieval where keyword overlap is high.
Persists as JSON + npy (numpy only, no torch, no C extensions).
"""

import os
import re
import json
import glob
import math
import logging
from pathlib import Path
from typing import List, Dict, Optional

import numpy as np

logger = logging.getLogger(__name__)

CHUNK_SIZE    = 600
CHUNK_OVERLAP = 120


# ── Chunker ───────────────────────────────────────────────────────────────────

def _chunk_text(text: str, source: str) -> List[Dict]:
    chunks, start, idx = [], 0, 0
    while start < len(text):
        snippet = text[start: start + CHUNK_SIZE].strip()
        if snippet:
            chunks.append({"id": f"{source}_{idx}", "source": source,
                           "text": snippet, "chunk_index": idx})
            idx += 1
        start += CHUNK_SIZE - CHUNK_OVERLAP
    return chunks


# ── TF-IDF Vectoriser ─────────────────────────────────────────────────────────

def _tokenize(text: str) -> List[str]:
    """Lowercase, split on non-alphanum, remove stopwords."""
    _STOP = {"the","a","an","is","are","was","were","be","been","being",
             "have","has","had","do","does","did","will","would","could",
             "should","may","might","shall","and","or","but","in","on",
             "at","to","for","of","with","by","from","as","this","that",
             "it","its","not","no","if","when","which","who","how","what"}
    tokens = re.findall(r"[a-z0-9]+", text.lower())
    return [t for t in tokens if t not in _STOP and len(t) > 1]


def _build_tfidf(docs: List[str]):
    """
    Build TF-IDF matrix for a list of document strings.
    Returns (matrix [N, V] float32, vocab dict).
    """
    tokenized = [_tokenize(d) for d in docs]
    N = len(docs)

    # Vocabulary
    vocab: Dict[str, int] = {}
    for tokens in tokenized:
        for t in tokens:
            if t not in vocab:
                vocab[t] = len(vocab)

    V = len(vocab)
    if V == 0:
        return np.zeros((N, 1), dtype=np.float32), vocab

    # TF matrix
    tf = np.zeros((N, V), dtype=np.float32)
    for i, tokens in enumerate(tokenized):
        for t in tokens:
            tf[i, vocab[t]] += 1
        row_sum = tf[i].sum()
        if row_sum > 0:
            tf[i] /= row_sum

    # IDF
    df = (tf > 0).sum(axis=0).astype(np.float32)
    idf = np.log((N + 1) / (df + 1)) + 1.0   # smooth IDF

    tfidf = tf * idf

    # L2 normalise rows
    norms = np.linalg.norm(tfidf, axis=1, keepdims=True)
    norms[norms == 0] = 1.0
    tfidf /= norms

    return tfidf.astype(np.float32), vocab


def _query_vec(query: str, vocab: Dict[str, int], idf: np.ndarray,
               V: int) -> np.ndarray:
    tokens = _tokenize(query)
    vec = np.zeros(V, dtype=np.float32)
    for t in tokens:
        if t in vocab:
            vec[vocab[t]] += 1
    # Apply same IDF
    vec *= idf
    norm = np.linalg.norm(vec)
    if norm > 0:
        vec /= norm
    return vec


# ── Store ─────────────────────────────────────────────────────────────────────

class VectorStore:
    """TF-IDF backed vector store. No torch, no sentence-transformers."""

    def __init__(self, db_path: str = "./chroma_db",
                 embed_model: str = "all-MiniLM-L6-v2"):   # param kept for compat
        self.db_path    = db_path
        self._meta_file = os.path.join(db_path, "meta.json")
        self._vecs_file = os.path.join(db_path, "vecs.npy")
        self._idf_file  = os.path.join(db_path, "idf.npy")
        self._vocab_file= os.path.join(db_path, "vocab.json")

        self._meta:  List[Dict]          = []
        self._vecs:  Optional[np.ndarray]= None
        self._idf:   Optional[np.ndarray]= None
        self._vocab: Optional[Dict]      = None

        os.makedirs(db_path, exist_ok=True)
        self._load()

    # ── Persistence ───────────────────────────────────────────────────────────

    def _load(self):
        if all(os.path.exists(f) for f in
               [self._meta_file, self._vecs_file,
                self._idf_file, self._vocab_file]):
            with open(self._meta_file,  "r", encoding="utf-8") as f:
                self._meta  = json.load(f)
            with open(self._vocab_file, "r", encoding="utf-8") as f:
                self._vocab = json.load(f)
            self._vecs = np.load(self._vecs_file)
            self._idf  = np.load(self._idf_file)
            logger.info(f"RAG: loaded {len(self._meta)} chunks "
                        f"(vocab={len(self._vocab)}) from {self.db_path}")

    def _save(self):
        with open(self._meta_file,  "w", encoding="utf-8") as f:
            json.dump(self._meta, f, ensure_ascii=False)
        with open(self._vocab_file, "w", encoding="utf-8") as f:
            json.dump(self._vocab, f)
        np.save(self._vecs_file, self._vecs)
        np.save(self._idf_file,  self._idf)
        logger.info(f"RAG: saved {len(self._meta)} chunks")

    # ── Public API ────────────────────────────────────────────────────────────

    def is_populated(self) -> bool:
        return bool(self._meta) and self._vecs is not None

    def ingest_knowledge_base(self, kb_path: str) -> int:
        files = (glob.glob(os.path.join(kb_path, "**/*.md"),  recursive=True) +
                 glob.glob(os.path.join(kb_path, "**/*.txt"), recursive=True))
        if not files:
            logger.warning(f"RAG: no files found in {kb_path}")
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
                logger.error(f"RAG: error reading {fpath}: {e}")

        if not all_chunks:
            return 0

        texts = [c["text"] for c in all_chunks]
        logger.info(f"RAG: building TF-IDF for {len(texts)} chunks…")

        tfidf, vocab = _build_tfidf(texts)

        # Recompute IDF for query-time use
        N, V = tfidf.shape
        df  = (tfidf > 0).sum(axis=0).astype(np.float32)
        idf = np.log((N + 1) / (df + 1)) + 1.0

        self._meta  = all_chunks
        self._vecs  = tfidf
        self._vocab = vocab
        self._idf   = idf
        self._save()
        return len(all_chunks)

    def query(self, query_text: str, n_results: int = 5) -> List[Dict]:
        if not self.is_populated():
            return []

        V   = len(self._vocab)
        qv  = _query_vec(query_text, self._vocab, self._idf, V)
        scores = self._vecs @ qv          # cosine similarity (both normalised)

        top_k   = min(n_results, len(self._meta))
        top_idx = np.argpartition(scores, -top_k)[-top_k:]
        top_idx = top_idx[np.argsort(scores[top_idx])[::-1]]

        return [
            {
                "text":     self._meta[i]["text"],
                "source":   self._meta[i]["source"],
                "distance": float(1 - scores[i]),
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
