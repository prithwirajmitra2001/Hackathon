"""Hybrid retriever: semantic search (ChromaDB) + keyword search (BM25), merged with Reciprocal Rank Fusion.

Semantic search catches meaning ("files got locked" ~ "encryption").
BM25 catches exact codes (T1486, Policy:S3/BucketPublicAccessGranted, CVE-2023-4966).
RRF score = sum over both lists of 1 / (k + rank), with k = 60.
"""
from __future__ import annotations

import hashlib
import math
import os
import re
import uuid
from dataclasses import dataclass, field

import chromadb
from rank_bm25 import BM25Okapi

RRF_K = 60
STOP = set("a an and are as at be by for from has have if in into is it its of on or that the this to was were with any all no not".split())


# ------------------------------------------------------------------ embeddings
class HashingEmbedder:
    """Offline fallback: feature-hashed word + character-trigram vectors (no model download).
    Used only when the real embedding model cannot be downloaded."""
    name = "offline hashing embedder (fallback)"

    def __init__(self, dim: int = 768):
        self.dim = dim

    def _vec(self, text: str) -> list[float]:
        v = [0.0] * self.dim
        words = re.findall(r"[a-z0-9]+", text.lower())
        feats = [w for w in words if w not in STOP]
        for w in words:
            p = f"#{w}#"
            feats += [p[i:i + 3] for i in range(len(p) - 2)]
        for f in feats:
            h = int(hashlib.md5(f.encode()).hexdigest(), 16)
            v[h % self.dim] += 1.0 if (h >> 64) & 1 else -1.0
        norm = math.sqrt(sum(x * x for x in v)) or 1.0
        return [x / norm for x in v]

    def __call__(self, texts: list[str]) -> list[list[float]]:
        return [self._vec(t) for t in texts]


def load_embedder():
    """Prefer a real sentence-embedding model; fall back to hashing if it cannot be loaded."""
    if os.getenv("SOCPILOT_EMBEDDER", "").lower() == "hashing":
        return HashingEmbedder()
    try:  # sentence-transformers, if installed
        from sentence_transformers import SentenceTransformer  # type: ignore
        model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")

        class _ST:
            name = "all-MiniLM-L6-v2 (sentence-transformers)"

            def __call__(self, texts):
                return model.encode(list(texts), normalize_embeddings=True).tolist()
        e = _ST()
        e(["probe"])
        return e
    except Exception:
        pass
    try:  # ChromaDB's built-in ONNX build of the same model (lighter, no torch)
        from chromadb.utils.embedding_functions import DefaultEmbeddingFunction
        ef = DefaultEmbeddingFunction()

        class _Onnx:
            name = "all-MiniLM-L6-v2 (ONNX, via ChromaDB)"

            def __call__(self, texts):
                return [list(map(float, v)) for v in ef(list(texts))]
        e = _Onnx()
        e(["probe"])
        return e
    except Exception:
        return HashingEmbedder()


# ------------------------------------------------------------------ BM25 tokens
def tokenize(text: str) -> list[str]:
    """Keep compound security codes whole AND split into parts, so both 'policy:s3/bucketpublicaccessgranted'
    and 'bucketpublicaccessgranted' match."""
    toks: list[str] = []
    for m in re.findall(r"[a-z0-9]+(?:[.:/_-][a-z0-9]+)*", text.lower()):
        parts = re.split(r"[.:/_-]", m)
        if len(parts) > 1:
            toks.append(m)
        toks += [p for p in parts if p and p not in STOP]
    return toks


# ------------------------------------------------------------------ retriever
@dataclass
class Doc:
    id: str
    text: str
    meta: dict = field(default_factory=dict)


@dataclass
class Hit:
    doc: Doc
    rrf: float
    sem_rank: int | None
    bm25_rank: int | None
    sem_score: float | None
    bm25_score: float | None


class HybridRetriever:
    def __init__(self, docs: list[Doc], embedder, name: str):
        self.docs = docs
        self.by_id = {d.id: d for d in docs}
        self.embedder = embedder
        client = chromadb.EphemeralClient()
        self.collection = client.create_collection(name=f"{name}-{uuid.uuid4().hex[:8]}", metadata={"hnsw:space": "cosine"})
        self.collection.add(ids=[d.id for d in docs], documents=[d.text for d in docs],
                            embeddings=embedder([d.text for d in docs]),
                            metadatas=[{k: (v if isinstance(v, (str, int, float, bool)) else str(v)) for k, v in d.meta.items()} or {"_": ""} for d in docs])
        self.bm25 = BM25Okapi([tokenize(d.text) for d in docs])

    def semantic(self, query: str, n: int) -> list[tuple[str, float]]:
        res = self.collection.query(query_embeddings=self.embedder([query]), n_results=min(n, len(self.docs)))
        return [(i, 1.0 - d) for i, d in zip(res["ids"][0], res["distances"][0])]

    def keyword(self, query: str, n: int) -> list[tuple[str, float]]:
        scores = self.bm25.get_scores(tokenize(query))
        ranked = sorted(zip([d.id for d in self.docs], scores), key=lambda x: -x[1])
        return [(i, float(s)) for i, s in ranked[:n] if s > 0]

    def search(self, query: str, top_k: int = 10, pool: int = 25) -> list[Hit]:
        sem = self.semantic(query, pool)
        kw = self.keyword(query, pool)
        sem_rank = {i: r + 1 for r, (i, _) in enumerate(sem)}
        kw_rank = {i: r + 1 for r, (i, _) in enumerate(kw)}
        sem_score, kw_score = dict(sem), dict(kw)
        ids = set(sem_rank) | set(kw_rank)
        hits = []
        for i in ids:
            rrf = (1 / (RRF_K + sem_rank[i]) if i in sem_rank else 0) + (1 / (RRF_K + kw_rank[i]) if i in kw_rank else 0)
            hits.append(Hit(self.by_id[i], rrf, sem_rank.get(i), kw_rank.get(i), sem_score.get(i), kw_score.get(i)))
        hits.sort(key=lambda h: -h.rrf)
        return hits[:top_k]
