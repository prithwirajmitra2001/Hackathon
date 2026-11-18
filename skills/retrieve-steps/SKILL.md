---
name: retrieve-steps
description: Find the right playbook and its relevant steps for an alert using hybrid retrieval: ChromaDB vector search plus BM25 keyword search, merged with Reciprocal Rank Fusion.
---

# Retrieve steps

Code: `socpilot/retriever.py` (HybridRetriever), `socpilot/kb.py` (KnowledgeBase)

## Index (built once at start-up)
- One document **per playbook step**: playbook title, section, step text, finding types, ATT&CK IDs and names, step tags. Metadata: `playbook_id`, `section`. The step ID is the document ID, so a retrieved step **is** its citation.
- One document per CVE advisory.
- Vectors: `all-MiniLM-L6-v2` (sentence-transformers, or ChromaDB's ONNX build), stored in ChromaDB (cosine). Offline fallback: hashing embedder.
- Keywords: BM25 (`rank_bm25`). Tokenizer keeps compound codes whole **and** split (`policy:s3/bucketpublicaccessgranted` + `bucketpublicaccessgranted`).

## Query
Built from the parsed alert: category, finding type, title, ATT&CK IDs + names, true facts, indicator types present, CVE nicknames/products.

## Merge
Reciprocal Rank Fusion: `score = 1/(60 + semantic_rank) + 1/(60 + bm25_rank)`; top 15 kept.

## Choose the playbook
Sum RRF scores per playbook. The top playbook is used only if at least one of its steps was found by **both** searches; otherwise answer "No approved procedure".
