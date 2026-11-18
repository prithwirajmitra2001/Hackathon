"""Knowledge base: playbook steps + CVE advisories, each in its own hybrid index."""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass

from .alert_parser import ATTACK_NAMES, NormalizedAlert
from .cve import cve_document
from .loader import Playbook, load_cve_feed, load_playbooks
from .retriever import Doc, HybridRetriever, Hit, load_embedder

PLACEHOLDER_WORDS = {
    "message_id": "the message", "urls": "the URLs", "users": "affected user accounts", "sender": "the sender address",
    "sender_domain": "the sender domain", "domains": "malicious domains", "ips": "attacker IP addresses",
    "files": "affected files", "hosts": "affected hosts", "hashes": "malicious file hashes", "cves": "the exploited CVE",
    "app": "the targeted application", "principal": "the IAM principal", "access_keys": "the access key", "buckets": "the S3 bucket",
}


def generic_text(text: str) -> str:
    return re.sub(r"\{(\w+)\}", lambda m: PLACEHOLDER_WORDS.get(m.group(1), m.group(1)), text)


@dataclass
class PlaybookScore:
    playbook: Playbook
    score: float
    hits: int
    agreed: int      # hits found by BOTH semantic and BM25


class KnowledgeBase:
    def __init__(self):
        self.playbooks = load_playbooks()
        self.feed = load_cve_feed()
        self.embedder = load_embedder()
        step_docs = []
        for pb in self.playbooks.values():
            for s in pb.steps:
                text = (f"{pb.title} ({pb.id}). {s.section}. {generic_text(s.text)} "
                        f"Applies to: {'; '.join(pb.finding_types)}. ATT&CK {' '.join(pb.attack)} "
                        f"{' '.join(ATTACK_NAMES.get(t, '') for t in pb.attack)}. {' '.join(s.tags).replace('_', ' ')}")
                step_docs.append(Doc(s.id, text, {"playbook_id": pb.id, "section": f"{s.section_no}. {s.section}"}))
        cve_docs = [Doc(r["cve_id"], cve_document(r), {"kev": bool(r.get("kev", {}).get("listed"))}) for r in self.feed["records"]]
        self.steps = HybridRetriever(step_docs, self.embedder, "steps")
        self.cves = HybridRetriever(cve_docs, self.embedder, "cves")

    @property
    def stats(self) -> dict:
        return {"playbooks": len(self.playbooks), "steps": len(self.steps.docs), "cves": len(self.cves.docs),
                "embedder": self.embedder.name}

    # ------------------------------------------------------------ queries
    @staticmethod
    def alert_query(n: NormalizedAlert, cve_records: list[dict]) -> str:
        parts = [n.category, n.finding_type, n.title, " ".join(n.attack), " ".join(ATTACK_NAMES.get(t, "") for t in n.attack)]
        parts += [k.replace("_", " ") for k, v in n.facts.items() if v]
        parts += [PLACEHOLDER_WORDS.get(k, k) for k, v in n.entities.items() if v and k in PLACEHOLDER_WORDS]
        parts += [f"{r.get('nickname', '')} {r.get('product', '')}" for r in cve_records]
        return " ".join(p for p in parts if p)

    def rank_playbooks(self, hits: list[Hit]) -> list[PlaybookScore]:
        agg: dict[str, list[Hit]] = defaultdict(list)
        for h in hits:
            agg[h.doc.meta["playbook_id"]].append(h)
        scores = [PlaybookScore(self.playbooks[pid], sum(h.rrf for h in hs), len(hs),
                                sum(1 for h in hs if h.sem_rank and h.bm25_rank)) for pid, hs in agg.items()]
        for pid, pb in self.playbooks.items():
            if pid not in agg:
                scores.append(PlaybookScore(pb, 0.0, 0, 0))
        return sorted(scores, key=lambda s: -s.score)

    def related_cves(self, query: str, alert_attack: list[str], exclude: set[str]) -> list[Hit]:
        """Advisories related to an alert that names no CVE. Kept only when both searches agree (top 3 in each)
        AND the advisory shares an ATT&CK technique family with the alert. Context only: never sets priority."""
        if exclude:
            return []
        fam = {t.split(".")[0] for t in alert_attack}
        hits = self.cves.search(query, top_k=5)
        out = []
        for h in hits:
            rec = self.feed["by_id"][h.doc.id]
            shares = fam & {t.split(".")[0] for t in rec.get("attack", [])}
            if h.sem_rank and h.bm25_rank and h.sem_rank <= 3 and h.bm25_rank <= 3 and shares:
                out.append(h)
        return out
