"""The full pipeline for one alert: parse -> CVE intel -> hybrid retrieval -> playbook + severity
-> grounded checklist (LLM + validator) -> playbook gaps."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import date, datetime, timezone

from .alert_parser import NormalizedAlert, parse_alert
from .cve import CveIntel, prioritize
from .kb import KnowledgeBase, PlaybookScore, generic_text
from .llm import LLM
from .loader import Playbook, Step
from .retriever import Hit

IOC_LABEL = {"ips": "IP addresses", "domains": "domains", "urls": "URLs", "hashes": "file hashes", "users": "user accounts",
             "hosts": "hosts", "sender": "sender address", "buckets": "S3 buckets", "access_keys": "access keys",
             "user_agent": "user agent", "app": "application", "files": "files", "principal": "IAM principal"}
SEV_ORDER = {"P1": 1, "P2": 2, "P3": 3, "P4": 4}


# ------------------------------------------------------------------ data classes
@dataclass
class ChecklistItem:
    step_id: str
    section: str
    text: str
    is_action: bool
    sop_text: str
    retrieval: Hit | None = None
    note: str = ""


@dataclass
class Checklist:
    items: list[ChecklistItem]
    skipped: list[dict]
    dropped: list[dict]            # model output with no valid step ID
    outside_sop: list[str]         # model ideas not in the SOP (never actionable)
    omitted: list[dict]            # SOP steps the model left out, with its reason
    drafted_by: str


@dataclass
class Analysis:
    alert: NormalizedAlert
    cves: list[CveIntel]
    related_cves: list[Hit]
    query: str
    step_hits: list[Hit]
    ranking: list[PlaybookScore]
    playbook: Playbook | None
    triage: list[dict] = field(default_factory=list)
    severity: str = "P3"
    severity_reason: str = ""
    checklist: Checklist | None = None
    gaps: list[dict] = field(default_factory=list)
    analyzed_at: str = ""


# ------------------------------------------------------------------ rule evaluation
def eval_rule(rule: str, facts: dict) -> bool:
    """Evaluate simple rules like 'encryption_confirmed and (server or multi_host)'. Only fact names,
    and/or/not, parentheses and true/false are allowed."""
    tokens = re.findall(r"\(|\)|[A-Za-z_]+", rule)
    out = []
    for t in tokens:
        if t in ("(", ")", "and", "or", "not"):
            out.append(t)
        elif t.lower() == "true":
            out.append("True")
        elif t.lower() == "false":
            out.append("False")
        else:
            out.append("True" if facts.get(t) else "False")
    return bool(eval(" ".join(out), {"__builtins__": {}}, {}))  # noqa: S307 - whitelisted tokens only


def fill(text: str, entities: dict) -> str:
    def rep(m):
        vals = entities.get(m.group(1)) or []
        return ", ".join(f"`{v}`" for v in vals) if vals else generic_text(m.group(0))
    return re.sub(r"\{(\w+)\}", rep, text)


# ------------------------------------------------------------------ checklist
def candidate_steps(pb: Playbook, alert: NormalizedAlert) -> tuple[list[Step], list[dict]]:
    keep, skipped = [], []
    for s in pb.steps:
        if s.condition and not alert.facts.get(s.condition):
            skipped.append({"step_id": s.id, "why": f"condition '{s.condition}' is not true for this alert"})
            continue
        if s.needs and not any(alert.entities.get(k) for k in s.needs):
            skipped.append({"step_id": s.id, "why": "alert has no " + ", ".join(s.needs)})
            continue
        keep.append(s)
    return keep, skipped


def draft_checklist(a: Analysis, llm: LLM | None) -> Checklist:
    pb, alert = a.playbook, a.alert
    cands, skipped = candidate_steps(pb, alert)
    hit_by_id = {h.doc.id: h for h in a.step_hits}
    base = {s.id: ChecklistItem(s.id, f"{s.section_no}. {s.section}", fill(s.text, alert.entities), s.is_action,
                                generic_text(s.text), hit_by_id.get(s.id)) for s in cands}
    if llm is None:
        return Checklist(list(base.values()), skipped, [], [], [], "offline (SOP text filled with indicators)")

    payload = {
        "alert": {"source": alert.source, "title": alert.title, "category": alert.category, "attack": alert.attack_labels,
                  "facts": alert.facts, "indicators": {k: v for k, v in alert.entities.items() if v}},
        "severity": a.severity, "playbook": f"{pb.id} v{pb.version} {pb.title}",
        "cves": [{"id": c.cve_id, "priority": c.priority, "reason": c.reason,
                  "kev_required_action": (c.record or {}).get("kev", {}).get("required_action")} for c in a.cves],
        "allowed_steps": [{"step_id": i.step_id, "section": i.section, "sop_text": i.text} for i in base.values()],
    }
    task = ("Write the response checklist for this incident.\n"
            "- Use ONLY steps from allowed_steps, in the same order. Keep each step_id exactly.\n"
            "- Rewrite each step in one clear sentence for this incident, keeping the indicator values in backticks.\n"
            "- You may omit a step only if it clearly does not apply; list it in 'omitted' with a short reason.\n"
            "- Put any idea that is NOT in allowed_steps into 'outside_sop' (these are never actioned).\n"
            "Return JSON: {\"checklist\": [{\"step_id\": str, \"text\": str}], \"omitted\": [{\"step_id\": str, \"reason\": str}], "
            "\"outside_sop\": [str]}\n\nINPUT:\n" + json.dumps(payload, indent=1))
    try:
        out = llm.complete_json(task)
    except Exception as e:  # never break the demo: fall back to SOP text
        cl = Checklist(list(base.values()), skipped, [], [], [], f"offline fallback (LLM error: {type(e).__name__})")
        return cl
    items, dropped, seen = [], [], set()
    for row in out.get("checklist", []):
        sid = str(row.get("step_id", "")).strip()
        if sid not in base or sid in seen:          # the validator
            dropped.append({"text": row.get("text", ""), "step_id": sid or None,
                            "why": "duplicate step" if sid in seen else f"no step '{sid}' in {pb.id} candidates"})
            continue
        seen.add(sid)
        item = base[sid]
        text = str(row.get("text") or "").strip()
        item.text = text or item.text
        items.append(item)
    omitted = [o for o in out.get("omitted", []) if o.get("step_id") in base and o.get("step_id") not in seen]
    # SOP actions the model silently dropped come back: the SOP, not the model, decides what is required.
    for sid, item in base.items():
        if sid not in seen and not any(o["step_id"] == sid for o in omitted):
            item.note = "restored: model left this SOP step out"
            items.append(item)
    order = list(base)
    items.sort(key=lambda i: order.index(i.step_id))
    return Checklist(items, skipped, dropped, [str(x) for x in out.get("outside_sop", [])], omitted, f"LLM ({llm.label}) + validator")


# ------------------------------------------------------------------ gaps
def find_gaps(a: Analysis, today: date | None = None) -> list[dict]:
    pb, alert = a.playbook, a.alert
    gaps = []
    needs = {n for s in pb.steps for n in s.needs}
    tags = {t for s in pb.steps for t in s.tags}
    for k, label in IOC_LABEL.items():
        vals = alert.entities.get(k) or []
        if vals and k not in needs:
            gaps.append({"kind": "Indicator not handled", "detail": f"The alert has {label} ({', '.join(vals)}) but no step in {pb.id} acts on them.",
                         "fix": f"Add a step for {label} to {pb.id}, or record that they can be ignored."})
    for c in a.cves:
        if not c.record:
            continue
        for t in c.record.get("response_tags", []):
            if t not in tags:
                req = (c.record.get("kev", {}).get("required_action") or "").rstrip(".")
                gaps.append({"kind": "CVE action not covered",
                             "detail": f"{c.cve_id} ({c.record.get('nickname')}): CISA KEV says “{req}”. {pb.id} has no step for '{t.replace('_', ' ')}'.",
                             "fix": f"Add a '{t.replace('_', ' ')}' step to {pb.id} section 3 (Contain)."})
    today = today or datetime.now(timezone.utc).date()
    age = (today - date.fromisoformat(pb.last_review)).days
    if age > pb.review_interval_days:
        gaps.append({"kind": "Playbook overdue for review", "detail": f"{pb.id} was last reviewed {pb.last_review} ({age} days ago); policy is every {pb.review_interval_days} days.",
                     "fix": f"Ask the owner ({pb.owner}) to review it."})
    return gaps


# ------------------------------------------------------------------ main entry
def analyze(raw: dict, kb: KnowledgeBase, llm: LLM | None = None, today: date | None = None) -> Analysis:
    alert = parse_alert(raw)
    cves = [prioritize(c, kb.feed) for c in alert.entities["cves"]]
    query = kb.alert_query(alert, [c.record for c in cves if c.record])
    related = kb.related_cves(query, alert.attack, exclude=set(alert.entities["cves"]))
    hits = kb.steps.search(query, top_k=15)
    ranking = kb.rank_playbooks(hits)
    top = ranking[0]
    pb = top.playbook if top.agreed >= 1 else None   # need at least one step found by BOTH searches
    a = Analysis(alert, cves, related, query, hits, ranking, pb, analyzed_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    if pb is None:
        return a
    a.triage = [{"question": t["question"], "fact": t["fact"], "answer": alert.facts.get(t["fact"]),
                 "evidence": alert.evidence.get(t["fact"], "not in alert")} for t in pb.triage]
    level = next(s for s in pb.severity if eval_rule(str(s["rule"]), alert.facts))
    a.severity, a.severity_reason = level["level"], level["when"]
    a.checklist = draft_checklist(a, llm)
    a.gaps = find_gaps(a, today)
    return a
