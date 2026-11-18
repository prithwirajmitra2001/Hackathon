"""One-click incident ticket: summary, timeline, root cause, containment actions, gaps."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from .llm import LLM
from .pipeline import IOC_LABEL, Analysis


def _root_cause_offline(a: Analysis) -> str:
    al = a.alert
    e = al.entities
    cve = next((c for c in a.cves if c.record), None)
    if al.category == "Ransomware":
        s = f"Ransomware encrypted files on {', '.join(e['hosts'][:1]) or 'an internal host'}"
        if cve:
            s += (f". Suspected initial access: {cve.cve_id} ({cve.record.get('nickname')}) on "
                  f"{e['hosts'][-1] if len(e['hosts']) > 1 else 'an exposed appliance'}, from {', '.join(e['ips']) or 'an external IP'}")
        return s + "."
    if al.category == "Phishing":
        s = f"A phishing email from {', '.join(e['sender']) or 'an external sender'} was delivered and a link was clicked by {', '.join(e['users'])}"
        if cve:
            s += f". The link pattern matches {cve.cve_id} ({cve.record.get('nickname')})"
        return s + "."
    if al.category == "Credential Stuffing":
        return (f"Automated sign-in attempts from {len(e['ips'])} IP addresses ({', '.join(e['user_agent']) or 'unknown client'}) "
                f"reused leaked passwords; {len(e['users'])} account(s) signed in successfully without MFA.")
    if al.category == "Cloud Storage Exposure":
        return (f"IAM principal {', '.join(e['principal'])} changed the policy of {', '.join(e['buckets'])} to allow public read, "
                f"calling from {', '.join(e['ips'])} (outside the corporate network).")
    return f"{al.category} activity reported by {al.source}: {al.title}."


def _ts(value: str) -> str:
    """Normalise vendor timestamps ('...Z', '...+0000', '...+00:00') to 'YYYY-MM-DD HH:MM:SS' UTC."""
    import re
    v = re.sub(r"Z$", "+00:00", str(value).strip())
    v = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", v)
    try:
        return datetime.fromisoformat(v).astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return str(value)


def build_timeline(a: Analysis, decisions: dict, created_at: str) -> list[tuple[str, str]]:
    al = a.alert
    tl = [(al.first_seen, f"Activity first seen ({al.source})")]
    if al.last_seen and al.last_seen != al.first_seen:
        tl.append((al.last_seen, "Activity last seen"))
    recv = al.raw.get("createdAt") or al.raw.get("TimeGenerated") or al.raw.get("timestamp")
    if recv and recv not in (al.first_seen, al.last_seen):
        tl.append((recv, "Alert raised"))
    tl.append((a.analyzed_at, f"Triaged by SOC Runbook Copilot: {a.playbook.id}, severity {a.severity}"))
    for sid, d in decisions.items():
        if d.get("state") in ("approved", "rejected") and d.get("at"):
            tl.append((d["at"], f"{sid} {d['state']} by analyst"))
    tl.append((created_at, "Incident ticket created"))
    return sorted(((_ts(t), what) for t, what in tl), key=lambda x: x[0])


def generate_ticket(a: Analysis, decisions: dict, incident_id: str, llm: LLM | None = None) -> str:
    """decisions: {step_id: {"state": "approved"|"rejected"|"pending", "at": iso}}"""
    created = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    pb, al, cl = a.playbook, a.alert, a.checklist
    state = lambda sid: decisions.get(sid, {}).get("state", "pending")
    approved = [i for i in cl.items if i.is_action and state(i.step_id) == "approved"]
    rejected = [i for i in cl.items if i.is_action and state(i.step_id) == "rejected"]
    pending = [i for i in cl.items if i.is_action and state(i.step_id) == "pending"]
    root, summary, written_by = _root_cause_offline(a), None, "template"
    if llm is not None:
        try:
            out = llm.complete_json(
                "Write a short incident summary (3 sentences max) and a root-cause statement for this incident. "
                "Use only the facts given. Say 'suspected' where evidence is indirect. "
                'Return JSON: {"summary": str, "root_cause": str}\n\n' + json.dumps({
                    "alert": al.title, "source": al.source, "category": al.category, "attack": al.attack_labels,
                    "indicators": {k: v for k, v in al.entities.items() if v}, "facts": al.facts, "severity": a.severity,
                    "cves": [{"id": c.cve_id, "reason": c.reason} for c in a.cves],
                    "approved_actions": [i.text for i in approved], "playbook": pb.id}), max_tokens=600)
            summary, root, written_by = out.get("summary"), out.get("root_cause") or root, f"LLM ({llm.label})"
        except Exception:
            pass
    if not summary:
        summary = (f"{al.source} raised “{al.title}”. Classified as {al.category} "
                   f"({', '.join(al.attack_labels) or 'no ATT&CK tag'}), handled under {pb.id} v{pb.version}, severity {a.severity}. "
                   f"{len(approved)} containment/recovery action(s) approved, {len(rejected)} rejected, {len(pending)} awaiting approval.")
    L = [f"# {incident_id} · {pb.title} · {a.severity}", "",
         "| Field | Value |", "| --- | --- |",
         f"| Severity | {a.severity} ({a.severity_reason}) |",
         f"| Attack type | {al.category} · {', '.join(al.attack_labels) or 'n/a'} |",
         f"| Playbook | {pb.id} v{pb.version} ({pb.status}, owner: {pb.owner}) |",
         f"| Source alert | {al.source} · {al.alert_id} |",
         f"| Created | {created} |", "",
         "## Summary", summary, "", "## Root cause", root, "", "## Timeline (UTC)"]
    L += [f"- `{t}` {what}" for t, what in build_timeline(a, decisions, created)]
    L += ["", "## Indicators of compromise"]
    L += [f"- **{IOC_LABEL.get(k, k)}:** " + ", ".join(f"`{v}`" for v in al.entities[k]) for k in IOC_LABEL if al.entities.get(k)]
    if a.cves:
        L += ["", "## Vulnerability intelligence"]
        L += [f"- **{c.cve_id}** {('(' + c.record.get('nickname', '') + ')') if c.record else ''}: {c.priority}. {c.reason}." for c in a.cves]
    L += ["", "## Containment and recovery actions"]
    for i in cl.items:
        if not i.is_action:
            continue
        st = state(i.step_id)
        box = "x" if st == "approved" else " "
        tail = {"approved": "", "rejected": " — **rejected by analyst**", "pending": " — _awaiting approval_"}[st]
        L.append(f"- [{box}] {i.text} (*{i.step_id}*){tail}")
    L += ["", "## Investigation tasks"] + [f"- [ ] {i.text} (*{i.step_id}*)" for i in cl.items if not i.is_action]
    if a.gaps:
        L += ["", "## Playbook gaps found"] + [f"- **{g['kind']}:** {g['detail']} _Fix: {g['fix']}_" for g in a.gaps]
    L += ["", "## Regulatory", pb.regulatory, "", f"_Summary and root cause written by: {written_by}. Actions cite {pb.id}; nothing was executed automatically._"]
    return "\n".join(L)
