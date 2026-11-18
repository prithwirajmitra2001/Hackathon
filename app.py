"""SOC Runbook Copilot: Streamlit UI.  Run:  streamlit run app.py"""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone

# ChromaDB needs sqlite >= 3.35; some hosts ship older. Swap in pysqlite3 when it is installed.
try:
    __import__("pysqlite3")
    import sys
    sys.modules["sqlite3"] = sys.modules.pop("pysqlite3")
except ImportError:
    pass

import pandas as pd
import streamlit as st

st.set_page_config(page_title="SOC Runbook Copilot", page_icon="\U0001F6E1", layout="wide")

for _k in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "SOCPILOT_MODEL", "SOCPILOT_EMBEDDER"):
    try:
        if _k in st.secrets and not os.getenv(_k):
            os.environ[_k] = str(st.secrets[_k])
    except Exception:
        pass

from socpilot.alert_parser import ATTACK_NAMES  # noqa: E402
from socpilot.kb import KnowledgeBase, generic_text  # noqa: E402
from socpilot.llm import get_llm  # noqa: E402
from socpilot.loader import load_sample_alerts  # noqa: E402
from socpilot.pipeline import IOC_LABEL, analyze  # noqa: E402
from socpilot.ticket import generate_ticket  # noqa: E402

SEV_COLOR = {"P1": "#b3263a", "P2": "#9a5f0c", "P3": "#2b5797", "P4": "#586a77"}
st.markdown("""<style>
.badge{display:inline-block;padding:2px 10px;border-radius:999px;font-weight:600;font-size:.85rem;color:#fff;margin-right:6px}
.chip{display:inline-block;padding:1px 8px;border-radius:6px;font-family:ui-monospace,monospace;font-size:.8rem;border:1px solid #0c6a84;color:#0c6a84;margin-right:4px}
.gap{border-left:4px solid #c27c0e;background:rgba(194,124,14,.08);padding:10px 14px;border-radius:6px;margin-bottom:10px}
.drop{border-left:4px solid #b3263a;background:rgba(179,38,58,.07);padding:8px 12px;border-radius:6px;margin-bottom:8px}
.small{font-size:.85rem;opacity:.75}
</style>""", unsafe_allow_html=True)


def badge(text: str, color: str) -> str:
    return f'<span class="badge" style="background:{color}">{text}</span>'


@st.cache_resource(show_spinner="Building the knowledge base (vector store + BM25)...")
def get_kb() -> KnowledgeBase:
    return KnowledgeBase()


kb = get_kb()
llm = get_llm()
samples = load_sample_alerts()
SAMPLE_LABELS = {"alert_ransom_wazuh.json": "Ransomware on file server (Wazuh)",
                 "alert_phish_sentinel.json": "Phishing email clicked (Sentinel)",
                 "alert_credstuff_sentinel.json": "Credential stuffing (Sentinel)",
                 "alert_s3_guardduty.json": "Public S3 bucket (GuardDuty)"}

# ------------------------------------------------------------------ sidebar
with st.sidebar:
    st.title("\U0001F6E1 SOC Runbook Copilot")
    st.caption("Confirmed alert in → approved, cited playbook steps out. Nothing is executed.")
    mode = st.radio("Alert input", ["Sample alerts", "Upload JSON", "Paste JSON"], horizontal=False)
    raw, alert_name = None, None
    if mode == "Sample alerts":
        names = [n for n in SAMPLE_LABELS if n in samples] + [n for n in samples if n not in SAMPLE_LABELS]
        alert_name = st.selectbox("Alert", names, format_func=lambda n: SAMPLE_LABELS.get(n, n))
        raw = samples[alert_name]
    elif mode == "Upload JSON":
        f = st.file_uploader("Alert JSON (GuardDuty, Sentinel, Wazuh or any JSON)", type=["json"])
        if f:
            try:
                raw, alert_name = json.load(f), f.name
            except ValueError:
                st.error("That file is not valid JSON.")
    else:
        txt = st.text_area("Paste one alert as JSON", height=180)
        if txt.strip():
            try:
                raw, alert_name = json.loads(txt), "pasted alert"
            except ValueError:
                st.error("That text is not valid JSON.")
    st.divider()
    st.markdown("**Knowledge base**")
    s = kb.stats
    st.markdown(f"{s['playbooks']} playbooks · {s['steps']} steps · {s['cves']} CVE advisories  \n"
                f"<span class='small'>Embeddings: {s['embedder']}<br>Retrieval: ChromaDB + BM25, merged with RRF (k=60)</span>",
                unsafe_allow_html=True)
    st.markdown("**Language model**")
    st.markdown(llm.label if llm else "<span class='small'>Offline mode: no API key set. Checklist uses SOP text filled "
                "with indicators; ticket uses templates. Add ANTHROPIC_API_KEY or OPENAI_API_KEY to enable.</span>",
                unsafe_allow_html=True)

if raw is None:
    st.info("Choose a sample alert, or upload / paste one, in the sidebar.")
    st.stop()
if not isinstance(raw, dict):
    st.error("Expected one alert as a JSON object.")
    st.stop()

# ------------------------------------------------------------------ analysis (cached per alert)
key = hashlib.sha1(json.dumps(raw, sort_keys=True).encode()).hexdigest()[:12]
ss = st.session_state
ss.setdefault("analyses", {})
ss.setdefault("decisions", {})
ss.setdefault("tickets", {})
rerun = st.sidebar.button("Re-run analysis", use_container_width=True)
if key not in ss.analyses or rerun:
    with st.spinner("Parsing alert, searching playbooks and drafting the checklist..."):
        ss.analyses[key] = analyze(raw, kb, llm)
    ss.decisions[key] = {}
    ss.tickets.pop(key, None)
a = ss.analyses[key]
decisions = ss.decisions[key]
al = a.alert
incident_id = "INC-" + datetime.now(timezone.utc).strftime("%Y%m%d") + "-" + key[:4].upper()

head = f"{badge(a.severity, SEV_COLOR.get(a.severity, '#586a77'))}" if a.playbook else badge("No playbook", "#586a77")
head += badge(al.category, "#0c6a84")
st.markdown(f"### {al.title}")
st.markdown(head + f"<span class='small'>{al.source} · first seen {al.first_seen} · {incident_id}</span>", unsafe_allow_html=True)

tabs = st.tabs(["1 · Alert & IoCs", "2 · CVE intel", "3 · Playbook & severity", "4 · Containment checklist",
                "5 · Playbook gaps", "6 · Incident ticket", "Knowledge base"])

# ------------------------------------------------------------------ 1. alert parser
with tabs[0]:
    c1, c2 = st.columns([1, 1.4])
    with c1:
        st.subheader("Attack classification")
        st.markdown(f"**{al.category}**")
        for t in al.attack:
            st.markdown(f"<span class='chip'>{t}</span> {ATTACK_NAMES.get(t, '')}", unsafe_allow_html=True)
        st.caption(f"ATT&CK source: {al.attack_source}")
        st.markdown(f"**Source:** {al.source}  \n**Finding type:** `{al.finding_type}`  \n**Vendor severity:** {al.vendor_severity}  \n"
                    f"**First / last seen:** {al.first_seen} / {al.last_seen}")
        if al.facts:
            st.markdown("**Facts read from the alert**")
            st.dataframe(pd.DataFrame([{"fact": k, "value": v, "evidence": al.evidence.get(k, "")} for k, v in al.facts.items()]),
                         hide_index=True, use_container_width=True)
    with c2:
        st.subheader("Indicators of compromise")
        rows = [{"type": IOC_LABEL.get(k, k.replace("_", " ")), "value": v, "found in": w} for k, v, w in al.iocs()]
        st.dataframe(pd.DataFrame(rows) if rows else pd.DataFrame(columns=["type", "value", "found in"]), hide_index=True, use_container_width=True)
    with st.expander("Raw alert JSON (as the vendor sent it)"):
        st.json(raw)

# ------------------------------------------------------------------ 2. CVE intel
with tabs[1]:
    st.caption("Priority ladder: CISA KEV → EPSS → SSVC → CVSS. The first signal that fires decides.")
    if not a.cves:
        st.info("This alert names no CVE. Severity comes from the playbook's own table (tab 3).")
    for c in a.cves:
        with st.container(border=True):
            rec = c.record or {}
            st.markdown(f"{badge(c.priority, SEV_COLOR[c.priority])} **{c.cve_id}** {rec.get('nickname', '')}  \n"
                        f"<span class='small'>{rec.get('title', 'Not in local feed')} · found by: {c.how_found}</span>", unsafe_allow_html=True)
            st.dataframe(pd.DataFrame([{"signal": l["signal"], "value": l["detail"], "decided": "✔" if l["decided"] else ""} for l in c.ladder]),
                         hide_index=True, use_container_width=True)
            st.markdown(f"**Why {c.priority}:** {c.reason}.")
            if rec.get("kev", {}).get("required_action"):
                st.markdown(f"**CISA required action:** {rec['kev']['required_action']}")
    if a.related_cves:
        st.subheader("Related advisories (hybrid search, context only)")
        for h in a.related_cves:
            rec = kb.feed["by_id"][h.doc.id]
            st.markdown(f"- **{h.doc.id}** {rec['nickname']}: {rec['title']} <span class='small'>(semantic #{h.sem_rank}, BM25 #{h.bm25_rank})</span>",
                        unsafe_allow_html=True)

# ------------------------------------------------------------------ 3. playbook + severity
with tabs[2]:
    st.subheader("Which playbook? (hybrid retrieval over all playbook steps)")
    st.dataframe(pd.DataFrame([{"playbook": r.playbook.id, "title": r.playbook.title, "RRF score": round(r.score, 4),
                                "steps in top 15": r.hits, "found by both searches": r.agreed} for r in a.ranking]),
                 hide_index=True, use_container_width=True)
    st.caption(f"Search text built from the alert: {a.query}")
    if not a.playbook:
        st.error("No approved procedure matches this alert. Escalate to Tier 2 (AGENTS.md rule 2).")
    else:
        pb = a.playbook
        st.markdown(f"**Selected:** {pb.id} · {pb.title} v{pb.version} · {pb.status} · owner {pb.owner} · last review {pb.last_review}")
        st.subheader("Triage questions (from the playbook)")
        st.dataframe(pd.DataFrame([{"question": t["question"], "answer": {True: "Yes", False: "No", None: "Unknown"}[t["answer"]],
                                    "evidence in alert": t["evidence"]} for t in a.triage]), hide_index=True, use_container_width=True)
        st.markdown(f"Severity {badge(a.severity, SEV_COLOR[a.severity])} because: *{a.severity_reason}*", unsafe_allow_html=True)
        with st.expander(f"Read {pb.id}.md"):
            st.markdown(pb.markdown.split("---", 2)[2])

# ------------------------------------------------------------------ 4. checklist
def _set(step_id: str, widget_key: str):
    val = ss[widget_key]
    decisions[step_id] = {"state": {"Approve": "approved", "Reject": "rejected"}.get(val, "pending"),
                          "at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}


with tabs[3]:
    if not a.playbook:
        st.error("No checklist: no approved procedure for this alert.")
    else:
        cl, pb = a.checklist, a.playbook
        acts = [i for i in cl.items if i.is_action]
        n_ap = sum(1 for i in acts if decisions.get(i.step_id, {}).get("state") == "approved")
        m = st.columns(5)
        m[0].metric("Steps in checklist", len(cl.items))
        m[1].metric("Need approval", len(acts))
        m[2].metric("Approved", n_ap)
        m[3].metric("Dropped by validator", len(cl.dropped))
        m[4].metric("Skipped (not applicable)", len(cl.skipped))
        st.caption(f"Drafted by: {cl.drafted_by}. Every line cites a step in {pb.id}; containment waits for an analyst.")
        if st.button("Approve all containment and recovery actions"):
            now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            for i in acts:
                decisions[i.step_id] = {"state": "approved", "at": now}
                ss[f"dec-{key}-{i.step_id}"] = "Approve"
            st.rerun()
        section = None
        for i in cl.items:
            if i.section != section:
                section = i.section
                st.markdown(f"#### {section}")
            c1, c2, c3 = st.columns([5, 1.3, 3])
            c1.markdown(i.text + (f"  \n<span class='small'>{i.note}</span>" if i.note else ""), unsafe_allow_html=True)
            with c2.popover(i.step_id, use_container_width=True):
                stp = pb.step(i.step_id)
                st.markdown(f"**{i.step_id}** · {pb.title} v{pb.version} · {stp.section_no}. {stp.section}")
                st.markdown(f"> {generic_text(stp.text)}")
                if i.retrieval:
                    st.caption(f"Retrieval: semantic #{i.retrieval.sem_rank or '-'}, BM25 #{i.retrieval.bm25_rank or '-'}, RRF {i.retrieval.rrf:.4f}")
            if i.is_action:
                wk = f"dec-{key}-{i.step_id}"
                ss.setdefault(wk, "Pending")
                c3.radio("decision", ["Pending", "Approve", "Reject"], key=wk, horizontal=True, label_visibility="collapsed",
                         on_change=_set, args=(i.step_id, wk))
            else:
                c3.caption("investigation task")
        if cl.dropped:
            st.markdown("#### Dropped by the validator")
            for d in cl.dropped:
                st.markdown(f"<div class='drop'><s>{d['text']}</s><br><span class='small'>{d['why']}</span></div>", unsafe_allow_html=True)
        if cl.outside_sop:
            st.markdown("#### Model ideas outside the SOP (not actionable)")
            for x in cl.outside_sop:
                st.markdown(f"<div class='drop'>{x}<br><span class='small'>Not in {pb.id}. Shown for review only; add it to the playbook to make it actionable.</span></div>",
                            unsafe_allow_html=True)
        if cl.omitted:
            with st.expander(f"Steps the model omitted ({len(cl.omitted)})"):
                for o in cl.omitted:
                    st.markdown(f"- **{o['step_id']}**: {o.get('reason', '')}")
        if cl.skipped:
            with st.expander(f"Steps skipped by rule ({len(cl.skipped)})"):
                for sk in cl.skipped:
                    st.markdown(f"- **{sk['step_id']}**: {sk['why']}")
        with st.expander("Why these steps? (hybrid retrieval ranks)"):
            st.dataframe(pd.DataFrame([{"step": h.doc.id, "playbook": h.doc.meta["playbook_id"], "semantic rank": h.sem_rank,
                                        "BM25 rank": h.bm25_rank, "RRF": round(h.rrf, 4)} for h in a.step_hits]),
                         hide_index=True, use_container_width=True)

# ------------------------------------------------------------------ 5. gaps
with tabs[4]:
    if not a.playbook:
        st.warning("No playbook covers this alert at all: that is the biggest gap. Consider writing one.")
    elif not a.gaps:
        st.success(f"No gaps: every indicator and every KEV required action is covered by {a.playbook.id}.")
    else:
        st.caption("Found by plain code after each run: indicators no step acts on, KEV required actions with no matching step, overdue reviews.")
        for g in a.gaps:
            st.markdown(f"<div class='gap'><b>{g['kind']}</b><br>{g['detail']}<br><span class='small'>Suggested fix: {g['fix']}</span></div>",
                        unsafe_allow_html=True)

# ------------------------------------------------------------------ 6. ticket
with tabs[5]:
    if not a.playbook:
        st.info("Ticket needs a matched playbook.")
    else:
        if st.button("\U0001F4DD Generate Incident Ticket", type="primary"):
            with st.spinner("Writing the ticket..."):
                ss.tickets[key] = generate_ticket(a, decisions, incident_id, llm)
        md = ss.tickets.get(key)
        if md:
            st.download_button("Download ticket (.md)", md, file_name=f"{incident_id}.md", mime="text/markdown")
            with st.container(border=True):
                import re as _re
                st.markdown(_re.sub(r"^(#{1,2}) ", lambda m: "#" * (len(m.group(1)) + 3) + " ", md, flags=_re.M))
            with st.expander("Markdown source (copy into Jira / ServiceNow)"):
                st.code(md, language="markdown")
        else:
            st.caption("Approve or reject actions in tab 4 first; the ticket records each decision with its time.")

# ------------------------------------------------------------------ knowledge base
with tabs[6]:
    s = kb.stats
    m = st.columns(4)
    m[0].metric("Playbooks", s["playbooks"])
    m[1].metric("Indexed steps", s["steps"])
    m[2].metric("CVE advisories", s["cves"])
    m[3].metric("Retrieval", "Hybrid")
    st.caption(f"Embeddings: {s['embedder']}. Vector store: ChromaDB (cosine). Keywords: BM25. Merge: Reciprocal Rank Fusion, k=60.")
    q = st.text_input("Try a search", "files got locked and a note asks for bitcoin")
    which = st.radio("Index", ["Playbook steps", "CVE advisories"], horizontal=True)
    if q:
        r = (kb.steps if which == "Playbook steps" else kb.cves).search(q, top_k=8)
        st.dataframe(pd.DataFrame([{"id": h.doc.id, "semantic rank": h.sem_rank, "BM25 rank": h.bm25_rank, "RRF": round(h.rrf, 4),
                                    "text": h.doc.text[:160] + "…"} for h in r]), hide_index=True, use_container_width=True)
    c1, c2 = st.columns(2)
    with c1:
        pid = st.selectbox("View a playbook", list(kb.playbooks))
        with st.container(height=420):
            st.markdown(kb.playbooks[pid].markdown.split("---", 2)[2])
    with c2:
        st.markdown("**CVE feed** (`data/cve_feed.json`)")
        st.dataframe(pd.DataFrame([{"CVE": r["cve_id"], "name": r["nickname"], "KEV": "yes" if r["kev"].get("listed") else "no",
                                    "ransomware": r["kev"].get("known_ransomware_use", "-"), "EPSS": r["epss"]["score"],
                                    "CVSS": r["cvss_v31"]["base_score"]} for r in kb.feed["records"]]), hide_index=True, use_container_width=True)
