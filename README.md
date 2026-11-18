# SOC Runbook Copilot

**A confirmed security alert goes in. The company's approved response comes out:** a containment checklist where every line cites an exact SOP step, a one-click incident ticket, and a list of gaps in the playbook itself. A human approves every action; nothing is executed.

Hackathon problem **4A: SOC Incident Runbook & Threat Intel Assistant**.

## Required features → where they live

| 4A expected functionality | Implementation | In the app |
|---|---|---|
| Vector store indexing SOC playbooks and CVE advisories | `socpilot/retriever.py`, `socpilot/kb.py`: one document per playbook step + one per CVE, in **ChromaDB**, plus **BM25**, merged with **Reciprocal Rank Fusion** (hybrid retrieval) | *Knowledge base* tab (try a search), *Why these steps?* panel |
| Alert log parser extracting IoCs and attack classification from raw JSON | `socpilot/alert_parser.py`: GuardDuty, Sentinel, Wazuh + generic regex parser; category + MITRE ATT&CK | Tab 1 *Alert & IoCs* |
| Grounded containment checklist citing exact SOP steps | `socpilot/pipeline.py`: LLM drafts from retrieved steps only; validator drops lines without a real step ID | Tab 4 *Containment checklist* (click a step ID to see the SOP text) |
| One-click "Generate Incident Ticket" (timeline, root cause, containment actions) | `socpilot/ticket.py` | Tab 6 *Incident ticket* |
| **Extra:** CVE priority ladder (KEV → EPSS → SSVC → CVSS) | `socpilot/cve.py` | Tab 2 *CVE intel* |
| **Extra:** playbook gap finder | `socpilot/pipeline.py` → `find_gaps()` | Tab 5 *Playbook gaps* |

## How it works

```
alert JSON ──► parse-alert ──► extract-iocs ──► enrich-cve ──► retrieve-steps ──► build-checklist ──► analyst approves ──► write-ticket
 (GuardDuty,    common shape    IPs, hosts,      KEV/EPSS/      ChromaDB + BM25     LLM + validator      Approve / Reject      timeline, root cause,
  Sentinel,     + ATT&CK        hashes, CVEs…    SSVC/CVSS      → RRF → playbook    (cites step IDs)     per action            actions, gaps
  Wazuh)
```

Only *build-checklist* and *write-ticket* use the LLM. Everything else is plain, testable code.

## Run locally (2 minutes)

```bash
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
export ANTHROPIC_API_KEY=sk-ant-...                    # or OPENAI_API_KEY=...; optional
streamlit run app.py
```

- **No API key?** The app still runs in *offline mode*: the checklist uses the SOP text filled with the alert's indicators, and the ticket uses templates.
- **First start** downloads the `all-MiniLM-L6-v2` embedding model (about 80 MB). If the download is blocked, the app falls back to an offline hashing embedder and says so in the sidebar.
- Terminal version: `python cli.py data/alerts/alert_ransom_wazuh.json --approve-all`
- Tests: `pytest -q` (11 tests, run offline)
- Optional: `SOCPILOT_MODEL` overrides the model name; `SOCPILOT_OFFLINE=1` forces offline mode.

## Host it live (free)

**Streamlit Community Cloud** (simplest):
1. Push this folder to a GitHub repository.
2. Go to <https://share.streamlit.io> → *Create app* → pick the repo, branch `main`, file `app.py`.
3. *Advanced settings → Secrets*: paste `ANTHROPIC_API_KEY = "sk-ant-..."` (see `.streamlit/secrets.toml.example`).
4. Deploy. You get a public `https://<name>.streamlit.app` link.

**Hugging Face Spaces** (alternative): create a *Streamlit* Space, upload these files, and add `ANTHROPIC_API_KEY` under *Settings → Variables and secrets*.

## Project layout

```
AGENTS.md                 agent role, hard rules, pipeline map
skills/                   Agent Skills (SKILL.md)
  parse-alert/ extract-iocs/ enrich-cve/ retrieve-steps/ build-checklist/ write-ticket/
  pb-phishing/ pb-ransomware/ pb-credential-stuffing/ pb-ddos/ pb-public-s3-bucket/
playbooks/PB-*.md         5 approved SOPs (NIST SP 800-61r3 / AWS template shape, stable step IDs)
data/cve_feed.json        8 CVE advisories: NVD + CISA KEV + FIRST EPSS + CISA SSVC
data/alerts/*.json        4 sample alerts in real vendor formats
socpilot/                 pipeline code
app.py                    Streamlit UI
cli.py                    terminal runner
scripts/build_skills.py   regenerate playbook skills after editing a playbook
tests/                    pytest
```

## The sample data

- **Playbooks.** Phishing, Ransomware, Credential Stuffing, DDoS and Public S3 Bucket. YAML front matter holds the severity rules and triage questions; each step is `- **PB-XXX-n.m** text <!-- needs | if | tags -->`. Two flaws are planted on purpose: PB-RANS has no session-revocation step (needed for Citrix Bleed), and its review is overdue.
- **CVE feed.** Real CVE IDs, CVSS scores, KEV dates and ransomware flags. EPSS values are from FIRST on 2026-11-18. SSVC *automatable* / *technical impact* values are illustrative. Three entries are decoys that no alert should match.
- **Alerts.** GuardDuty (public S3 bucket), Sentinel (phishing; credential stuffing), Wazuh (ransomware). All indicators are fake: documentation IP ranges, `.example` / `.test` domains, random hashes, AWS account `123456789012`.

## 2-minute demo script

1. **Knowledge base tab:** 52 steps and 8 advisories indexed. Search "files got locked and a note asks for bitcoin" and show the semantic and BM25 ranks.
2. **Ransomware alert, tab 1:** IoCs, each with the field it came from; attack type *Ransomware · T1486*.
3. **Tab 2:** CVE-2023-4966 is P1 because it is in CISA KEV and used by ransomware.
4. **Tab 4:** every line cites `PB-RANS-x.y`; click a citation to show the SOP text. Approve the actions.
5. **Tab 6:** *Generate Incident Ticket*. Show the timeline with the approval times, the root cause and the actions.
6. **Tab 5:** the gap: "CISA says *kill all active and persistent sessions*; PB-RANS has no step for it."

## Limitations

- Sample data only; no connections to real SIEM, EDR or ticketing systems, and no actions are executed.
- Alert facts (e.g. "clicked", "public read") are read by per-vendor rules; new vendors need a small parser.
- The CVE feed is a local snapshot, not a live sync.
