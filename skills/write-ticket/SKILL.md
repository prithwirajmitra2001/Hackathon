---
name: write-ticket
description: Generate the incident ticket (summary, timeline, root cause, containment actions, IoCs, CVE intel, playbook gaps) in Markdown when the analyst clicks Generate Incident Ticket.
---

# Write ticket

Code: `socpilot/ticket.py` → `generate_ticket()`, gaps in `socpilot/pipeline.py` → `find_gaps()`

## Sections
1. Header table: severity + reason, attack type, playbook + version + owner, source alert, created time.
2. **Summary** and **Root cause**: LLM, facts only, "suspected" when indirect (template fallback offline).
3. **Timeline (UTC):** activity first/last seen, alert raised, triage time, every analyst approve/reject with its time, ticket created. Timestamps normalized from vendor formats.
4. IoCs, CVE intelligence (priority + reason).
5. **Containment and recovery actions:** `[x]` approved, rejected, or awaiting approval; each with its step ID.
6. Investigation tasks.
7. **Playbook gaps** (code, never the LLM):
   - an indicator type present in the alert that no step acts on;
   - a KEV `required_action` (CVE `response_tags`) with no step carrying that tag;
   - playbook older than its `review_interval_days`.
8. Regulatory note from the playbook.
