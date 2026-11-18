---
name: build-checklist
description: Draft the containment checklist for an alert from the matched playbook's steps with the LLM, then validate that every line cites a real step ID. Use after retrieve-steps.
---

# Build checklist

Code: `socpilot/pipeline.py` → `draft_checklist()`

## Steps
1. **Candidates (code):** all steps of the matched playbook, in order, minus steps whose `if:` fact is false or whose needed indicators are all absent. Fill `{placeholders}` with indicator values.
2. **Draft (LLM):** send the alert facts, severity, CVE intel and the candidates as `allowed_steps`. Ask for JSON:
   `{"checklist":[{"step_id","text"}], "omitted":[{"step_id","reason"}], "outside_sop":[str]}`.
3. **Validate (code):**
   - drop any line whose `step_id` is not in the candidates (or repeats one);
   - restore any candidate step the model silently left out (the SOP decides what is required);
   - keep the SOP order.
4. Mark sections 3 and 4 as actions that need analyst approval; sections 2 and 5 are tasks.

## Offline / failure mode
No API key or an LLM error → use the filled SOP text directly. The demo never breaks.
