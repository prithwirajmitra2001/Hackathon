---
name: pb-ransomware
description: Approved ransomware response SOP (PB-RANS v3.0). Use when an alert matches "ransomware", "mass file rename", "ransom note" or MITRE ATT&CK T1486, T1490. Returns cited steps only.
---

# Ransomware Response (PB-RANS)

Source of truth: `playbooks/PB-RANS.md` · owner: Incident Commander (on-call) · approved by CISO · last review 2026-05-02.

## When to use
- Encryption or mass file modification on endpoints or servers, with or without a ransom note.
- Finding types: ransomware; mass file rename; ransom note
- ATT&CK: T1486, T1490

## How to use
1. Answer each triage question from alert fields. If a field is missing, answer "unknown"; do not guess.
2. Pick severity with the first rule that is true, top to bottom.
3. Take the steps in order. Skip a step only if its `if:` condition is false or the alert has none of the indicators it needs.
4. Replace each `{placeholder}` with the real indicator values from the alert.
5. Cite every line by step ID, e.g. `PB-RANS-3.1`. Never add a step that is not listed below.
6. Sections 3 and 4 are actions: mark them "awaiting approval". Sections 2 and 5 are tasks.
7. If an indicator or a KEV required action has no step, report it as a playbook gap.

## Triage questions
- Is encryption confirmed (renamed files or ransom note)? (fact: `encryption_confirmed`)
- Is a server affected? (fact: `server`)
- Is a known-exploited initial-access vulnerability suspected? (fact: `kev_initial_access`)

## Severity
- **P1**: Encryption confirmed on any server or more than one endpoint  (rule: `encryption_confirmed and (server or multi_host)`)
- **P2**: Encryption confirmed on a single workstation  (rule: `encryption_confirmed`)
- **P3**: Ransomware tooling seen, no encryption  (rule: `true`)

## Steps

### 2. Detect & Analyze
- `PB-RANS-2.1` Confirm encryption: sample renamed files ({files}) and identify the extension and ransom note.  _(needs files)_
- `PB-RANS-2.2` Find patient zero and the initial-access path; review VPN and gateway logs for 14 days ({hosts}).  _(needs hosts)_
- `PB-RANS-2.3` Capture a memory image of {hosts} before any shutdown, if safe.  _(needs hosts)_

### 3. Contain  (needs approval)
- `PB-RANS-3.1` Network-isolate {hosts} with EDR containment. Do not power them off.  _(needs hosts)_
- `PB-RANS-3.2` Block {ips} at the perimeter firewall.  _(needs ips)_
- `PB-RANS-3.3` Block hashes {hashes} fleet-wide in EDR.  _(needs hashes)_
- `PB-RANS-3.4` Disable affected service accounts and reset privileged credentials (domain admins, backup operators).
- `PB-RANS-3.5` Disconnect the backup repository and confirm immutable copies exist.
- `PB-RANS-3.6` Preserve evidence: snapshot volumes, copy the ransom note, export the EDR timeline.

### 4. Eradicate & Recover  (needs approval)
- `PB-RANS-4.1` Patch or mitigate the initial-access vulnerability {cves} on exposed appliances.  _(needs cves)_
- `PB-RANS-4.2` Rebuild affected hosts from known-good images and restore data from immutable backup.
- `PB-RANS-4.3` Close only after 72 hours with no new encryption activity.

### 5. Post-Incident
- `PB-RANS-5.1` Engage Legal to assess regulatory notification (e.g. 72-hour GDPR window if personal data is affected).
- `PB-RANS-5.2` Hold the post-incident review within 5 business days.

## Regulatory
Personal data affected: Legal decides on GDPR Art. 33 notification within 72 hours of awareness.
