---
id: PB-RANS
title: "Ransomware Response"
version: "3.0"
status: Approved
owner: "Incident Commander (on-call)"
approved_by: "CISO"
last_review: "2026-05-02"
review_interval_days: 180
attack: [T1486, T1490]
finding_types:
  - "ransomware"
  - "mass file rename"
  - "ransom note"
severity:
  - level: P1
    when: "Encryption confirmed on any server or more than one endpoint"
    rule: "encryption_confirmed and (server or multi_host)"
  - level: P2
    when: "Encryption confirmed on a single workstation"
    rule: "encryption_confirmed"
  - level: P3
    when: "Ransomware tooling seen, no encryption"
    rule: "true"
triage:
  - question: "Is encryption confirmed (renamed files or ransom note)?"
    fact: encryption_confirmed
  - question: "Is a server affected?"
    fact: server
  - question: "Is a known-exploited initial-access vulnerability suspected?"
    fact: kev_initial_access
regulatory: "Personal data affected: Legal decides on GDPR Art. 33 notification within 72 hours of awareness."
---

# Ransomware Response (PB-RANS v3.0)

> Approved standard operating procedure. Step IDs are stable: cite them in tickets and reviews.

## 1. Overview

Encryption or mass file modification on endpoints or servers, with or without a ransom note.

**Applies to findings:** ransomware; mass file rename; ransom note  
**MITRE ATT&CK:** T1486, T1490

### Severity classification

| Level | Criteria |
| --- | --- |
| P1 | Encryption confirmed on any server or more than one endpoint |
| P2 | Encryption confirmed on a single workstation |
| P3 | Ransomware tooling seen, no encryption |

### Initial triage questions

- [ ] Is encryption confirmed (renamed files or ransom note)?
- [ ] Is a server affected?
- [ ] Is a known-exploited initial-access vulnerability suspected?

## 2. Detect & Analyze

- **PB-RANS-2.1** Confirm encryption: sample renamed files ({files}) and identify the extension and ransom note. <!-- needs: files -->
- **PB-RANS-2.2** Find patient zero and the initial-access path; review VPN and gateway logs for 14 days ({hosts}). <!-- needs: hosts -->
- **PB-RANS-2.3** Capture a memory image of {hosts} before any shutdown, if safe. <!-- needs: hosts | tags: evidence -->

## 3. Contain

- **PB-RANS-3.1** Network-isolate {hosts} with EDR containment. Do not power them off. <!-- needs: hosts -->
- **PB-RANS-3.2** Block {ips} at the perimeter firewall. <!-- needs: ips -->
- **PB-RANS-3.3** Block hashes {hashes} fleet-wide in EDR. <!-- needs: hashes -->
- **PB-RANS-3.4** Disable affected service accounts and reset privileged credentials (domain admins, backup operators). <!-- tags: credential_reset -->
- **PB-RANS-3.5** Disconnect the backup repository and confirm immutable copies exist. <!-- tags: backup -->
- **PB-RANS-3.6** Preserve evidence: snapshot volumes, copy the ransom note, export the EDR timeline. <!-- tags: evidence -->

## 4. Eradicate & Recover

- **PB-RANS-4.1** Patch or mitigate the initial-access vulnerability {cves} on exposed appliances. <!-- needs: cves | tags: patch_appliance -->
- **PB-RANS-4.2** Rebuild affected hosts from known-good images and restore data from immutable backup.
- **PB-RANS-4.3** Close only after 72 hours with no new encryption activity.

## 5. Post-Incident

- **PB-RANS-5.1** Engage Legal to assess regulatory notification (e.g. 72-hour GDPR window if personal data is affected).
- **PB-RANS-5.2** Hold the post-incident review within 5 business days.

## Appendix B. Regulatory and notification

Personal data affected: Legal decides on GDPR Art. 33 notification within 72 hours of awareness.

## Revision history

| Version | Date | Change |
| --- | --- | --- |
| 3.0 | 2026-05-02 | Last approved review |
