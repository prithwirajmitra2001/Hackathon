---
id: PB-PHISH
title: "Phishing Response"
version: "2.1"
status: Approved
owner: "SOC Tier 2 Lead"
approved_by: "CISO"
last_review: "2026-08-14"
review_interval_days: 180
attack: [T1566, T1566.002]
finding_types:
  - "Email reported by user as malware or phish"
  - "Phish"
  - "Malicious URL click"
severity:
  - level: P1
    when: "Credentials entered, attachment executed, or an executive/finance mailbox affected"
    rule: "credentials_submitted or attachment_opened or vip"
  - level: P2
    when: "A recipient clicked a link but no credential entry is confirmed"
    rule: "clicked"
  - level: P3
    when: "Delivered, no user interaction"
    rule: "delivered"
  - level: P4
    when: "Blocked before delivery"
    rule: "true"
triage:
  - question: "Did any recipient click a link?"
    fact: clicked
  - question: "Were credentials entered on the linked page?"
    fact: credentials_submitted
  - question: "Was an attachment opened or executed?"
    fact: attachment_opened
  - question: "Is a finance or executive mailbox affected?"
    fact: vip
regulatory: "If credentials of finance users were exposed, inform Legal within 24 hours (internal policy SEC-07)."
---

# Phishing Response (PB-PHISH v2.1)

> Approved standard operating procedure. Step IDs are stable: cite them in tickets and reviews.

## 1. Overview

User-reported or detected phishing email that may lead to credential theft, malware or NTLM leakage.

**Applies to findings:** Email reported by user as malware or phish; Phish; Malicious URL click  
**MITRE ATT&CK:** T1566, T1566.002

### Severity classification

| Level | Criteria |
| --- | --- |
| P1 | Credentials entered, attachment executed, or an executive/finance mailbox affected |
| P2 | A recipient clicked a link but no credential entry is confirmed |
| P3 | Delivered, no user interaction |
| P4 | Blocked before delivery |

### Initial triage questions

- [ ] Did any recipient click a link?
- [ ] Were credentials entered on the linked page?
- [ ] Was an attachment opened or executed?
- [ ] Is a finance or executive mailbox affected?

## 2. Detect & Analyze

- **PB-PHISH-2.1** Retrieve the original message {message_id} and run a message trace to list every recipient. <!-- needs: message_id -->
- **PB-PHISH-2.2** Detonate the URLs {urls} in the sandbox and record the verdicts in the case. <!-- needs: urls -->
- **PB-PHISH-2.3** Review sign-in logs for {users} for 24 hours after delivery. <!-- needs: users -->

## 3. Contain

- **PB-PHISH-3.1** Export message headers and the sandbox report to the case folder before any purge. <!-- tags: evidence -->
- **PB-PHISH-3.2** Purge message {message_id} from all mailboxes (soft delete). <!-- needs: message_id -->
- **PB-PHISH-3.3** Block sender {sender} and domain {sender_domain} at the mail gateway. <!-- needs: sender -->
- **PB-PHISH-3.4** Block {domains} at the web proxy and DNS resolver. <!-- needs: domains -->
- **PB-PHISH-3.5** Reset the password and revoke all sessions and refresh tokens for {users}. <!-- needs: users | if: clicked | tags: session_revocation, credential_reset -->
- **PB-PHISH-3.6** Block outbound SMB (TCP 445) to the internet, including {ips}. <!-- needs: ips | tags: smb_block -->

## 4. Eradicate & Recover

- **PB-PHISH-4.1** Check mailbox rules and forwarding for {users}; remove any the user did not create. <!-- needs: users -->
- **PB-PHISH-4.2** Confirm Outlook / Office build on affected endpoints and patch within the critical-vulnerability SLA (72 h). <!-- tags: patch_client -->
- **PB-PHISH-4.3** Notify the affected users and send the phishing awareness reminder.

## 5. Post-Incident

- **PB-PHISH-5.1** Add sender, domains and URLs to the threat-intel platform as indicators.
- **PB-PHISH-5.2** Record the timeline (delivered, reported, purged, contained) in the incident ticket.

## Appendix B. Regulatory and notification

If credentials of finance users were exposed, inform Legal within 24 hours (internal policy SEC-07).

## Revision history

| Version | Date | Change |
| --- | --- | --- |
| 2.1 | 2026-08-14 | Last approved review |
