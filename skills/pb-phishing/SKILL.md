---
name: pb-phishing
description: Approved phishing response SOP (PB-PHISH v2.1). Use when an alert matches "Email reported by user as malware or phish", "Phish", "Malicious URL click" or MITRE ATT&CK T1566, T1566.002. Returns cited steps only.
---

# Phishing Response (PB-PHISH)

Source of truth: `playbooks/PB-PHISH.md` · owner: SOC Tier 2 Lead · approved by CISO · last review 2026-08-14.

## When to use
- User-reported or detected phishing email that may lead to credential theft, malware or NTLM leakage.
- Finding types: Email reported by user as malware or phish; Phish; Malicious URL click
- ATT&CK: T1566, T1566.002

## How to use
1. Answer each triage question from alert fields. If a field is missing, answer "unknown"; do not guess.
2. Pick severity with the first rule that is true, top to bottom.
3. Take the steps in order. Skip a step only if its `if:` condition is false or the alert has none of the indicators it needs.
4. Replace each `{placeholder}` with the real indicator values from the alert.
5. Cite every line by step ID, e.g. `PB-PHISH-3.1`. Never add a step that is not listed below.
6. Sections 3 and 4 are actions: mark them "awaiting approval". Sections 2 and 5 are tasks.
7. If an indicator or a KEV required action has no step, report it as a playbook gap.

## Triage questions
- Did any recipient click a link? (fact: `clicked`)
- Were credentials entered on the linked page? (fact: `credentials_submitted`)
- Was an attachment opened or executed? (fact: `attachment_opened`)
- Is a finance or executive mailbox affected? (fact: `vip`)

## Severity
- **P1**: Credentials entered, attachment executed, or an executive/finance mailbox affected  (rule: `credentials_submitted or attachment_opened or vip`)
- **P2**: A recipient clicked a link but no credential entry is confirmed  (rule: `clicked`)
- **P3**: Delivered, no user interaction  (rule: `delivered`)
- **P4**: Blocked before delivery  (rule: `true`)

## Steps

### 2. Detect & Analyze
- `PB-PHISH-2.1` Retrieve the original message {message_id} and run a message trace to list every recipient.  _(needs message_id)_
- `PB-PHISH-2.2` Detonate the URLs {urls} in the sandbox and record the verdicts in the case.  _(needs urls)_
- `PB-PHISH-2.3` Review sign-in logs for {users} for 24 hours after delivery.  _(needs users)_

### 3. Contain  (needs approval)
- `PB-PHISH-3.1` Export message headers and the sandbox report to the case folder before any purge.
- `PB-PHISH-3.2` Purge message {message_id} from all mailboxes (soft delete).  _(needs message_id)_
- `PB-PHISH-3.3` Block sender {sender} and domain {sender_domain} at the mail gateway.  _(needs sender)_
- `PB-PHISH-3.4` Block {domains} at the web proxy and DNS resolver.  _(needs domains)_
- `PB-PHISH-3.5` Reset the password and revoke all sessions and refresh tokens for {users}.  _(only if `clicked`; needs users)_
- `PB-PHISH-3.6` Block outbound SMB (TCP 445) to the internet, including {ips}.  _(needs ips)_

### 4. Eradicate & Recover  (needs approval)
- `PB-PHISH-4.1` Check mailbox rules and forwarding for {users}; remove any the user did not create.  _(needs users)_
- `PB-PHISH-4.2` Confirm Outlook / Office build on affected endpoints and patch within the critical-vulnerability SLA (72 h).
- `PB-PHISH-4.3` Notify the affected users and send the phishing awareness reminder.

### 5. Post-Incident
- `PB-PHISH-5.1` Add sender, domains and URLs to the threat-intel platform as indicators.
- `PB-PHISH-5.2` Record the timeline (delivered, reported, purged, contained) in the incident ticket.

## Regulatory
If credentials of finance users were exposed, inform Legal within 24 hours (internal policy SEC-07).
