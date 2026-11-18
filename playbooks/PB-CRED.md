---
id: PB-CRED
title: "Credential Stuffing Response"
version: "1.4"
status: Approved
owner: "Identity Security Engineer"
approved_by: "Head of IAM"
last_review: "2026-09-21"
review_interval_days: 180
attack: [T1110.004, T1110.003]
finding_types:
  - "credential stuffing"
  - "password spray"
  - "brute force"
severity:
  - level: P1
    when: "A privileged account signed in successfully"
    rule: "privileged_success"
  - level: P2
    when: "One or more successful sign-ins from attacking IPs"
    rule: "success"
  - level: P3
    when: "Failures only"
    rule: "true"
triage:
  - question: "Did any sign-in from the attacking IPs succeed?"
    fact: success
  - question: "Was a privileged account among them?"
    fact: privileged_success
  - question: "Was MFA satisfied on a successful sign-in?"
    fact: mfa_passed
regulatory: "Account takeover of a customer account: inform the Privacy Office the same business day."
---

# Credential Stuffing Response (PB-CRED v1.4)

> Approved standard operating procedure. Step IDs are stable: cite them in tickets and reviews.

## 1. Overview

Automated login attempts using breached username/password pairs against an identity provider or app.

**Applies to findings:** credential stuffing; password spray; brute force  
**MITRE ATT&CK:** T1110.004, T1110.003

### Severity classification

| Level | Criteria |
| --- | --- |
| P1 | A privileged account signed in successfully |
| P2 | One or more successful sign-ins from attacking IPs |
| P3 | Failures only |

### Initial triage questions

- [ ] Did any sign-in from the attacking IPs succeed?
- [ ] Was a privileged account among them?
- [ ] Was MFA satisfied on a successful sign-in?

## 2. Detect & Analyze

- **PB-CRED-2.1** Pull sign-in logs for the attack window and list successful sign-ins from {ips}. <!-- needs: ips -->
- **PB-CRED-2.2** Check MFA status and breach-corpus exposure for {users}. <!-- needs: users -->

## 3. Contain

- **PB-CRED-3.1** Block {ips} with a conditional-access named location; add the ASN if IPs rotate. <!-- needs: ips -->
- **PB-CRED-3.2** Force a password reset and revoke all sessions for {users}. <!-- needs: users | if: success | tags: credential_reset, session_revocation -->
- **PB-CRED-3.3** Require MFA re-registration for {users} and a compliant device for 7 days. <!-- needs: users | if: success -->
- **PB-CRED-3.4** Turn on bot protection / rate limiting for the targeted app ({app}). <!-- needs: app | tags: rate_limit -->

## 4. Eradicate & Recover

- **PB-CRED-4.1** Review activity of {users} since first success: inbox rules, OAuth grants, file downloads. <!-- needs: users | if: success -->
- **PB-CRED-4.2** Notify affected users and require a new unique password.

## 5. Post-Incident

- **PB-CRED-5.1** Report failures, successes and time-to-block in the incident ticket.

## Appendix B. Regulatory and notification

Account takeover of a customer account: inform the Privacy Office the same business day.

## Revision history

| Version | Date | Change |
| --- | --- | --- |
| 1.4 | 2026-09-21 | Last approved review |
