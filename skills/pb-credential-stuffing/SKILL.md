---
name: pb-credential-stuffing
description: Approved credential stuffing response SOP (PB-CRED v1.4). Use when an alert matches "credential stuffing", "password spray", "brute force" or MITRE ATT&CK T1110.004, T1110.003. Returns cited steps only.
---

# Credential Stuffing Response (PB-CRED)

Source of truth: `playbooks/PB-CRED.md` · owner: Identity Security Engineer · approved by Head of IAM · last review 2026-09-21.

## When to use
- Automated login attempts using breached username/password pairs against an identity provider or app.
- Finding types: credential stuffing; password spray; brute force
- ATT&CK: T1110.004, T1110.003

## How to use
1. Answer each triage question from alert fields. If a field is missing, answer "unknown"; do not guess.
2. Pick severity with the first rule that is true, top to bottom.
3. Take the steps in order. Skip a step only if its `if:` condition is false or the alert has none of the indicators it needs.
4. Replace each `{placeholder}` with the real indicator values from the alert.
5. Cite every line by step ID, e.g. `PB-CRED-3.1`. Never add a step that is not listed below.
6. Sections 3 and 4 are actions: mark them "awaiting approval". Sections 2 and 5 are tasks.
7. If an indicator or a KEV required action has no step, report it as a playbook gap.

## Triage questions
- Did any sign-in from the attacking IPs succeed? (fact: `success`)
- Was a privileged account among them? (fact: `privileged_success`)
- Was MFA satisfied on a successful sign-in? (fact: `mfa_passed`)

## Severity
- **P1**: A privileged account signed in successfully  (rule: `privileged_success`)
- **P2**: One or more successful sign-ins from attacking IPs  (rule: `success`)
- **P3**: Failures only  (rule: `true`)

## Steps

### 2. Detect & Analyze
- `PB-CRED-2.1` Pull sign-in logs for the attack window and list successful sign-ins from {ips}.  _(needs ips)_
- `PB-CRED-2.2` Check MFA status and breach-corpus exposure for {users}.  _(needs users)_

### 3. Contain  (needs approval)
- `PB-CRED-3.1` Block {ips} with a conditional-access named location; add the ASN if IPs rotate.  _(needs ips)_
- `PB-CRED-3.2` Force a password reset and revoke all sessions for {users}.  _(only if `success`; needs users)_
- `PB-CRED-3.3` Require MFA re-registration for {users} and a compliant device for 7 days.  _(only if `success`; needs users)_
- `PB-CRED-3.4` Turn on bot protection / rate limiting for the targeted app ({app}).  _(needs app)_

### 4. Eradicate & Recover  (needs approval)
- `PB-CRED-4.1` Review activity of {users} since first success: inbox rules, OAuth grants, file downloads.  _(only if `success`; needs users)_
- `PB-CRED-4.2` Notify affected users and require a new unique password.

### 5. Post-Incident
- `PB-CRED-5.1` Report failures, successes and time-to-block in the incident ticket.

## Regulatory
Account takeover of a customer account: inform the Privacy Office the same business day.
