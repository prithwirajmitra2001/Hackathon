---
name: pb-ddos
description: Approved ddos response SOP (PB-DDOS v1.1). Use when an alert matches "ddos", "traffic spike", "http flood" or MITRE ATT&CK T1498, T1499. Returns cited steps only.
---

# DDoS Response (PB-DDOS)

Source of truth: `playbooks/PB-DDOS.md` · owner: Network Operations Lead · approved by CTO · last review 2026-03-30.

## When to use
- Volumetric or application-layer denial of service against public services.
- Finding types: ddos; traffic spike; http flood
- ATT&CK: T1498, T1499

## How to use
1. Answer each triage question from alert fields. If a field is missing, answer "unknown"; do not guess.
2. Pick severity with the first rule that is true, top to bottom.
3. Take the steps in order. Skip a step only if its `if:` condition is false or the alert has none of the indicators it needs.
4. Replace each `{placeholder}` with the real indicator values from the alert.
5. Cite every line by step ID, e.g. `PB-DDOS-3.1`. Never add a step that is not listed below.
6. Sections 3 and 4 are actions: mark them "awaiting approval". Sections 2 and 5 are tasks.
7. If an indicator or a KEV required action has no step, report it as a playbook gap.

## Triage questions
- Is a customer-facing service down? (fact: `outage`)
- Is traffic HTTP/2 with abnormal stream resets? (fact: `http2_resets`)

## Severity
- **P1**: Customer-facing service down more than 5 minutes  (rule: `outage`)
- **P2**: Degraded latency or error rate above SLO  (rule: `true`)

## Steps

### 2. Detect & Analyze
- `PB-DDOS-2.1` Compare traffic to the 7-day baseline; identify the target endpoint and protocol.

### 3. Contain  (needs approval)
- `PB-DDOS-3.1` Engage the CDN / scrubbing provider and switch the target to always-on mitigation.
- `PB-DDOS-3.2` Apply rate-based WAF rules and geo or ASN blocks for {ips}.  _(needs ips)_
- `PB-DDOS-3.3` For HTTP/2 Rapid Reset, apply server patches and cap concurrent stream resets.

### 4. Eradicate & Recover  (needs approval)
- `PB-DDOS-4.1` Scale back mitigation once traffic is at baseline for 1 hour.

### 5. Post-Incident
- `PB-DDOS-5.1` Publish the status-page post-mortem within 3 business days.

## Regulatory
None by default; check customer SLA credits.
