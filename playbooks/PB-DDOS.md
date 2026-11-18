---
id: PB-DDOS
title: "DDoS Response"
version: "1.1"
status: Approved
owner: "Network Operations Lead"
approved_by: "CTO"
last_review: "2026-03-30"
review_interval_days: 180
attack: [T1498, T1499]
finding_types:
  - "ddos"
  - "traffic spike"
  - "http flood"
severity:
  - level: P1
    when: "Customer-facing service down more than 5 minutes"
    rule: "outage"
  - level: P2
    when: "Degraded latency or error rate above SLO"
    rule: "true"
triage:
  - question: "Is a customer-facing service down?"
    fact: outage
  - question: "Is traffic HTTP/2 with abnormal stream resets?"
    fact: http2_resets
regulatory: "None by default; check customer SLA credits."
---

# DDoS Response (PB-DDOS v1.1)

> Approved standard operating procedure. Step IDs are stable: cite them in tickets and reviews.

## 1. Overview

Volumetric or application-layer denial of service against public services.

**Applies to findings:** ddos; traffic spike; http flood  
**MITRE ATT&CK:** T1498, T1499

### Severity classification

| Level | Criteria |
| --- | --- |
| P1 | Customer-facing service down more than 5 minutes |
| P2 | Degraded latency or error rate above SLO |

### Initial triage questions

- [ ] Is a customer-facing service down?
- [ ] Is traffic HTTP/2 with abnormal stream resets?

## 2. Detect & Analyze

- **PB-DDOS-2.1** Compare traffic to the 7-day baseline; identify the target endpoint and protocol.

## 3. Contain

- **PB-DDOS-3.1** Engage the CDN / scrubbing provider and switch the target to always-on mitigation.
- **PB-DDOS-3.2** Apply rate-based WAF rules and geo or ASN blocks for {ips}. <!-- needs: ips | tags: rate_limit -->
- **PB-DDOS-3.3** For HTTP/2 Rapid Reset, apply server patches and cap concurrent stream resets. <!-- tags: patch_server -->

## 4. Eradicate & Recover

- **PB-DDOS-4.1** Scale back mitigation once traffic is at baseline for 1 hour.

## 5. Post-Incident

- **PB-DDOS-5.1** Publish the status-page post-mortem within 3 business days.

## Appendix B. Regulatory and notification

None by default; check customer SLA credits.

## Revision history

| Version | Date | Change |
| --- | --- | --- |
| 1.1 | 2026-03-30 | Last approved review |
