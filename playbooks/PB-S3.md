---
id: PB-S3
title: "Public S3 Bucket Exposure"
version: "2.0"
status: Approved
owner: "Cloud Security Engineer"
approved_by: "CISO"
last_review: "2026-10-03"
review_interval_days: 180
attack: [T1530]
finding_types:
  - "Policy:S3/BucketPublicAccessGranted"
  - "Policy:S3/BucketAnonymousAccessGranted"
  - "Policy:S3/BucketBlockPublicAccessDisabled"
  - "Stealth:S3/ServerAccessLoggingDisabled"
severity:
  - level: P1
    when: "Public read on a bucket tagged confidential or PII"
    rule: "public_read and sensitive"
  - level: P2
    when: "Public access on a non-sensitive bucket"
    rule: "public_read"
  - level: P3
    when: "Block Public Access or logging disabled only"
    rule: "true"
triage:
  - question: "Is the bucket publicly readable?"
    fact: public_read
  - question: "Is the bucket tagged confidential / PII?"
    fact: sensitive
  - question: "Did the change come from outside the corporate network?"
    fact: external_ip
regulatory: "PII exposed: Legal assesses notification within 72 hours."
---

# Public S3 Bucket Exposure (PB-S3 v2.0)

> Approved standard operating procedure. Step IDs are stable: cite them in tickets and reviews.

## 1. Overview

An S3 bucket became publicly readable or writable, or its protections were switched off.

**Applies to findings:** Policy:S3/BucketPublicAccessGranted; Policy:S3/BucketAnonymousAccessGranted; Policy:S3/BucketBlockPublicAccessDisabled; Stealth:S3/ServerAccessLoggingDisabled  
**MITRE ATT&CK:** T1530

### Severity classification

| Level | Criteria |
| --- | --- |
| P1 | Public read on a bucket tagged confidential or PII |
| P2 | Public access on a non-sensitive bucket |
| P3 | Block Public Access or logging disabled only |

### Initial triage questions

- [ ] Is the bucket publicly readable?
- [ ] Is the bucket tagged confidential / PII?
- [ ] Did the change come from outside the corporate network?

## 2. Detect & Analyze

- **PB-S3-2.1** In CloudTrail, find who changed the policy: {principal} using key {access_keys}. <!-- needs: principal -->
- **PB-S3-2.2** Check S3 access logs for GetObject on {buckets} from outside the org since the change. <!-- needs: buckets -->

## 3. Contain

- **PB-S3-3.1** Save a copy of the current bucket policy to the case folder (evidence). <!-- tags: evidence -->
- **PB-S3-3.2** Re-enable Block Public Access on {buckets}: aws s3api put-public-access-block --bucket <name> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true <!-- needs: buckets -->
- **PB-S3-3.3** Remove the public statement from the bucket policy of {buckets}. <!-- needs: buckets -->
- **PB-S3-3.4** Deactivate access key {access_keys} of {principal} and review its last 24 h of API calls. <!-- needs: access_keys | tags: credential_reset -->

## 4. Eradicate & Recover

- **PB-S3-4.1** Enforce account-level Block Public Access with an SCP.
- **PB-S3-4.2** If objects were downloaded and contain PII, hand over to Legal for notification.

## 5. Post-Incident

- **PB-S3-5.1** Add AWS Config rule s3-bucket-public-read-prohibited if missing.

## Appendix B. Regulatory and notification

PII exposed: Legal assesses notification within 72 hours.

## Revision history

| Version | Date | Change |
| --- | --- | --- |
| 2.0 | 2026-10-03 | Last approved review |
