---
name: pb-public-s3-bucket
description: Approved public s3 bucket exposure SOP (PB-S3 v2.0). Use when an alert matches "Policy:S3/BucketPublicAccessGranted", "Policy:S3/BucketAnonymousAccessGranted", "Policy:S3/BucketBlockPublicAccessDisabled" or MITRE ATT&CK T1530. Returns cited steps only.
---

# Public S3 Bucket Exposure (PB-S3)

Source of truth: `playbooks/PB-S3.md` · owner: Cloud Security Engineer · approved by CISO · last review 2026-10-03.

## When to use
- An S3 bucket became publicly readable or writable, or its protections were switched off.
- Finding types: Policy:S3/BucketPublicAccessGranted; Policy:S3/BucketAnonymousAccessGranted; Policy:S3/BucketBlockPublicAccessDisabled; Stealth:S3/ServerAccessLoggingDisabled
- ATT&CK: T1530

## How to use
1. Answer each triage question from alert fields. If a field is missing, answer "unknown"; do not guess.
2. Pick severity with the first rule that is true, top to bottom.
3. Take the steps in order. Skip a step only if its `if:` condition is false or the alert has none of the indicators it needs.
4. Replace each `{placeholder}` with the real indicator values from the alert.
5. Cite every line by step ID, e.g. `PB-S3-3.1`. Never add a step that is not listed below.
6. Sections 3 and 4 are actions: mark them "awaiting approval". Sections 2 and 5 are tasks.
7. If an indicator or a KEV required action has no step, report it as a playbook gap.

## Triage questions
- Is the bucket publicly readable? (fact: `public_read`)
- Is the bucket tagged confidential / PII? (fact: `sensitive`)
- Did the change come from outside the corporate network? (fact: `external_ip`)

## Severity
- **P1**: Public read on a bucket tagged confidential or PII  (rule: `public_read and sensitive`)
- **P2**: Public access on a non-sensitive bucket  (rule: `public_read`)
- **P3**: Block Public Access or logging disabled only  (rule: `true`)

## Steps

### 2. Detect & Analyze
- `PB-S3-2.1` In CloudTrail, find who changed the policy: {principal} using key {access_keys}.  _(needs principal)_
- `PB-S3-2.2` Check S3 access logs for GetObject on {buckets} from outside the org since the change.  _(needs buckets)_

### 3. Contain  (needs approval)
- `PB-S3-3.1` Save a copy of the current bucket policy to the case folder (evidence).
- `PB-S3-3.2` Re-enable Block Public Access on {buckets}: aws s3api put-public-access-block --bucket <name> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true  _(needs buckets)_
- `PB-S3-3.3` Remove the public statement from the bucket policy of {buckets}.  _(needs buckets)_
- `PB-S3-3.4` Deactivate access key {access_keys} of {principal} and review its last 24 h of API calls.  _(needs access_keys)_

### 4. Eradicate & Recover  (needs approval)
- `PB-S3-4.1` Enforce account-level Block Public Access with an SCP.
- `PB-S3-4.2` If objects were downloaded and contain PII, hand over to Legal for notification.

### 5. Post-Incident
- `PB-S3-5.1` Add AWS Config rule s3-bucket-public-read-prohibited if missing.

## Regulatory
PII exposed: Legal assesses notification within 72 hours.
