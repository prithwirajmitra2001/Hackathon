---
name: extract-iocs
description: Extract indicators of compromise (IPs, domains, URLs, hashes, users, hosts, files, buckets, access keys, CVE IDs, user agents) from a parsed alert, recording the field each came from.
---

# Extract IoCs

Code: `socpilot/alert_parser.py` (vendor parsers + regex sweep)

## Steps
1. Take structured values from vendor fields first (e.g. `Entities[ip].Address`, `resource.s3BucketDetails[0].name`).
2. Then sweep the whole raw JSON with regex for CVE IDs (`CVE-\d{4}-\d{4,7}`); for generic alerts also IPv4, SHA-256, URLs and e-mail addresses.
3. Record the origin of every value (`origin[type|value] = field path`) so the analyst can verify it.
4. Split IPs: private ranges go to `internal_ips` (never blocked); external ones go to `ips`.
5. De-duplicate; keep first-seen order.

## Output types
`users, hosts, ips, internal_ips, domains, urls, hashes, files, sender, sender_domain, message_id, buckets, access_keys, principal, cves, app, user_agent`
