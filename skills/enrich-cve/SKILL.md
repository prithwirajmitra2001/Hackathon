---
name: enrich-cve
description: Look up CVEs from an alert in data/cve_feed.json and set priority with the ladder CISA KEV → EPSS → SSVC → CVSS; find related advisories by hybrid search when the alert names no CVE.
---

# Enrich CVE

Code: `socpilot/cve.py` → `prioritize()`, `socpilot/kb.py` → `related_cves()`

## Exact lookup (alert names a CVE ID)
Look the ID up by key in the feed: no similarity search, because vectors are bad at exact codes.

## Priority ladder (first signal that fires decides)
| Rung | Fires when | Priority |
|---|---|---|
| CISA KEV | listed (known exploited) | P1 ("and used in ransomware" if `known_ransomware_use = Known`) |
| EPSS | percentile ≥ 0.95 | P2 |
| SSVC | exploitation `poc`/`active` or automatable `yes` | P3 |
| CVSS | always | P3 if ≥ 9.0, else P4 |

Always output the full ladder and which rung decided.

## Related advisories (alert names no CVE)
Hybrid search over advisories. Keep a hit only if it is top-3 in **both** semantic and BM25 search **and** shares an ATT&CK technique family with the alert. These are context only: they never set priority.

## Feed record shape
`cve_id, nickname, title, description, vendor, product, cwe[], cvss_v31{base_score,severity,source}, kev{listed,date_added,due_date,known_ransomware_use,required_action}, epss{score,percentile,date}, ssvc{exploitation,automatable,technical_impact}, attack[], response_tags[]`
