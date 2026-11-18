"""CVE intelligence: exact lookup by ID and the priority ladder KEV -> EPSS -> SSVC -> CVSS."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class CveIntel:
    cve_id: str
    record: dict | None
    priority: str
    reason: str
    ladder: list[dict] = field(default_factory=list)
    how_found: str = "exact ID in alert"


def prioritize(cve_id: str, feed: dict, how_found: str = "exact ID in alert") -> CveIntel:
    rec = feed["by_id"].get(cve_id)
    if rec is None:
        return CveIntel(cve_id, None, "P3", "Not in the local feed: verify manually before acting", [], how_found)
    ladder, priority, reason = [], None, None
    kev = rec.get("kev", {})
    if kev.get("listed"):
        ransom = kev.get("known_ransomware_use") == "Known"
        ladder.append({"signal": "CISA KEV", "decided": True,
                       "detail": f"Listed {kev['date_added']}, federal due {kev['due_date']}, ransomware use: {kev.get('known_ransomware_use')}"})
        priority = "P1"
        reason = "Known exploited (CISA KEV)" + (" and used in ransomware campaigns" if ransom else "")
    else:
        ladder.append({"signal": "CISA KEV", "decided": False, "detail": "Not listed"})
    ep = rec.get("epss", {})
    hit = priority is None and ep.get("percentile", 0) >= 0.95
    ladder.append({"signal": "EPSS", "decided": hit,
                   "detail": f"{ep.get('score', 0) * 100:.1f}% chance of exploitation in 30 days ({ep.get('percentile', 0) * 100:.1f}th percentile, {ep.get('date')})"})
    if hit:
        priority, reason = "P2", "Not in KEV, but EPSS is in the top 5%"
    ss = rec.get("ssvc", {})
    hit = priority is None and (ss.get("exploitation") in ("poc", "active") or ss.get("automatable") == "yes")
    ladder.append({"signal": "SSVC", "decided": hit,
                   "detail": f"Exploitation {ss.get('exploitation')}, automatable {ss.get('automatable')}, technical impact {ss.get('technical_impact')}"})
    if hit:
        priority, reason = "P3", "SSVC shows exploitation evidence"
    cv = rec.get("cvss_v31", {})
    hit = priority is None
    ladder.append({"signal": "CVSS", "decided": hit, "detail": f"{cv.get('base_score')} {cv.get('severity')} ({cv.get('source')})"})
    if hit:
        priority = "P3" if (cv.get("base_score") or 0) >= 9 else "P4"
        reason = "Only a CVSS score is available"
    return CveIntel(cve_id, rec, priority, reason, ladder, how_found)


def cve_document(rec: dict) -> str:
    """Text that goes into the vector store and BM25 index for one CVE advisory."""
    kev = rec.get("kev", {})
    return (f"{rec['cve_id']} {rec.get('nickname', '')}. {rec.get('title', '')}. {rec.get('description', '')} "
            f"Vendor {rec.get('vendor', '')}, product {rec.get('product', '')}. ATT&CK {' '.join(rec.get('attack', []))}. "
            f"KEV required action: {kev.get('required_action', 'not listed')}")
