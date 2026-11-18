"""Alert log parser: vendor JSON -> one common shape, IoCs and attack classification.

Supports AWS GuardDuty findings, Microsoft Sentinel SecurityAlert rows and Wazuh alerts.
Anything else goes through a generic parser that relies on the regex sweep only.
"""
from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field

ATTACK_NAMES = {
    "T1486": "Data Encrypted for Impact", "T1490": "Inhibit System Recovery", "T1566": "Phishing",
    "T1566.001": "Spearphishing Attachment", "T1566.002": "Spearphishing Link", "T1110": "Brute Force",
    "T1110.003": "Password Spraying", "T1110.004": "Credential Stuffing", "T1530": "Data from Cloud Storage",
    "T1498": "Network Denial of Service", "T1499": "Endpoint Denial of Service", "T1499.002": "Service Exhaustion Flood",
    "T1190": "Exploit Public-Facing Application", "T1187": "Forced Authentication", "T1550.004": "Web Session Cookie",
}
CATEGORY_BY_TECHNIQUE = [
    ("T1486", "Ransomware"), ("T1566", "Phishing"), ("T1110", "Credential Stuffing"),
    ("T1530", "Cloud Storage Exposure"), ("T1498", "Denial of Service"), ("T1499", "Denial of Service"),
]
CATEGORY_BY_KEYWORD = [
    (r"ransom|encrypt|lockbit", "Ransomware"), (r"phish|malicious email|reported by user", "Phishing"),
    (r"credential stuffing|password spray|brute", "Credential Stuffing"), (r"s3|bucket", "Cloud Storage Exposure"),
    (r"ddos|denial of service|flood|rapid reset", "Denial of Service"),
]
# GuardDuty has no ATT&CK field: map finding-type prefixes to techniques.
GUARDDUTY_ATTACK = {"Policy:S3/": ["T1530"], "Stealth:S3/": ["T1530"], "UnauthorizedAccess:S3/": ["T1530"]}

RE_IPV4 = re.compile(r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b")
RE_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b")
RE_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
RE_URL = re.compile(r"\b(?:https?|file)://[^\s\"'<>]+")
RE_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")

IOC_TYPES = ["users", "hosts", "ips", "internal_ips", "domains", "urls", "hashes", "files", "sender", "sender_domain",
             "message_id", "buckets", "access_keys", "principal", "cves", "app", "user_agent"]


@dataclass
class NormalizedAlert:
    source: str
    alert_id: str
    title: str
    first_seen: str
    last_seen: str
    finding_type: str
    vendor_severity: str
    attack: list[str]
    attack_source: str
    category: str = "Unknown"
    entities: dict = field(default_factory=lambda: {k: [] for k in IOC_TYPES})
    origin: dict = field(default_factory=dict)
    facts: dict = field(default_factory=dict)
    evidence: dict = field(default_factory=dict)
    raw: dict = field(default_factory=dict)

    def add(self, kind: str, value, where: str) -> None:
        if not value:
            return
        value = str(value)
        if value not in self.entities[kind]:
            self.entities[kind].append(value)
            self.origin[f"{kind}|{value}"] = where

    @property
    def attack_labels(self) -> list[str]:
        return [f"{t} {ATTACK_NAMES.get(t, '')}".strip() for t in self.attack]

    def iocs(self) -> list[tuple[str, str, str]]:
        return [(k, v, self.origin.get(f"{k}|{v}", "")) for k in IOC_TYPES for v in self.entities[k]]


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private and not ipaddress.ip_address(ip) in ipaddress.ip_network("192.0.2.0/24") \
            and not ipaddress.ip_address(ip) in ipaddress.ip_network("198.51.100.0/24") \
            and not ipaddress.ip_address(ip) in ipaddress.ip_network("203.0.113.0/24")
    except ValueError:
        return False


def _loads(value, default):
    if isinstance(value, (list, dict)):
        return value
    try:
        return json.loads(value) if value else default
    except (TypeError, ValueError):
        return default


def _host(url: str) -> str | None:
    m = re.match(r"^[a-z]+://([^/:?#]+)", url, re.I)
    return m.group(1) if m else None


def detect_source(raw: dict) -> str:
    if "schemaVersion" in raw and "service" in raw and "type" in raw:
        return "AWS GuardDuty"
    if "SystemAlertId" in raw and "AlertName" in raw:
        return "Microsoft Sentinel"
    if "rule" in raw and "agent" in raw:
        return "Wazuh"
    return "Generic JSON"


# ---------------------------------------------------------------- per vendor
def _guardduty(raw: dict) -> NormalizedAlert:
    svc = raw.get("service", {})
    bucket = (raw.get("resource", {}).get("s3BucketDetails") or [{}])[0]
    key = raw.get("resource", {}).get("accessKeyDetails", {})
    call = svc.get("action", {}).get("awsApiCallAction", {})
    ip = call.get("remoteIpDetails", {}).get("ipAddressV4")
    sev = raw.get("severity", 0)
    ftype = raw.get("type", "")
    attack = next((v for k, v in GUARDDUTY_ATTACK.items() if ftype.startswith(k)), [])
    n = NormalizedAlert(
        source="AWS GuardDuty", alert_id=raw.get("id", ""), title=raw.get("title", ftype),
        first_seen=svc.get("eventFirstSeen", raw.get("createdAt", "")), last_seen=svc.get("eventLastSeen", raw.get("updatedAt", "")),
        finding_type=ftype, vendor_severity=f"{sev}/10 ({'High' if sev >= 7 else 'Medium' if sev >= 4 else 'Low'})",
        attack=attack, attack_source="inferred from GuardDuty finding type", raw=raw)
    n.add("buckets", bucket.get("name"), "resource.s3BucketDetails[0].name")
    n.add("access_keys", key.get("accessKeyId"), "resource.accessKeyDetails.accessKeyId")
    n.add("principal", key.get("userName"), "resource.accessKeyDetails.userName")
    n.add("ips", ip, "service.action.awsApiCallAction.remoteIpDetails.ipAddressV4")
    tags = [str(t.get("value", "")).lower() for t in bucket.get("tags", [])]
    policy = bucket.get("publicAccess", {}).get("permissionConfiguration", {}).get("bucketLevelPermissions", {}).get("bucketPolicy", {})
    n.facts = {"public_read": bool(policy.get("allowsPublicReadAccess")),
               "sensitive": any(re.search(r"confidential|pii|restricted", t) for t in tags),
               "external_ip": bool(ip) and not _is_private(ip)}
    n.evidence = {"public_read": f"bucketPolicy.allowsPublicReadAccess = {policy.get('allowsPublicReadAccess')}",
                  "sensitive": f"bucket tags = {', '.join(tags) or 'none'}",
                  "external_ip": f"caller IP {ip} ({call.get('remoteIpDetails', {}).get('country', {}).get('countryName', '?')})"}
    return n


def _sentinel(raw: dict) -> NormalizedAlert:
    ents = _loads(raw.get("Entities"), [])
    ext = _loads(raw.get("ExtendedProperties"), {})
    tech = list(dict.fromkeys(_loads(raw.get("Techniques"), []) + _loads(raw.get("SubTechniques"), [])))
    n = NormalizedAlert(
        source="Microsoft Sentinel", alert_id=raw.get("SystemAlertId", ""), title=raw.get("AlertName", ""),
        first_seen=raw.get("StartTime") or raw.get("TimeGenerated", ""), last_seen=raw.get("EndTime") or raw.get("TimeGenerated", ""),
        finding_type=raw.get("AlertName", ""), vendor_severity=raw.get("AlertSeverity", ""), attack=tech,
        attack_source="Techniques / SubTechniques fields", raw=raw)
    for e in ents:
        t = e.get("Type")
        if t == "mailbox":
            n.add("users", e.get("MailboxPrimaryAddress"), "Entities[mailbox].MailboxPrimaryAddress")
        elif t == "account":
            n.add("users", f"{e.get('Name')}@{e.get('UPNSuffix')}", "Entities[account].Name + UPNSuffix")
        elif t == "ip":
            n.add("ips", e.get("Address"), "Entities[ip].Address")
        elif t == "url":
            n.add("urls", e.get("Url"), "Entities[url].Url")
            h = _host(e.get("Url", ""))
            if h and not RE_IPV4.fullmatch(h):
                n.add("domains", h, "host of Entities[url].Url")
        elif t == "mailMessage":
            n.add("sender", e.get("Sender"), "Entities[mailMessage].Sender")
            n.add("sender_domain", (e.get("Sender") or "@").split("@")[1], "domain of Sender")
            n.add("message_id", e.get("InternetMessageId"), "Entities[mailMessage].InternetMessageId")
    n.add("app", ext.get("Application"), "ExtendedProperties.Application")
    n.add("user_agent", ext.get("UserAgent"), "ExtendedProperties.UserAgent")
    if re.search(r"phish", n.title, re.I):
        cred = ext.get("Credentials submitted")
        n.facts = {"delivered": ext.get("Delivery action") == "Delivered", "clicked": ext.get("Clicked") == "true",
                   "credentials_submitted": True if cred == "true" else False if cred == "false" else None,
                   "attachment_opened": ext.get("Attachment opened") == "true",
                   "vip": bool(re.search(r"finance|exec", ext.get("Department", ""), re.I))}
        n.evidence = {k: f"ExtendedProperties: {v}" for k, v in {
            "clicked": f"Clicked = {ext.get('Clicked')}", "credentials_submitted": f"Credentials submitted = {cred}",
            "attachment_opened": f"Attachment opened = {ext.get('Attachment opened')}", "vip": f"Department = {ext.get('Department')}",
            "delivered": f"Delivery action = {ext.get('Delivery action')}"}.items()}
    else:
        succ = int(ext.get("SuccessfulSignIns", "0") or 0)
        priv = any(e.get("Type") == "account" and e.get("IsPrivileged") for e in ents)
        n.facts = {"success": succ > 0, "privileged_success": succ > 0 and priv, "mfa_passed": ext.get("MfaSatisfied") == "true"}
        n.evidence = {"success": f"ExtendedProperties.SuccessfulSignIns = {succ}",
                      "privileged_success": f"Entities[account].IsPrivileged = {priv}",
                      "mfa_passed": f"ExtendedProperties.MfaSatisfied = {ext.get('MfaSatisfied')}"}
    return n


def _wazuh(raw: dict) -> NormalizedAlert:
    rule, agent = raw.get("rule", {}), raw.get("agent", {})
    data = raw.get("data", {})
    corr, proc = data.get("correlation", {}), data.get("process", {})
    sysc = raw.get("syscheck", {})
    n = NormalizedAlert(
        source="Wazuh", alert_id=raw.get("id", ""), title=rule.get("description", ""), first_seen=raw.get("timestamp", ""),
        last_seen=raw.get("timestamp", ""), finding_type=rule.get("description", ""),
        vendor_severity=f"rule.level {rule.get('level')}/15", attack=list(rule.get("mitre", {}).get("id", [])),
        attack_source="rule.mitre.id", raw=raw)
    n.add("hosts", agent.get("name"), "agent.name")
    n.add("internal_ips", agent.get("ip"), "agent.ip")
    n.add("hosts", corr.get("initial_access_suspect"), "data.correlation.initial_access_suspect")
    n.add("ips", corr.get("src_ip"), "data.correlation.src_ip")
    n.add("hashes", proc.get("sha256"), "data.process.sha256")
    n.add("hashes", sysc.get("sha256_after"), "syscheck.sha256_after")
    n.add("files", sysc.get("path"), "syscheck.path")
    note = re.search(r"Ransom note (\S+?)\.? created", raw.get("full_log", ""))
    if note:
        n.add("files", note.group(1), "full_log (regex)")
    n.add("cves", corr.get("vulnerability.cve"), "data.correlation.vulnerability.cve")
    groups = rule.get("groups", [])
    n.facts = {"encryption_confirmed": "ransomware" in groups and "renamed" in raw.get("full_log", ""),
               "server": bool(re.match(r"^(FS|SRV|DC)-", agent.get("name", ""), re.I)), "multi_host": False,
               "kev_initial_access": bool(corr.get("vulnerability.cve"))}
    n.evidence = {"encryption_confirmed": "rule.groups contains 'ransomware' and full_log shows renamed files",
                  "server": f"agent.name = {agent.get('name')} (FS- prefix = file server)",
                  "kev_initial_access": f"data.correlation.vulnerability.cve = {corr.get('vulnerability.cve', 'none')}"}
    return n


def _generic(raw: dict) -> NormalizedAlert:
    title = str(raw.get("title") or raw.get("name") or raw.get("description") or "Uploaded alert")
    return NormalizedAlert(source="Generic JSON", alert_id=str(raw.get("id", "")), title=title, first_seen=str(raw.get("timestamp", "")),
                           last_seen=str(raw.get("timestamp", "")), finding_type=title, vendor_severity=str(raw.get("severity", "unknown")),
                           attack=[t for t in re.findall(r"\bT\d{4}(?:\.\d{3})?\b", json.dumps(raw))], attack_source="regex", raw=raw)


def _classify(n: NormalizedAlert) -> str:
    for prefix, cat in CATEGORY_BY_TECHNIQUE:
        if any(t == prefix or t.startswith(prefix + ".") for t in n.attack):
            return cat
    text = f"{n.finding_type} {n.title}".lower()
    return next((cat for pat, cat in CATEGORY_BY_KEYWORD if re.search(pat, text)), "Unknown")


def parse_alert(raw: dict) -> NormalizedAlert:
    """Parse one alert. Vendor parser first, then a regex sweep over the whole JSON."""
    source = detect_source(raw)
    n = {"AWS GuardDuty": _guardduty, "Microsoft Sentinel": _sentinel, "Wazuh": _wazuh}.get(source, _generic)(raw)
    text = json.dumps(raw)
    for cve in RE_CVE.findall(text):
        n.add("cves", cve, "regex over raw alert")
    if source == "Generic JSON":
        for ip in RE_IPV4.findall(text):
            n.add("internal_ips" if _is_private(ip) else "ips", ip, "regex over raw alert")
        for h in RE_SHA256.findall(text):
            n.add("hashes", h.lower(), "regex over raw alert")
        for u in RE_URL.findall(text):
            n.add("urls", u, "regex over raw alert")
        for e in RE_EMAIL.findall(text):
            n.add("users", e, "regex over raw alert")
    n.category = _classify(n)
    return n
