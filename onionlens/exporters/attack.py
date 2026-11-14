"""Map content categories and signals to MITRE ATT&CK techniques (Enterprise matrix)."""

from __future__ import annotations

TECHNIQUES = {
    "T1078": ("Valid Accounts", "initial-access"),
    "T1589.001": ("Gather Victim Identity Information: Credentials", "reconnaissance"),
    "T1597.002": ("Search Closed Sources: Purchase Technical Data", "reconnaissance"),
    "T1486": ("Data Encrypted for Impact", "impact"),
    "T1567": ("Exfiltration Over Web Service", "exfiltration"),
    "T1657": ("Financial Theft", "impact"),
    "T1588.001": ("Obtain Capabilities: Malware", "resource-development"),
    "T1588.002": ("Obtain Capabilities: Tool", "resource-development"),
    "T1588.005": ("Obtain Capabilities: Exploits", "resource-development"),
    "T1588.006": ("Obtain Capabilities: Vulnerabilities", "resource-development"),
    "T1190": ("Exploit Public-Facing Application", "initial-access"),
    "T1133": ("External Remote Services", "initial-access"),
    "T1021.001": ("Remote Services: Remote Desktop Protocol", "lateral-movement"),
    "T1650": ("Acquire Access", "resource-development"),
    "T1566": ("Phishing", "initial-access"),
    "T1583.005": ("Acquire Infrastructure: Botnet", "resource-development"),
    "T1498": ("Network Denial of Service", "impact"),
    "T1555": ("Credentials from Password Stores", "credential-access"),
    "T1539": ("Steal Web Session Cookie", "credential-access"),
}

_CATEGORY_MAP = {
    "credential_leak": ["T1078", "T1589.001", "T1597.002"],
    "ransomware": ["T1486", "T1567", "T1657"],
    "malware": ["T1588.001"],
    "exploit": ["T1588.005", "T1588.006", "T1190"],
    "access_broker": ["T1650", "T1133", "T1078"],
    "fraud": ["T1657", "T1566"],
    "hacking_services": ["T1588.002"],
}

_KEYWORD_MAP = {
    "rdp": ["T1021.001", "T1133"],
    "phishing": ["T1566"],
    "botnet": ["T1583.005"],
    "ddos": ["T1498"],
    "stealer": ["T1555", "T1539"],
    "cookies": ["T1539"],
    "vpn": ["T1133"],
}


def map_techniques(category: str, text: str, has_cves: bool = False) -> list[str]:
    ids = list(_CATEGORY_MAP.get(category, []))
    low = text.lower()
    for kw, techs in _KEYWORD_MAP.items():
        if kw in low:
            ids.extend(techs)
    if has_cves:
        ids.append("T1588.006")
    seen: list[str] = []
    for t in ids:
        if t not in seen:
            seen.append(t)
    return seen


def describe(tid: str) -> dict:
    name, tactic = TECHNIQUES.get(tid, (tid, "unknown"))
    url = "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"
    return {"id": tid, "name": name, "tactic": tactic, "url": url}
