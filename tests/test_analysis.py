from onionlens.exporters.attack import map_techniques
from onionlens.processing.classifier import classify_keyword
from onionlens.processing.ioc import extract_iocs
from onionlens.processing.scoring import threat_score
from onionlens.processing.watchlist import WatchTerm, match_watchlist
from onionlens.safety import is_prohibited, redact


def test_classifier_categories():
    assert classify_keyword("Fresh combolist and leaked database dump, email:pass plaintext").category == "credential_leak"
    assert classify_keyword("Selling initial access, RDP with domain admin, revenue $50M").category == "access_broker"
    assert classify_keyword("Ransomware affiliate program, decryptor and leak site, double extortion").category == "ransomware"
    assert classify_keyword("New crypter, FUD, AV bypass, builder and C2 panel included").category == "malware"
    assert classify_keyword("Nice weather today, see you tomorrow").category == "other"


def test_classifier_is_explainable():
    c = classify_keyword("Working 0day exploit, unauthenticated RCE, PoC for CVE-2024-3400")
    assert c.category == "exploit"
    assert "exploit" in c.evidence


def test_watchlist_credential_hit_is_escalated():
    text = redact("dump: bob@acme.example:pass123 and alice@other.example:qwerty")
    iocs = extract_iocs(text)
    hits = match_watchlist(text, iocs, [WatchTerm("domain", "acme.example", "high")])
    assert len(hits) == 1 and hits[0].severity == "critical"


def test_watchlist_keyword_and_ip_range():
    text = "Selling access to Acme Industries, VPN gateway 203.0.113.17"
    iocs = extract_iocs(text)
    hits = match_watchlist(text, iocs, [WatchTerm("keyword", "Acme Industries"), WatchTerm("ip_range", "203.0.113.0/24")])
    kinds = {h.term.kind for h in hits}
    assert kinds == {"keyword", "ip_range"}


def test_score_bounds_and_ordering():
    benign = threat_score("other", 0.0, [], [])
    bad = threat_score("ransomware", 0.9, [], [])
    assert 0 <= benign < bad <= 100


def test_attack_mapping():
    t = map_techniques("access_broker", "RDP access with domain admin", has_cves=True)
    assert "T1650" in t and "T1021.001" in t and "T1588.006" in t


def test_safety_blocklist():
    assert is_prohibited("normal forum post about databases") is None
    assert is_prohibited("pthc archive") is not None


def test_classifier_accuracy_does_not_regress():
    from onionlens.evaluate import evaluate, load, split

    _, test = split(load())
    r = evaluate(test)
    assert r["accuracy"] >= 0.85, r["errors"]
    assert r["macro_f1"] >= 0.85
