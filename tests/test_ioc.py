import random

from onionlens.collectors.demo import fake_btc
from onionlens.processing.ioc import extract_iocs, valid_bech32, valid_btc_base58
from onionlens.safety import redact


def types(text):
    return {(i.type, i.value) for i in extract_iocs(text)}


def test_btc_validation():
    assert valid_btc_base58("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")  # genesis address
    assert not valid_btc_base58("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb")
    assert valid_bech32("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq")
    assert valid_btc_base58(fake_btc(random.Random(1)))


def test_extracts_core_types():
    text = (
        "Contact jabber: seller@exploit.im, payment 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa. "
        "Mirror: http://" + "a" * 56 + ".onion/ . Exploit for CVE-2024-3400 hosted at 8.8.8.8 and evil-site.ru. "
        "Hash 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 Posted by DarkSeller"
    )
    t = types(text)
    assert ("jabber", "seller@exploit.im") in t
    assert ("btc_address", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa") in t
    assert ("onion", "a" * 56 + ".onion") in t
    assert ("cve", "CVE-2024-3400") in t
    assert ("ipv4", "8.8.8.8") in t
    assert ("domain", "evil-site.ru") in t
    assert ("handle", "DarkSeller") in t
    assert any(k == "sha256" for k, _ in t)
    # jabber id must not double as an email
    assert not any(k == "email" and "exploit.im" in v for k, v in t)


def test_private_ips_ignored():
    assert not any(k == "ipv4" for k, _ in types("internal host 10.0.0.5 and 192.168.1.1"))


def test_credentials_are_masked_end_to_end():
    raw = "john.doe@acme.example:Summer2024!\nmaria@acme.example | hunter22"
    red = redact(raw)
    assert "Summer2024!" not in red and "hunter22" not in red
    iocs = extract_iocs(red)
    creds = [i for i in iocs if i.type == "credential"]
    assert len(creds) == 2
    assert all(i.value.startswith(("j***@", "m***@")) for i in creds)
    assert all(i.context == "acme.example" for i in creds)


def test_cards_masked():
    red = redact("card 4111 1111 1111 1111 exp 12/29")
    assert "4111 1111 1111 1111" not in red
    assert ("card", "411111******1111") in types(red)


def test_non_luhn_number_untouched():
    assert redact("order 1234567890123") == "order 1234567890123"
