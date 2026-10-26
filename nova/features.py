"""Lexical feature extraction for domain names (no network access needed)."""
from __future__ import annotations

import math
import re
from collections import Counter

import numpy as np

BRANDS = ("paypal", "google", "facebook", "microsoft", "apple", "amazon", "netflix",
          "instagram", "whatsapp", "twitter", "linkedin", "dropbox", "binance", "coinbase",
          "bank", "cib", "nbe", "vodafone", "etisalat", "orange", "fawry")
KEYWORDS = ("login", "signin", "secure", "verify", "account", "update", "confirm", "wallet",
            "billing", "support", "password", "free", "bonus", "gift", "prize", "recover",
            "unlock", "suspend", "alert", "invoice")
SUSPICIOUS_TLDS = frozenset({"xyz", "top", "click", "tk", "ml", "ga", "cf", "gq", "icu", "buzz",
                             "work", "zip", "cyou", "monster", "rest", "sbs", "quest", "cfd"})
SECOND_LEVEL = frozenset({"co", "com", "net", "org", "gov", "edu", "ac", "or", "ne", "go"})

IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
VALID_RE = re.compile(r"^(?=.{3,253}$)[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?"
                      r"(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)*$")
CONS_RE = re.compile(r"[bcdfghjklmnpqrstvwxyz]+")
DIGIT_RE = re.compile(r"\d+")


def normalize(raw: str) -> str:
    """Lower-case and strip scheme / path / port / credentials / trailing dot."""
    d = raw.strip().lower()
    d = re.sub(r"^[a-z][a-z0-9+.-]*://", "", d)
    d = re.split(r"[/?#]", d, maxsplit=1)[0]
    d = d.rsplit("@", 1)[-1]
    d = re.sub(r":\d+$", "", d)
    return d.strip(".")


def is_valid(d: str) -> bool:
    return bool(VALID_RE.match(d)) and "." in d


def is_ip(d: str) -> bool:
    return bool(IP_RE.match(d))


def registered_domain(d: str) -> str:
    """Approximate eTLD+1 (good enough for grouping and features, no PSL dependency)."""
    if is_ip(d):
        return d
    parts = d.split(".")
    if len(parts) <= 2:
        return d
    if len(parts[-1]) == 2 and parts[-2] in SECOND_LEVEL and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def _parts(d: str):
    reg = registered_domain(d)
    sub = d[: -len(reg)].strip(".") if d != reg else ""
    label = reg if is_ip(d) else reg.split(".")[0]
    tld = reg.split(".")[-1]
    return reg, sub, label, tld


FEATURE_NAMES = [
    "length", "label_len", "n_labels", "n_hyphens", "digit_ratio", "label_entropy",
    "full_entropy", "vowel_ratio", "max_consonant_run", "max_digit_run", "tld_len",
    "tld_suspicious", "n_keywords", "brand_in_subdomain", "brand_impersonation",
    "is_ip", "punycode", "subdomain_len", "max_label_len", "n_digit_groups",
]


def extract(domain: str) -> list[float]:
    d = normalize(domain)
    reg, sub, label, tld = _parts(d)
    letters = [c for c in label if c.isalpha()]
    vowels = sum(c in "aeiou" for c in letters)
    return [
        len(d), len(label), d.count(".") + 1, d.count("-"),
        sum(c.isdigit() for c in d) / max(len(d), 1),
        _entropy(label), _entropy(d.replace(".", "")),
        vowels / max(len(letters), 1),
        max((len(m) for m in CONS_RE.findall(label)), default=0),
        max((len(m) for m in DIGIT_RE.findall(d)), default=0),
        len(tld), int(tld in SUSPICIOUS_TLDS),
        sum(k in d for k in KEYWORDS),
        int(any(b in sub for b in BRANDS)),
        int(any(b in label and label != b for b in BRANDS)),
        int(is_ip(d)), int("xn--" in d), len(sub),
        max(len(x) for x in d.split(".")), len(DIGIT_RE.findall(d)),
    ]


def extract_many(domains) -> np.ndarray:
    return np.array([extract(d) for d in domains], dtype=np.float32)


def explain(domain: str) -> list[str]:
    """Human-readable reasons (rule-based hints shown next to the ML score)."""
    d = normalize(domain)
    f = dict(zip(FEATURE_NAMES, extract(d)))
    why = []
    if f["is_ip"]:
        why.append("host is a raw IP address")
    if f["tld_suspicious"]:
        why.append("TLD frequently abused (.%s)" % d.rsplit(".", 1)[-1])
    kws = [k for k in KEYWORDS if k in d]
    if kws:
        why.append("phishing-style keywords: " + ", ".join(kws[:4]))
    if f["brand_in_subdomain"]:
        why.append("brand name used inside a subdomain")
    if f["brand_impersonation"]:
        why.append("brand name mixed into an unrelated domain")
    if f["label_entropy"] > 3.4 and f["label_len"] >= 10:
        why.append("random-looking name (possible DGA)")
    if f["n_hyphens"] >= 3:
        why.append("many hyphens")
    if f["n_labels"] >= 5:
        why.append("unusually deep subdomain nesting")
    if f["punycode"]:
        why.append("punycode (possible look-alike characters)")
    if f["digit_ratio"] > 0.3:
        why.append("high share of digits")
    return why
