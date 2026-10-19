from __future__ import annotations

import ipaddress
import math
import re
from dataclasses import dataclass
from urllib.parse import urlparse, unquote

SUSPICIOUS_KEYWORDS = (
    "login", "verify", "secure", "update", "account", "banking", "kyc",
    "password", "confirm", "suspend", "unlock", "invoice", "refund",
    "wallet", "crypto", "support", "alert",
)

SUSPICIOUS_TLDS = {".zip", ".mov", ".xyz", ".top", ".gq", ".tk", ".ml", ".cf", ".click", ".country", ".support"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly", "rb.gy"}


@dataclass
class UrlAssessment:
    url: str
    score: int
    features: dict
    flags: list[str]


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def extract_features(url: str) -> dict:
    raw = url.strip()
    parsed = urlparse(raw if "://" in raw else "http://" + raw)
    host = (parsed.hostname or "").lower()
    path = unquote(parsed.path or "")
    query = unquote(parsed.query or "")
    full = f"{host}{path}?{query}"
    labels = [p for p in host.split(".") if p]
    suspicious_chars = len(re.findall(r"[@%_\-!~*]", raw))
    keywords = sum(1 for k in SUSPICIOUS_KEYWORDS if k in full.lower())
    tld = "." + labels[-1] if labels else ""
    return {
        "url_length": len(raw),
        "https": 1 if parsed.scheme == "https" else 0,
        "domain_length": len(host),
        "num_dots": host.count("."),
        "num_subdomains": max(0, len(labels) - 2),
        "special_chars": suspicious_chars,
        "ip_url": 1 if host and _is_ip(host) else 0,
        "suspicious_keywords": keywords,
        "has_at": 1 if "@" in raw else 0,
        "has_hyphen": 1 if "-" in host else 0,
        "path_length": len(path),
        "query_length": len(query),
        "digit_ratio": (sum(c.isdigit() for c in host) / max(1, len(host))),
        "suspicious_tld": 1 if tld in SUSPICIOUS_TLDS else 0,
        "shortener": 1 if host in SHORTENERS else 0,
        "double_slash_path": 1 if "//" in path else 0,
    }


FEATURE_ORDER = [
    "url_length", "https", "domain_length", "num_dots", "num_subdomains",
    "special_chars", "ip_url", "suspicious_keywords", "has_at", "has_hyphen",
    "path_length", "query_length", "digit_ratio", "suspicious_tld",
    "shortener", "double_slash_path",
]


def heuristic_score(features: dict) -> tuple[int, list[str]]:
    flags = []
    score = 8
    if features["ip_url"]:
        score += 35
        flags.append("URL uses a raw IP address instead of a domain")
    if not features["https"]:
        score += 18
        flags.append("Connection is not HTTPS")
    if features["has_at"]:
        score += 22
        flags.append("URL contains @, a common obfuscation trick")
    if features["num_subdomains"] >= 3:
        score += 16
        flags.append("Unusually deep subdomain structure")
    if features["url_length"] > 90:
        score += 12
        flags.append("URL is unusually long")
    if features["suspicious_keywords"] >= 2:
        score += 14
        flags.append("Path or host uses phishing keywords (login, verify, kyc)")
    elif features["suspicious_keywords"] == 1:
        score += 7
    if features["suspicious_tld"]:
        score += 16
        flags.append("Top-level domain is commonly abused in phishing")
    if features["shortener"]:
        score += 14
        flags.append("Link shortener hides the real destination")
    if features["has_hyphen"] and features["suspicious_keywords"]:
        score += 8
        flags.append("Hyphenated host plus security keywords")
    if features["digit_ratio"] > 0.25:
        score += 10
        flags.append("Domain contains an unusual number of digits")
    if features["double_slash_path"]:
        score += 8
        flags.append("Path contains redirect-like double slashes")
    return min(100, score), flags


def analyze_urls(urls: list[str], predictor=None) -> UrlAssessment:
    if not urls:
        return UrlAssessment(url="", score=5, features={}, flags=[])

    worst: UrlAssessment | None = None
    for url in urls:
        features = extract_features(url)
        h_score, flags = heuristic_score(features)
        ml_score = h_score
        if predictor is not None:
            try:
                ml_score = predictor(features)
            except Exception:
                ml_score = h_score
        score = int(round(0.55 * ml_score + 0.45 * h_score))
        assessment = UrlAssessment(url=url, score=min(100, score), features=features, flags=flags)
        if worst is None or assessment.score > worst.score:
            worst = assessment
    return worst or UrlAssessment(url=urls[0], score=5, features={}, flags=[])


def feature_vector(features: dict) -> list[float]:
    return [float(features.get(name, 0)) for name in FEATURE_ORDER]


def entropy(s: str) -> float:
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)
