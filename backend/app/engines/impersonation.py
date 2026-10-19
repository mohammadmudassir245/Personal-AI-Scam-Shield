from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse

BRANDS: dict[str, dict] = {
    "sbi": {"names": ["sbi", "state bank of india", "onlinesbi"], "domains": ["sbi.co.in", "onlinesbi.sbi", "bank.sbi"]},
    "hdfc": {"names": ["hdfc"], "domains": ["hdfcbank.com"]},
    "icici": {"names": ["icici"], "domains": ["icicibank.com"]},
    "axis": {"names": ["axis bank"], "domains": ["axisbank.com"]},
    "paytm": {"names": ["paytm"], "domains": ["paytm.com", "paytm.in"]},
    "phonepe": {"names": ["phonepe", "phone pe"], "domains": ["phonepe.com"]},
    "gpay": {"names": ["google pay", "gpay"], "domains": ["pay.google.com", "google.com"]},
    "amazon": {"names": ["amazon", "amazon pay"], "domains": ["amazon.in", "amazon.com"]},
    "flipkart": {"names": ["flipkart"], "domains": ["flipkart.com"]},
    "whatsapp": {"names": ["whatsapp"], "domains": ["whatsapp.com", "wa.me"]},
    "instagram": {"names": ["instagram", "meta"], "domains": ["instagram.com", "meta.com"]},
    "facebook": {"names": ["facebook"], "domains": ["facebook.com", "fb.com"]},
    "microsoft": {"names": ["microsoft", "outlook", "onedrive"], "domains": ["microsoft.com", "live.com", "office.com"]},
    "google": {"names": ["google", "gmail"], "domains": ["google.com", "gmail.com"]},
    "apple": {"names": ["apple", "icloud", "app store"], "domains": ["apple.com", "icloud.com"]},
    "incometax": {"names": ["income tax", "itd", "e-filing"], "domains": ["incometax.gov.in"]},
    "uidai": {"names": ["uidai", "aadhaar", "aadhar"], "domains": ["uidai.gov.in"]},
    "rbi": {"names": ["reserve bank", "rbi"], "domains": ["rbi.org.in"]},
    "irctc": {"names": ["irctc"], "domains": ["irctc.co.in"]},
    "delhivery": {"names": ["delhivery"], "domains": ["delhivery.com"]},
    "indiapost": {"names": ["india post", "indian post"], "domains": ["indiapost.gov.in"]},
    "fedex": {"names": ["fedex"], "domains": ["fedex.com"]},
    "dhl": {"names": ["dhl"], "domains": ["dhl.com"]},
}


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            curr.append(min(curr[j - 1] + 1, prev[j] + 1, prev[j - 1] + (ca != cb)))
        prev = curr
    return prev[-1]


def registered_domain(host: str) -> str:
    parts = [p for p in host.lower().split(".") if p]
    if len(parts) >= 2:
        if parts[-1] in {"in", "uk", "au"} and len(parts) >= 3:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])
    return host.lower()


@dataclass
class ImpersonationResult:
    score: int
    brand: str
    claimed: bool
    domain_mismatch: bool
    flags: list[str]


def analyze(text: str, urls: list[str], sender: str = "") -> ImpersonationResult:
    lowered = text.lower()
    claimed_brand = ""
    for brand, meta in BRANDS.items():
        if any(re.search(rf"\b{re.escape(name)}\b", lowered) for name in meta["names"]):
            claimed_brand = brand
            break

    hosts = []
    for url in urls:
        host = (urlparse(url).hostname or "").lower()
        if host:
            hosts.append(host)
    if sender and "@" in sender:
        hosts.append(sender.split("@", 1)[1].lower().strip("> "))

    flags = []
    domain_mismatch = False
    typosquat = False

    if claimed_brand:
        official = BRANDS[claimed_brand]["domains"]
        flags.append(f"Message claims association with {claimed_brand.upper()}")
        for host in hosts:
            reg = registered_domain(host)
            if not any(reg == d or host.endswith("." + d) for d in official):
                domain_mismatch = True
                flags.append(f"Domain {host} does not match official {claimed_brand.upper()} domains")
            for d in official:
                token = d.split(".")[0]
                label = host.split(".")[0]
                if 0 < levenshtein(label, token) <= 2 and label != token:
                    typosquat = True
                    flags.append(f"Host '{label}' looks similar to '{token}' (possible typosquat)")

    if not claimed_brand:
        for host in hosts:
            label = host.split(".")[0].replace("-", "")
            for brand, meta in BRANDS.items():
                token = meta["domains"][0].split(".")[0]
                if token in host and registered_domain(host) not in meta["domains"]:
                    claimed_brand = brand
                    domain_mismatch = True
                    flags.append(f"Domain {host} piggybacks on the {brand.upper()} name")
                elif 0 < levenshtein(label, token) <= 1 and len(token) > 3:
                    claimed_brand = brand
                    typosquat = True
                    flags.append(f"Possible typosquat of {brand.upper()} in {host}")

    score = 8
    if claimed_brand:
        score += 20
    if domain_mismatch:
        score += 45
    if typosquat:
        score += 28
    if claimed_brand and not hosts:
        score += 10
        flags.append("A trusted brand is mentioned but no official domain is present")

    return ImpersonationResult(
        score=min(100, score),
        brand=claimed_brand,
        claimed=bool(claimed_brand),
        domain_mismatch=domain_mismatch,
        flags=flags,
    )
