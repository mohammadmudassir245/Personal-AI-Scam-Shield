from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

URL_RE = re.compile(r"(https?://[^\s<>\"']+|www\.[^\s<>\"']+)", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
WHITESPACE_RE = re.compile(r"\s+")

TECHNIQUES = {
    "urgency": {
        "label": "Urgency",
        "patterns": [
            r"\bimmediately\b", r"\burgent\b", r"\bact now\b", r"\bright now\b",
            r"\btoday only\b", r"\bwithin \d+ (minutes?|hours?)\b", r"\bexpire[sd]?\b",
            r"\blast chance\b", r"\bbefore (midnight|today|it is too late)\b",
            r"\baccount will be (blocked|suspended|closed)\b", r"\bkyc immediately\b",
        ],
    },
    "fear": {
        "label": "Fear / threat",
        "patterns": [
            r"\bsuspended\b", r"\bblocked\b", r"\blegal action\b", r"\bcompromised\b",
            r"\bunauthorized\b", r"\barrest\b", r"\bfir\b", r"\bpenalty\b",
            r"\baccount (has been|will be) (locked|frozen)\b", r"\bsecurity alert\b",
        ],
    },
    "authority": {
        "label": "Authority impersonation",
        "patterns": [
            r"\bofficial\b", r"\bgovernment\b", r"\bincome tax\b", r"\buidai\b",
            r"\brbi\b", r"\bcyber cell\b", r"\bministry\b", r"\bcompliance\b",
            r"\bbank (alert|security|notification)\b", r"\bcustomer care\b",
        ],
    },
    "reward": {
        "label": "Reward / prize",
        "patterns": [
            r"\bcongratulat", r"\byou (have )?won\b", r"\blottery\b", r"\bprize\b",
            r"\breward\b", r"\bcashback\b", r"\bfree iphone\b", r"\bclaim (your )?(gift|reward|prize)\b",
        ],
    },
    "financial": {
        "label": "Financial pressure",
        "patterns": [
            r"\bsend (money|payment|rs|inr|₹)\b", r"\bpay (a )?(fee|fine|tax|verification)\b",
            r"\btransfer\b", r"\bbank details\b", r"\bupi\b", r"\bgift card\b",
            r"\bwallets?\b", r"\binvest(ment)?\b", r"\bguaranteed returns?\b",
            r"₹\s*\d+", r"\brs\.?\s*\d+", r"\binr\s*\d+",
        ],
    },
    "credential": {
        "label": "Credential request",
        "patterns": [
            r"\botp\b", r"\bpassword\b", r"\bpin\b", r"\bcvv\b", r"\baadhaar\b",
            r"\bpan (card|number)\b", r"\blogin (here|now|to verify)\b",
            r"\bverify (your )?(account|kyc|identity)\b", r"\bshare (the )?otp\b",
            r"\bone[- ]time (password|pin)\b", r"\bkyc\b", r"\bcomplete kyc\b",
        ],
    },
}

SCAM_TYPES = [
    ("otp_scam", "OTP scam", [r"\botp\b", r"\bone[- ]time password\b"]),
    ("prize_lottery", "Prize / lottery scam", [r"\bwon\b", r"\blottery\b", r"\bprize\b", r"congratulat"]),
    ("job_scam", "Job scam", [r"\bwork from home\b", r"\bhiring\b", r"\bpart[- ]time job\b", r"\bsalary credited\b"]),
    ("investment", "Investment scam", [r"\binvest\b", r"\bcrypto\b", r"\bguaranteed return", r"\btrading profit"]),
    ("delivery", "Delivery scam", [r"\bcourier\b", r"\bparcel\b", r"\bdelivery\b", r"\bcustoms fee\b"]),
    ("government", "Government impersonation", [r"\bincome tax\b", r"\buidai\b", r"\baadhaar\b", r"\bgovernment\b", r"\brbi\b"]),
    ("bank_impersonation", "Bank impersonation", [r"\bky[cс]\b", r"\bbank account\b", r"\bnetbanking\b", r"\bifsc\b"]),
    ("account_takeover", "Account takeover", [r"\bunusual (sign[- ]?in|login)\b", r"\breset (your )?password\b", r"\bconfirm (your )?identity\b"]),
    ("phishing", "Phishing", [r"\bverify\b", r"\bclick (here|below)\b", r"https?://"]),
]


@dataclass
class TextBundle:
    raw: str
    combined: str
    clean: str
    sender: str
    subject: str
    urls: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)


def preprocess(content: str, sender: str = "", subject: str = "", input_type: str = "message") -> TextBundle:
    parts = []
    if sender:
        parts.append(f"Sender: {sender}")
    if subject:
        parts.append(f"Subject: {subject}")
    if input_type == "url" and content.strip() and "://" not in content and not content.lower().startswith("www."):
        content = "https://" + content.strip()
    parts.append(content or "")
    combined = "\n".join(parts)
    urls = extract_urls(combined)
    emails = EMAIL_RE.findall(combined)
    clean = WHITESPACE_RE.sub(" ", combined).strip()
    return TextBundle(
        raw=content or "",
        combined=combined,
        clean=clean,
        sender=sender.strip(),
        subject=subject.strip(),
        urls=urls,
        emails=emails,
    )


def extract_urls(text: str) -> list[str]:
    found = []
    for match in URL_RE.findall(text or ""):
        url = match.rstrip(".,);]")
        if url.lower().startswith("www."):
            url = "https://" + url
        if url not in found:
            found.append(url)
    # Bare domains typed as URL input
    stripped = (text or "").strip()
    if stripped and " " not in stripped and "." in stripped and not URL_RE.search(stripped):
        candidate = stripped if "://" in stripped else "https://" + stripped
        parsed = urlparse(candidate)
        if parsed.netloc:
            found.append(candidate)
    return found


def detect_techniques(text: str) -> dict[str, dict]:
    lowered = text.lower()
    hits = {}
    for key, spec in TECHNIQUES.items():
        matched = []
        for pattern in spec["patterns"]:
            if re.search(pattern, lowered, flags=re.IGNORECASE):
                matched.append(pattern)
        intensity = min(100, 35 + 18 * len(matched)) if matched else 0
        hits[key] = {
            "key": key,
            "label": spec["label"],
            "matched": bool(matched),
            "count": len(matched),
            "score": intensity,
        }
    return hits


def classify_scam_type(text: str, techniques: dict, impersonation_hit: bool, brand: str = "") -> str:
    lowered = text.lower()
    if impersonation_hit and (brand in {"sbi", "hdfc", "icici", "axis"} or "bank" in lowered or "kyc" in lowered):
        return "Bank impersonation"
    ranked = []
    for index, (key, label, patterns) in enumerate(SCAM_TYPES):
        score = sum(1 for p in patterns if re.search(p, lowered, flags=re.IGNORECASE))
        ranked.append((score, -index, label))
    ranked.sort(reverse=True)
    if impersonation_hit and techniques.get("credential", {}).get("matched"):
        return "Bank impersonation" if "bank" in lowered or "kyc" in lowered or brand else "Phishing"
    if ranked and ranked[0][0] > 0:
        return ranked[0][2]
    if techniques.get("credential", {}).get("matched"):
        return "Phishing"
    if techniques.get("reward", {}).get("matched"):
        return "Prize / lottery scam"
    return "Social engineering" if any(t["matched"] for t in techniques.values()) else "Unclassified"
