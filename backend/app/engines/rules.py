from __future__ import annotations

from dataclasses import dataclass


@dataclass
class RuleHit:
    id: str
    title: str
    detail: str
    boost: int
    severity: str


def apply_rules(techniques: dict, url_score: int, impersonation, urls: list[str], text: str) -> tuple[int, list[RuleHit]]:
    hits: list[RuleHit] = []
    lowered = text.lower()

    cred = techniques.get("credential", {}).get("matched")
    urgency = techniques.get("urgency", {}).get("matched")
    fear = techniques.get("fear", {}).get("matched")
    reward = techniques.get("reward", {}).get("matched")
    financial = techniques.get("financial", {}).get("matched")
    has_url = bool(urls)
    suspicious_url = url_score >= 45

    if cred and suspicious_url:
        hits.append(RuleHit(
            "cred_url",
            "Credential request with a suspicious link",
            "Asking for OTP, PIN, or login plus an untrusted URL is a classic phishing pattern.",
            28,
            "critical",
        ))
    if impersonation.domain_mismatch and urgency:
        hits.append(RuleHit(
            "brand_urgency",
            "Brand impersonation plus urgency",
            "A trusted organization is claimed while pressuring you to act immediately.",
            26,
            "critical",
        ))
    if impersonation.claimed and has_url and impersonation.domain_mismatch:
        hits.append(RuleHit(
            "brand_external_login",
            "External verification link for a claimed brand",
            "Legitimate banks and agencies do not send login or KYC links to lookalike domains.",
            24,
            "high",
        ))
    if cred and ("otp" in lowered or "password" in lowered):
        hits.append(RuleHit(
            "otp_ask",
            "Direct OTP or password request",
            "No bank, courier, or employer needs you to share an OTP, PIN, or password by message.",
            22,
            "critical",
        ))
    if fear and urgency and has_url:
        hits.append(RuleHit(
            "fear_deadline_link",
            "Fear, deadline, and a link",
            "Threats of blocking or legal action are used to rush you into clicking.",
            18,
            "high",
        ))
    if reward and (financial or has_url):
        hits.append(RuleHit(
            "prize_fee",
            "Unexpected prize with a claim step",
            "Unsolicited winnings that require a click, fee, or details are almost always scams.",
            16,
            "high",
        ))
    if financial and urgency:
        hits.append(RuleHit(
            "pay_now",
            "Immediate payment demand",
            "Pressure to send money, gift cards, or a verification fee is a high-risk pattern.",
            16,
            "high",
        ))

    score = min(100, sum(h.boost for h in hits))
    if not hits:
        score = 6
    return score, hits
