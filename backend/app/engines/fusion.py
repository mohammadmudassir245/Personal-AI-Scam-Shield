from __future__ import annotations

from app.config import RISK_BANDS, RISK_WEIGHTS


def fuse(text_score: int, url_score: int, impersonation_score: int, social_score: int, rule_score: int) -> tuple[int, str, str]:
    weighted = (
        RISK_WEIGHTS["text"] * text_score
        + RISK_WEIGHTS["url"] * url_score
        + RISK_WEIGHTS["impersonation"] * impersonation_score
        + RISK_WEIGHTS["social"] * social_score
        + RISK_WEIGHTS["rules"] * rule_score
    )
    # Peak-risk bias: a single critical signal should not be averaged away.
    peak = max(text_score, url_score, impersonation_score, social_score, rule_score)
    score = int(round(0.62 * weighted + 0.38 * peak))
    score = max(0, min(100, score))
    for ceiling, level, label in RISK_BANDS:
        if score <= ceiling:
            return score, level, label
    return score, "CRITICAL", "Critical risk"


def social_score(techniques: dict) -> int:
    active = [t["score"] for t in techniques.values() if t["matched"]]
    if not active:
        return 6
    return min(100, int(round(0.55 * max(active) + 0.45 * (sum(active) / len(active)))))
