from __future__ import annotations

from app.schemas import NarrativeStep, Reason


def build_reasons(techniques, url_assessment, impersonation, rule_hits, nlp_label: str) -> list[Reason]:
    reasons: list[Reason] = []
    if nlp_label.lower() == "scam":
        reasons.append(Reason(severity="high", title="Language matches known scam patterns", detail="The wording is closer to fraudulent messages than to ordinary notifications."))
    elif nlp_label.lower() == "suspicious":
        reasons.append(Reason(severity="medium", title="Language looks suspicious", detail="The text contains mixed signals that are common in social-engineering attempts."))

    for hit in rule_hits:
        reasons.append(Reason(severity=hit.severity if hit.severity in {"critical", "high", "medium", "low"} else "high", title=hit.title, detail=hit.detail))

    for flag in impersonation.flags:
        severity = "critical" if impersonation.domain_mismatch else "high"
        reasons.append(Reason(severity=severity, title="Possible brand impersonation", detail=flag))

    for flag in url_assessment.flags:
        reasons.append(Reason(severity="high" if url_assessment.score >= 60 else "medium", title="Suspicious URL characteristic", detail=flag))

    for tech in techniques.values():
        if tech["matched"]:
            severity = "high" if tech["score"] >= 70 else "medium"
            reasons.append(Reason(severity=severity, title=tech["label"] + " detected", detail=f"The message uses {tech['label'].lower()} to influence a quick decision."))

    # Deduplicate titles+details
    unique = []
    seen = set()
    for reason in reasons:
        key = (reason.title, reason.detail)
        if key not in seen:
            seen.add(key)
            unique.append(reason)
    return unique[:12]


def build_narrative(techniques, impersonation, urls, scam_type: str, risk_level: str) -> tuple[list[NarrativeStep], str]:
    if risk_level == "LOW" and not any(t["matched"] for t in techniques.values()) and not impersonation.domain_mismatch:
        steps = [
            NarrativeStep(order=1, title="No clear manipulation path", detail="The content does not show a typical scam sequence such as impersonation, fear, then a credential harvest."),
        ]
        return steps, "No strong attack pattern was detected. Stay cautious with unexpected links, but this does not look like a classic scam script."

    steps: list[NarrativeStep] = []
    order = 1
    if impersonation.claimed:
        who = impersonation.brand.upper() if impersonation.brand else "a trusted organization"
        steps.append(NarrativeStep(order=order, title="Impersonate a trusted source", detail=f"The sender presents themselves as {who} so the message feels official."))
        order += 1
    if techniques.get("fear", {}).get("matched"):
        steps.append(NarrativeStep(order=order, title="Create fear", detail="The message threatens loss of access, money, or legal trouble so you feel you must respond."))
        order += 1
    if techniques.get("reward", {}).get("matched"):
        steps.append(NarrativeStep(order=order, title="Dangle a reward", detail="An unexpected prize or refund is used to lower your guard."))
        order += 1
    if techniques.get("urgency", {}).get("matched"):
        steps.append(NarrativeStep(order=order, title="Force a rushed decision", detail="A short deadline is used so you skip checking through official channels."))
        order += 1
    if techniques.get("financial", {}).get("matched"):
        steps.append(NarrativeStep(order=order, title="Push a money movement", detail="You are steered toward a payment, fee, investment, or transfer."))
        order += 1
    if urls:
        steps.append(NarrativeStep(order=order, title="Send you off-platform", detail="A link takes you away from the official app or website, where a fake page can collect information."))
        order += 1
    if techniques.get("credential", {}).get("matched"):
        steps.append(NarrativeStep(order=order, title="Harvest credentials", detail="The likely goal is an OTP, password, PIN, or KYC details that can take over an account."))
        order += 1
    if not steps:
        steps.append(NarrativeStep(order=1, title="Probe for a reaction", detail="The communication may be testing whether you will engage before a clearer request appears."))

    summary = (
        f"This looks like a {scam_type.lower()} pattern: "
        + " -> ".join(step.title.lower() for step in steps)
        + "."
    )
    return steps, summary
