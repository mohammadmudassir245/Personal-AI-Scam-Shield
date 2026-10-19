from __future__ import annotations

from functools import lru_cache

from app.engines.explain import build_narrative, build_reasons
from app.engines.fusion import fuse, social_score
from app.engines.impersonation import analyze as analyze_impersonation
from app.engines.nlp import TextClassifier
from app.engines.recommend import recommend
from app.engines.rules import apply_rules
from app.engines.text import classify_scam_type, detect_techniques, preprocess
from app.engines.url import analyze_urls, feature_vector
from app.schemas import AnalyzeRequest, AnalyzeResponse, SignalScore

DISCLAIMER = (
    "This is a risk score from local analysis, not a legal determination and not a "
    "guarantee that something is safe or fraudulent. Never submit passwords, OTPs, or PINs here."
)


@lru_cache(maxsize=1)
def get_classifier() -> TextClassifier:
    return TextClassifier()


def analyze(req: AnalyzeRequest) -> AnalyzeResponse:
    bundle = preprocess(req.content, req.sender, req.subject, req.input_type)
    if req.input_type == "url" and bundle.raw.strip() and not bundle.urls:
        bundle.urls = [bundle.raw.strip()]

    clf = get_classifier()
    text_score, nlp_label, _proba = clf.predict(bundle.clean)
    techniques = detect_techniques(bundle.clean)

    def url_predictor(features: dict) -> int:
        return clf.predict_url_risk(feature_vector(features))

    url_assessment = analyze_urls(bundle.urls, predictor=url_predictor)
    impersonation = analyze_impersonation(bundle.clean, bundle.urls, bundle.sender)
    rule_score, rule_hits = apply_rules(techniques, url_assessment.score, impersonation, bundle.urls, bundle.clean)
    social = social_score(techniques)

    if req.input_type == "url":
        text_score = min(text_score, 35)

    risk_score, risk_level, risk_label = fuse(
        text_score, url_assessment.score, impersonation.score, social, rule_score
    )
    scam_type = classify_scam_type(bundle.clean, techniques, impersonation.claimed, impersonation.brand)
    if risk_level == "LOW":
        scam_type = "No clear scam type"

    rec_title, rec_body = recommend(scam_type, techniques, bool(bundle.urls), risk_level)
    reasons = build_reasons(techniques, url_assessment, impersonation, rule_hits, nlp_label)
    narrative, summary = build_narrative(techniques, impersonation, bundle.urls, scam_type, risk_level)
    tech_labels = [t["label"] for t in techniques.values() if t["matched"]]

    signals = [
        SignalScore(name="Text / NLP", score=text_score, label=nlp_label),
        SignalScore(name="URL", score=url_assessment.score, label="flagged" if url_assessment.score >= 45 else "clear"),
        SignalScore(name="Impersonation", score=impersonation.score, label=impersonation.brand or "none"),
        SignalScore(name="Social engineering", score=social, label=f"{len(tech_labels)} technique(s)"),
        SignalScore(name="Security rules", score=rule_score, label=f"{len(rule_hits)} hit(s)"),
    ]

    return AnalyzeResponse(
        input_type=req.input_type,
        risk_score=risk_score,
        risk_level=risk_level,
        risk_label=risk_label,
        nlp_label=nlp_label,
        scam_type=scam_type,
        techniques=tech_labels,
        signals=signals,
        reasons=reasons,
        narrative=narrative,
        narrative_summary=summary,
        recommendation=rec_body,
        recommendation_title=rec_title,
        extracted_urls=bundle.urls,
        disclaimer=DISCLAIMER,
    )
