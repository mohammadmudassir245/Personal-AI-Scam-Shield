from __future__ import annotations

"""Text classifier.

Version 1 uses TF-IDF + Logistic Regression trained on curated seed messages so
the prototype runs locally without downloading DistilBERT. The interface matches
a future DistilBERT classifier: predict_label(text) -> (label, probabilities, risk).
"""

from app.ml.train import LABELS, ensure_models, text_risk_from_proba


class TextClassifier:
    def __init__(self) -> None:
        self.model, self.url_model = ensure_models()

    def predict(self, text: str) -> tuple[int, str, dict[str, float]]:
        if not text.strip():
            return 5, "legitimate", {label: 0.0 for label in LABELS}
        proba = self.model.predict_proba([text])[0]
        mapping = {cls: float(p) for cls, p in zip(self.model.classes_, proba)}
        for label in LABELS:
            mapping.setdefault(label, 0.0)
        score, label = text_risk_from_proba(mapping)
        return score, label, mapping

    def predict_url_risk(self, features: list[float]) -> int:
        import numpy as np

        proba = float(self.url_model.predict_proba(np.array([features], dtype=float))[0][1])
        return int(round(100 * proba))
