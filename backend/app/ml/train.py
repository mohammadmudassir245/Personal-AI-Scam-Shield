from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from xgboost import XGBClassifier

from app.config import MODELS_DIR
from app.engines.url import FEATURE_ORDER, extract_features, feature_vector
from app.ml.seed_data import TEXT_EXAMPLES, URL_EXAMPLES

TEXT_MODEL = MODELS_DIR / "text_tfidf_logreg.joblib"
URL_MODEL = MODELS_DIR / "url_xgb.joblib"
LABELS = ["legitimate", "suspicious", "scam"]


def train_text_model() -> Pipeline:
    texts, labels = zip(*TEXT_EXAMPLES)
    pipe = Pipeline(
        [
            ("tfidf", TfidfVectorizer(ngram_range=(1, 2), min_df=1, lowercase=True)),
            (
                "clf",
                LogisticRegression(max_iter=400, class_weight="balanced"),
            ),
        ]
    )
    pipe.fit(list(texts), list(labels))
    return pipe


def train_url_model() -> XGBClassifier:
    X = np.array([feature_vector(extract_features(url)) for url, _ in URL_EXAMPLES], dtype=float)
    y = np.array([0 if label == "legit" else 1 for _, label in URL_EXAMPLES])
    model = XGBClassifier(
        n_estimators=80,
        max_depth=4,
        learning_rate=0.2,
        objective="binary:logistic",
        eval_metric="logloss",
        n_jobs=1,
    )
    model.fit(X, y)
    model.get_booster().feature_names = FEATURE_ORDER
    return model


def ensure_models() -> tuple[Pipeline, XGBClassifier]:
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    if TEXT_MODEL.exists() and URL_MODEL.exists():
        return joblib.load(TEXT_MODEL), joblib.load(URL_MODEL)
    text_model = train_text_model()
    url_model = train_url_model()
    joblib.dump(text_model, TEXT_MODEL)
    joblib.dump(url_model, URL_MODEL)
    return text_model, url_model


def text_risk_from_proba(proba: dict[str, float]) -> tuple[int, str]:
    label = max(proba, key=proba.get)
    scam = proba.get("scam", 0)
    suspicious = proba.get("suspicious", 0)
    score = int(round(100 * (0.85 * scam + 0.45 * suspicious)))
    return min(100, max(4, score)), label


if __name__ == "__main__":
    text_model, url_model = ensure_models()
    print("Saved", TEXT_MODEL, URL_MODEL)
    print("Text classes", text_model.classes_)
