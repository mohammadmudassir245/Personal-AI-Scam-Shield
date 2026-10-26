"""
Central configuration — runtime constants + environment-variable overrides.
"""
from __future__ import annotations

import os
from pathlib import Path

# ── CORS ──────────────────────────────────────────────────────────────────────
# In production set ALLOWED_ORIGIN to your Vercel deployment URL.
ALLOWED_ORIGINS: list[str] = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]
_extra = os.getenv("ALLOWED_ORIGIN", "").strip()
if _extra:
    ALLOWED_ORIGINS.append(_extra)

# ── Paths ─────────────────────────────────────────────────────────────────────
_base = Path(__file__).parent.parent          # → backend/

MODELS_DIR: Path = Path(os.getenv("MODELS_DIR", str(_base / "models")))

DB_PATH: str = os.getenv("DB_PATH", str(_base / "scam_shield.db"))

# Alias kept for backwards-compatibility with database.py
DATABASE_PATH: str = DB_PATH

# ── Risk classification ───────────────────────────────────────────────────────
# (ceiling_inclusive, level_key, human_label)
RISK_BANDS: list[tuple[int, str, str]] = [
    (25,  "LOW",      "Low risk"),
    (50,  "MODERATE", "Moderate risk"),
    (75,  "HIGH",     "High risk"),
    (100, "CRITICAL", "Critical risk"),
]

# Weights for the five analysis signals (must sum to 1.0)
RISK_WEIGHTS: dict[str, float] = {
    "text":          0.28,
    "url":           0.26,
    "impersonation": 0.20,
    "social":        0.14,
    "rules":         0.12,
}
