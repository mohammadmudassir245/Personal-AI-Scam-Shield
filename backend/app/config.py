from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODELS_DIR = ROOT / "models"
DATABASE_PATH = ROOT / "scam_shield.db"

RISK_WEIGHTS = {
    "text": 0.28,
    "url": 0.24,
    "impersonation": 0.16,
    "social": 0.18,
    "rules": 0.14,
}

RISK_BANDS = (
    (25, "LOW", "Low risk"),
    (50, "MODERATE", "Moderate risk"),
    (75, "HIGH", "High risk"),
    (100, "CRITICAL", "Critical risk"),
)

# Never fetch or execute submitted URLs. Analysis is local/heuristic only.
FETCH_URLS = False
STORE_CONTENT = False
