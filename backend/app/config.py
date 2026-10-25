"""
Central configuration — reads from environment variables with sensible defaults.
"""
import os

# Frontend origin allowed for CORS.
# In production set ALLOWED_ORIGIN to your Vercel deployment URL.
ALLOWED_ORIGINS: list[str] = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]

_extra = os.getenv("ALLOWED_ORIGIN", "").strip()
if _extra:
    ALLOWED_ORIGINS.append(_extra)

# SQLite path — writable location on both local and Render
DB_PATH: str = os.getenv("DB_PATH", "scam_shield.db")

# Models directory
MODELS_DIR: str = os.getenv(
    "MODELS_DIR",
    os.path.join(os.path.dirname(__file__), "..", "models"),
)
