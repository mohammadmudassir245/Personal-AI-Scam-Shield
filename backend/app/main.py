import traceback

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import ALLOWED_ORIGINS
from app.database import get_recent, init_db, record_analysis
from app.pipeline import analyze, get_classifier
from app.schemas import AnalyzeRequest, AnalyzeResponse, HistoryRecord

app = FastAPI(
    title="Personal AI Scam Shield",
    description="Explainable scam-risk analysis for messages, SMS, URLs, and emails.",
    version="0.2.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    tb = traceback.format_exc()
    print(tb)
    return JSONResponse(
        status_code=500,
        content={"detail": f"{type(exc).__name__}: {exc}", "traceback": tb},
    )


@app.on_event("startup")
def startup() -> None:
    init_db()
    get_classifier()


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "service": "personal-ai-scam-shield", "version": "0.2.0"}


@app.post("/api/analyze", response_model=AnalyzeResponse)
def analyze_endpoint(req: AnalyzeRequest) -> AnalyzeResponse:
    result = analyze(req)
    try:
        record_analysis(
            input_type=result.input_type,
            risk_score=result.risk_score,
            risk_level=result.risk_level,
            risk_label=result.risk_label,
            scam_type=result.scam_type,
            techniques_count=len(result.techniques),
        )
    except Exception:
        pass
    return result


@app.get("/api/history", response_model=list[HistoryRecord])
def history_endpoint(limit: int = 20) -> list[HistoryRecord]:
    """Return the last N analyses (metadata only — no message content)."""
    rows = get_recent(min(limit, 50))
    return [HistoryRecord(**row) for row in rows]
