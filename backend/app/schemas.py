from typing import Literal

from pydantic import BaseModel, Field

InputType = Literal["message", "sms", "url", "email"]


class AnalyzeRequest(BaseModel):
    input_type: InputType
    content: str = Field(default="", max_length=20_000)
    sender: str = Field(default="", max_length=320)
    subject: str = Field(default="", max_length=500)


class SignalScore(BaseModel):
    name: str
    score: int
    label: str


class Reason(BaseModel):
    severity: Literal["critical", "high", "medium", "low", "info"]
    title: str
    detail: str


class NarrativeStep(BaseModel):
    order: int
    title: str
    detail: str


class AnalyzeResponse(BaseModel):
    input_type: InputType
    risk_score: int
    risk_level: str
    risk_label: str
    nlp_label: str
    scam_type: str
    techniques: list[str]
    signals: list[SignalScore]
    reasons: list[Reason]
    narrative: list[NarrativeStep]
    narrative_summary: str
    recommendation: str
    recommendation_title: str
    extracted_urls: list[str]
    disclaimer: str


class HistoryRecord(BaseModel):
    id: int
    timestamp: str
    input_type: str
    risk_score: int
    risk_level: str
    risk_label: str
    scam_type: str
    techniques_count: int
