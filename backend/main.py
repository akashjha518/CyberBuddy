from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from fastapi.middleware.cors import CORSMiddleware

from analyzer.message_analyzer import analyze_message
from analyzer.url_analyzer import analyze_url
from backend.ai.explainer import generate_explanation


app = FastAPI(
    title="CyberBuddy",
    description="AI-powered cybersecurity assistant for non-technical users.",
    version="0.1.0",
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:3000",
        "http://localhost:3000",
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


class MessageRequest(BaseModel):
    message: str = Field(
        ...,
        min_length=1,
        max_length=10000,
        description="Suspicious message to analyze",
    )


class URLRequest(BaseModel):
    url: str = Field(
        ...,
        min_length=1,
        max_length=2048,
        description="URL to analyze",
    )


@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "service": "CyberBuddy",
        "version": "0.1.0",
    }


@app.post("/api/analyze/message")
def analyze_suspicious_message(request: MessageRequest):
    try:
        result = analyze_message(request.message)

        # Deterministic analysis remains authoritative.
        # Gemma only explains the existing analysis.
        result["ai_explanation"] = generate_explanation(result)

        return result

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error),
        )


@app.post("/api/analyze/url")
def analyze_suspicious_url(request: URLRequest):
    try:
        result = analyze_url(request.url)

        # Deterministic URL analysis remains authoritative.
        # Gemma only explains the existing analysis.
        result["ai_explanation"] = generate_explanation(result)

        return result

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error),
        )