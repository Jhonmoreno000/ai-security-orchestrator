from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.scans import router as scans_router
from app.api.findings import router as findings_router
from app.api.ai import router as ai_router
from app.api.targets import router as targets_router
from app.api.websocket import router as ws_router

app = FastAPI(
    title="AI Security Orchestrator API",
    version="0.1.0",
    description="Plataforma de auditoría de ciberseguridad asistida por IA (ZAP, Nuclei, Semgrep, Trivy, AI Analyst, Retest Engine)"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scans_router)
app.include_router(findings_router)
app.include_router(ai_router)
app.include_router(targets_router)
app.include_router(ws_router)


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "AI Security Orchestrator Backend",
        "version": "0.1.0",
        "engines": ["zap", "nuclei", "semgrep", "trivy", "ai_analyst", "policy_engine", "retest_engine"]
    }
