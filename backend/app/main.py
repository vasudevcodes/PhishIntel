"""
PhishIntel Backend Application Entry Point (Phase 1).
Forensic Email Parser & Threat Investigation Foundation.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.v1.router import api_router
from app.core.config import settings

app = FastAPI(
    title="PhishIntel API",
    description="Forensic Email Parser & Investigation Platform - Phase 1 Foundation",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS middleware for local frontend communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include v1 endpoints
app.include_router(api_router, prefix=settings.API_V1_STR)


@app.get("/health", tags=["System"])
async def health_check():
    """Health check endpoint to verify backend operational readiness."""
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "phase": "Phase 1 - Forensic Foundation",
    }


@app.get("/", tags=["System"])
async def root():
    """Root redirect / information endpoint."""
    return {
        "message": "Welcome to PhishIntel Forensic Analysis Engine",
        "docs": "/docs",
        "health": "/health",
        "analyze_endpoint": f"{settings.API_V1_STR}/email/analyze",
    }
