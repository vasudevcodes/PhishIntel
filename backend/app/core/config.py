"""
Configuration module for PhishIntel Backend (Phase 1).
"""

from typing import List


class Settings:
    PROJECT_NAME: str = "PhishIntel"
    API_V1_STR: str = "/api/v1"
    MAX_UPLOAD_SIZE_BYTES: int = 10 * 1024 * 1024  # 10 MB limit
    ALLOWED_EXTENSIONS: List[str] = [".eml"]
    CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]
    TRUSTED_AUTHSERV_DOMAINS: List[str] = [
        "google.com",
        "mx.google.com",
        "protection.outlook.com",
        "outlook.com",
        "microsoft.com",
        "office365.com",
        "proofpoint.com",
        "pphosted.com",
        "mimecast.com",
        "cisco.com",
        "ironport.com",
        "barracuda.com",
        "sendgrid.net",
        "mailgun.org",
        "amazonses.com",
    ]


settings = Settings()
