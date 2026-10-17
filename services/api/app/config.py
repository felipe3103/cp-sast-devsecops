"""Configuração via variáveis de ambiente (12-factor)."""
from __future__ import annotations

import os
from dataclasses import dataclass, field


def _bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    database_url: str = os.getenv("DATABASE_URL", "sqlite:///./sentinela.db")
    redis_url: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    celery_eager: bool = _bool("CELERY_EAGER", False)
    api_token: str = os.getenv("SAST_API_TOKEN", "")
    max_upload_mb: int = int(os.getenv("MAX_UPLOAD_MB", "50"))
    max_files: int = int(os.getenv("MAX_FILES", "5000"))
    allowed_git_hosts: tuple[str, ...] = tuple(
        h.strip() for h in os.getenv("ALLOWED_GIT_HOSTS", "github.com,gitlab.com").split(",") if h.strip()
    )
    ai_auto_triage: bool = _bool("AI_AUTO_TRIAGE", False)
    ai_auto_limit: int = int(os.getenv("AI_AUTO_LIMIT", "15"))
    cors_origins: list[str] = field(
        default_factory=lambda: [o for o in os.getenv("CORS_ORIGINS", "").split(",") if o]
    )


settings = Settings()
