from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    upstream_url: str
    admin_username: str
    admin_password: str
    secret_key: str
    data_dir: Path
    log_body_limit: int
    request_timeout: int

    @property
    def db_path(self) -> Path:
        return self.data_dir / "magualine.db"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    data_dir = Path(os.getenv("DATA_DIR", "/app/data")).resolve()
    data_dir.mkdir(parents=True, exist_ok=True)
    upstream_url = os.getenv("UPSTREAM_URL", "http://host.docker.internal:8090").rstrip("/")

    return Settings(
        upstream_url=upstream_url,
        admin_username=os.getenv("ADMIN_USERNAME", "admin"),
        admin_password=os.getenv("ADMIN_PASSWORD", "ChangeThisPassword123"),
        secret_key=os.getenv("SECRET_KEY", "magualine-change-this-secret-key"),
        data_dir=data_dir,
        log_body_limit=int(os.getenv("LOG_BODY_LIMIT", "4096")),
        request_timeout=int(os.getenv("REQUEST_TIMEOUT", "30")),
    )
