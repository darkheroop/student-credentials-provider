"""
Configuration module for the Student Credentials Provider application.

Loads settings from environment variables via python-dotenv and exposes
them through a Config class used by the Flask app and services.
"""

import os
from dotenv import load_dotenv

# Load .env file from the project root (if present)
load_dotenv()


class Config:
    """Central configuration object for the SCP application."""

    # ── External Lookup Provider API ────────────────────────────────────
    MD5DECRYPT_API_KEY: str | None = os.getenv(
        "MD5DECRYPT_API_KEY",
        "md5d_live_155f0730_phEgWCGkD_dYIFpqOeeXCQa-K2Y7xBOAa_CzKxmzDqY",
    )
    MD5DECRYPT_API_URL: str = os.getenv(
        "MD5DECRYPT_API_URL",
        "https://api.md5decrypt.net/",
    )

    # ── Application mode ────────────────────────────────────────────────
    STUDENT_LOOKUP_MODE: str = os.getenv(
        "STUDENT_LOOKUP_MODE",
        os.getenv("HASH_LOOKUP_MODE", "live" if MD5DECRYPT_API_KEY else "demo"),
    )
    HASH_LOOKUP_MODE: str = STUDENT_LOOKUP_MODE  # Backward compatibility alias

    # ── Networking ──────────────────────────────────────────────────────
    STUDENT_LOOKUP_TIMEOUT_SECONDS: int = int(
        os.getenv("STUDENT_LOOKUP_TIMEOUT_SECONDS", os.getenv("REQUEST_TIMEOUT_SECONDS", "10"))
    )
    REQUEST_TIMEOUT_SECONDS: int = STUDENT_LOOKUP_TIMEOUT_SECONDS  # Backward compatibility alias

    # ── Rate limiting ───────────────────────────────────────────────────
    RATE_LIMIT_PER_MINUTE: int = int(os.getenv("RATE_LIMIT_PER_MINUTE", "30"))

    # ── Security & Admin ────────────────────────────────────────────────
    SECRET_KEY: str = os.getenv("SECRET_KEY", "dev-secret-change-me")
    API_ENCRYPTION_KEY: str = os.getenv(
        "API_ENCRYPTION_KEY", "scp-encryption-secret-key-32chars!"
    )
    ADMIN_USERNAME: str = os.getenv("ADMIN_USERNAME", "inexpert_trifler")
    ADMIN_PASSWORD: str = os.getenv("ADMIN_PASSWORD", "om sai 0987654321")
    SUBADMIN_USERS: str | None = os.getenv("SUBADMIN_USERS")

    # ── Database & Persistence ──────────────────────────────────────────
    BASE_DIR: str = os.path.dirname(os.path.abspath(__file__))

    # Primary managed database URL (Neon PostgreSQL on Vercel)
    _RAW_PG_URL: str | None = (
        os.getenv("DATABASE_URL")
        or os.getenv("DATABASE_URL_UNPOOLED")
        or os.getenv("DATABASE_POSTGRES_URL")
        or os.getenv("POSTGRES_URL")
        or os.getenv("DATABASE_POSTGRES_PRISMA_URL")
    )
    if not _RAW_PG_URL and os.getenv("DATABASE_POSTGRES_HOST"):
        _pg_host = os.getenv("DATABASE_POSTGRES_HOST")
        _pg_user = os.getenv("DATABASE_POSTGRES_USER") or "default"
        _pg_pass = os.getenv("DATABASE_POSTGRES_PASSWORD") or ""
        _pg_db = os.getenv("DATABASE_POSTGRES_DATABASE") or "neondb"
        _RAW_PG_URL = f"postgresql://{_pg_user}:{_pg_pass}@{_pg_host}/{_pg_db}?sslmode=require"

    DATABASE_URL: str | None = _RAW_PG_URL
    DATABASE_URL_UNPOOLED: str | None = os.getenv("DATABASE_URL_UNPOOLED")

    # Discrete Neon / Postgres connection settings
    DATABASE_POSTGRES_HOST: str | None = os.getenv("DATABASE_POSTGRES_HOST")
    DATABASE_POSTGRES_USER: str | None = os.getenv("DATABASE_POSTGRES_USER")
    DATABASE_POSTGRES_PASSWORD: str | None = os.getenv("DATABASE_POSTGRES_PASSWORD")
    DATABASE_POSTGRES_DATABASE: str | None = os.getenv("DATABASE_POSTGRES_DATABASE")

    # Local / fallback SQLite database path
    _RAW_DB_PATH: str = os.getenv("DATABASE_PATH", "").strip()
    if not _RAW_DB_PATH:
        DATABASE_PATH: str = (
            os.path.join("/tmp", "scp.db") if os.getenv("VERCEL") else os.path.abspath(os.path.join(BASE_DIR, "scp.db"))
        )
    elif _RAW_DB_PATH == ":memory:":
        DATABASE_PATH: str = ":memory:"
    elif os.path.isabs(_RAW_DB_PATH):
        DATABASE_PATH: str = os.path.abspath(_RAW_DB_PATH)
    else:
        DATABASE_PATH: str = os.path.abspath(os.path.join(BASE_DIR, _RAW_DB_PATH))
    PERSISTENT_SYNC_URL: str | None = os.getenv("PERSISTENT_SYNC_URL")
    GITHUB_TOKEN: str | None = os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN")
    GITHUB_REPO: str | None = os.getenv("GITHUB_REPO", "darkheroop/student-credentials-provider")
    MAX_FAILOVER_ATTEMPTS: int = int(os.getenv("MAX_FAILOVER_ATTEMPTS", "5"))
    DEFAULT_PAUSE_DURATION_MINUTES: int = int(os.getenv("DEFAULT_PAUSE_DURATION_MINUTES", "60"))
    SERVER_ERROR_COOLDOWN_SECONDS: int = int(os.getenv("SERVER_ERROR_COOLDOWN_SECONDS", "60"))
    NETWORK_ERROR_COOLDOWN_SECONDS: int = int(os.getenv("NETWORK_ERROR_COOLDOWN_SECONDS", "60"))
    RATE_LIMIT_COOLDOWN_SECONDS: int = int(os.getenv("RATE_LIMIT_COOLDOWN_SECONDS", "60"))

    # ── Supported hash algorithms ───────────────────────────────────────
    # Maps algorithm name → expected hex-digest length (in characters).
    SUPPORTED_ALGORITHMS: dict[str, int] = {
        "md5": 32,
        "sha1": 40,
        "sha256": 64,
        "sha384": 96,
        "sha512": 128,
        "ntlm": 32,
    }

    # ── Convenience properties ──────────────────────────────────────────

    @property
    def is_live_mode(self) -> bool:
        """Return True when the app is configured for live API look-ups."""
        mode = getattr(self, "STUDENT_LOOKUP_MODE", None) or getattr(self, "HASH_LOOKUP_MODE", "demo")
        return (
            mode == "live"
            and self.MD5DECRYPT_API_KEY is not None
            and self.MD5DECRYPT_API_KEY != "replace_with_your_api_key"
        )

    @property
    def is_demo_mode(self) -> bool:
        """Return True when the app is running in demo / offline mode."""
        return not self.is_live_mode

    @property
    def is_postgres(self) -> bool:
        """Return True when a PostgreSQL connection URL is configured."""
        url = self.DATABASE_URL
        return bool(url and (url.startswith("postgres://") or url.startswith("postgresql://")))
