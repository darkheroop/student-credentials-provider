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
    DATABASE_PATH: str = os.getenv(
        "DATABASE_PATH",
        os.path.join("/tmp", "scp.db") if os.getenv("VERCEL") else os.path.join(BASE_DIR, "scp.db"),
    )
    PERSISTENT_SYNC_URL: str | None = os.getenv("PERSISTENT_SYNC_URL")
    GITHUB_TOKEN: str | None = os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN")
    GITHUB_REPO: str | None = os.getenv("GITHUB_REPO", "darkheroop/student-credentials-provider")
    MAX_FAILOVER_ATTEMPTS: int = int(os.getenv("MAX_FAILOVER_ATTEMPTS", "5"))
    DEFAULT_PAUSE_DURATION_MINUTES: int = int(os.getenv("DEFAULT_PAUSE_DURATION_MINUTES", "60"))

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
