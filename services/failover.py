"""
Automatic API selection and failover coordinator for Student Credentials Provider.

Manages provider rotation, priority ordering, quota exhaustion exclusion,
rate-limit pause windows, and bounded failover across multiple API keys.
"""

from datetime import datetime, timedelta, timezone
from typing import Any

from config import Config
from database import Database
from services.crypto import CredentialCrypto
from services.providers.registry import get_provider_adapter


class ApiFailoverCoordinator:
    """Coordinates API provider selection, dispatch, and failover."""

    def __init__(self, db: Database, crypto: CredentialCrypto, config: Config | None = None):
        self.db = db
        self.crypto = crypto
        self.config = config or Config()

    def execute_lookup(self, hash_input: str, algorithm: str) -> dict[str, Any]:
        """
        Execute a hash lookup across eligible providers with automatic failover.
        """
        eligible_configs = self.db.get_eligible_configs()

        if not eligible_configs:
            return {
                "success": False,
                "status": "no_provider_available",
                "found": False,
                "lookup_input": hash_input,
                "hash": hash_input,
                "algorithm": algorithm,
                "algorithm_type": algorithm,
                "plaintext": None,
                "mode": "live",
                "error": "No active API providers are currently available.",
                "message": "No API providers are currently available.",
                "duration": 0.0,
            }

        max_attempts = min(len(eligible_configs), self.config.MAX_FAILOVER_ATTEMPTS)
        last_failure_reason = "No provider succeeded."

        for i in range(max_attempts):
            api_cfg = eligible_configs[i]
            cfg_id = api_cfg["id"]

            # Decrypt credential
            try:
                credential = self.crypto.decrypt(api_cfg["encrypted_credential"])
            except Exception as exc:
                self.db.set_health_status(cfg_id, "auth_failed", error_category="decryption_error")
                self.db.record_event(
                    cfg_id,
                    "auth_failure",
                    f"Decryption error: {exc.__class__.__name__}",
                )
                continue

            adapter = get_provider_adapter(api_cfg["provider_name"])

            # Execute provider call
            res = adapter.lookup(
                credential=credential,
                endpoint=api_cfg["endpoint"],
                hash_input=hash_input,
                algorithm=algorithm,
                timeout=self.config.STUDENT_LOOKUP_TIMEOUT_SECONDS,
            )

            # Record event in history
            self.db.record_event(
                config_id=cfg_id,
                event_category=res.status,
                sanitized_message=res.error_message or f"Lookup returned {res.status}",
                http_status=res.http_status,
                duration=res.duration,
            )

            # ── 1. Terminal Lookup: Match found OR Legitimate negative result ─
            if res.is_terminal_lookup:
                self.db.record_success(cfg_id, duration=res.duration)
                return {
                    "success": True,
                    "status": res.status,
                    "found": res.found,
                    "lookup_input": hash_input,
                    "hash": hash_input,
                    "algorithm": algorithm,
                    "algorithm_type": algorithm,
                    "plaintext": res.plaintext,
                    "mode": "live",
                    "provider_id": cfg_id,
                    "provider_name": api_cfg["display_name"],
                    "duration": res.duration,
                    "message": "A matching entry was returned." if res.found else "No matching record was found in the database.",
                    "error": None,
                }

            # ── 2. Quota Exhaustion ──────────────────────────────────────────
            if res.status == "quota_exhausted":
                now_utc = datetime.now(timezone.utc)
                pause_minutes = self.config.DEFAULT_PAUSE_DURATION_MINUTES
                paused_until = (now_utc + timedelta(minutes=pause_minutes)).isoformat()

                self.db.set_health_status(
                    cfg_id,
                    health_status="quota_exhausted",
                    paused_until=paused_until,
                    error_category="quota_exhausted",
                )
                last_failure_reason = f"Provider {api_cfg['display_name']} quota exhausted."
                continue

            # ── 3. Rate Limited (HTTP 429) ───────────────────────────────────
            if res.status == "rate_limited":
                now_utc = datetime.now(timezone.utc)
                retry_seconds = res.retry_after_seconds or 60
                paused_until = (now_utc + timedelta(seconds=retry_seconds)).isoformat()

                self.db.set_health_status(
                    cfg_id,
                    health_status="rate_limited",
                    paused_until=paused_until,
                    error_category="rate_limited",
                )
                last_failure_reason = f"Provider {api_cfg['display_name']} rate limited."
                continue

            # ── 4. Authentication Failure (HTTP 401/403) ─────────────────────
            if res.status == "auth_failed":
                self.db.set_health_status(
                    cfg_id,
                    health_status="auth_failed",
                    paused_until=None,
                    error_category="auth_failed",
                )
                last_failure_reason = f"Provider {api_cfg['display_name']} authentication failed."
                continue

            # ── 5. Transient Server Error or Network Timeout ─────────────────
            # Set short 2-minute cooldown so we don't hammer an unresponsive host
            cooldown_until = (datetime.now(timezone.utc) + timedelta(minutes=2)).isoformat()
            self.db.set_health_status(
                cfg_id,
                health_status="unhealthy",
                paused_until=cooldown_until,
                error_category=res.error_category or "transient_error",
            )
            last_failure_reason = f"Provider {api_cfg['display_name']} failed: {res.error_message or res.status}"

        # If all eligible providers failed:
        return {
            "success": False,
            "status": "all_providers_failed",
            "found": False,
            "lookup_input": hash_input,
            "hash": hash_input,
            "algorithm": algorithm,
            "algorithm_type": algorithm,
            "plaintext": None,
            "mode": "live",
            "error": "All available API providers failed or exceeded limits.",
            "message": "Unable to process your request. Please try again.",
            "duration": 0.0,
            "details": last_failure_reason,
        }
