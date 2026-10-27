"""
Automatic API selection and failover coordinator for Student Credentials Provider.

Manages priority-based provider selection, failover execution across multiple APIs,
quota exhaustion exclusion, rate-limit pause windows, and automatic recovery.
Neon PostgreSQL is the authoritative persistent store for all configurations and health states.
"""

from datetime import datetime, timedelta, timezone
import logging
import time
from typing import Any

from config import Config
from database import Database
from services.crypto import CredentialCrypto
from services.providers.registry import get_provider_adapter

logger = logging.getLogger(__name__)


class ApiFailoverCoordinator:
    """Coordinates priority-first API provider dispatch, failover, and health recovery."""

    def __init__(self, db: Database, crypto: CredentialCrypto, config: Config | None = None):
        self.db = db
        self.crypto = crypto
        self.config = config or Config()

    @staticmethod
    def order_configs_cyclically(
        configs: list[dict[str, Any]],
        last_config_id: int | None,
        last_priority: int | None,
    ) -> list[dict[str, Any]]:
        """
        Backward-compatibility helper: reorder configs into a cyclic rotation sequence.
        Note: Per system requirements, standard lookup execution uses priority-first selection.
        """
        if not configs:
            return []

        if last_config_id is not None:
            indices = [i for i, c in enumerate(configs) if c["id"] == last_config_id]
            if indices:
                start_idx = (indices[0] + 1) % len(configs)
                return configs[start_idx:] + configs[:start_idx]

        if last_priority is not None:
            after = [i for i, c in enumerate(configs) if c["priority"] > last_priority]
            if after:
                start_idx = after[0]
                return configs[start_idx:] + configs[:start_idx]
            return configs

        return configs

    def execute_lookup(self, hash_input: str, algorithm: str) -> dict[str, Any]:
        """
        Execute a hash lookup across eligible providers with strict priority ordering and failover.

        Selection Rules:
        1. Read the latest committed API configurations from PostgreSQL (ORDER BY priority ASC, id ASC).
        2. Filter out APIs that are manually disabled (enabled = 0) or temporarily ineligible (active cooldown).
        3. Attempt the highest-priority eligible API first (Priority 1 first).
        4. If it succeeds, return its result immediately without calling other providers.
        5. If it fails in a way that permits failover, attempt the next eligible API in priority order.
        6. Failed or exhausted APIs are never deleted; their health and cooldown states are persisted in PostgreSQL.
        """
        overall_start = time.time()

        # Validate input defensively
        if not hash_input or not str(hash_input).strip() or not algorithm or not str(algorithm).strip():
            return {
                "success": False,
                "status": "invalid_input",
                "found": False,
                "lookup_input": str(hash_input or ""),
                "hash": str(hash_input or ""),
                "algorithm": str(algorithm or ""),
                "algorithm_type": str(algorithm or ""),
                "plaintext": None,
                "mode": "live",
                "error": "Missing or invalid lookup input or algorithm.",
                "message": "Missing or invalid lookup input or algorithm.",
                "duration": 0.0,
            }

        # ── 1. Query latest eligible configurations directly from database ──
        # get_eligible_configs() unpauses expired cooldowns and filters (enabled=1, health_status='active')
        # ordered by priority ASC, id ASC.
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
                "error": "All configured APIs are currently unavailable. Please try again later.",
                "message": "All configured APIs are currently unavailable. Please try again later.",
                "duration": 0.0,
            }

        # ── 2. Order of attempts: Latest saved priority order (Priority 1 first) ─
        # Priority 1 is always attempted first for each new request.
        ordered_configs = list(eligible_configs)

        max_attempts = min(len(ordered_configs), getattr(self.config, "MAX_FAILOVER_ATTEMPTS", 5))
        attempted_ids: set[int] = set()
        last_failure_reason = "No provider succeeded."
        total_timeout = float(getattr(self.config, "STUDENT_LOOKUP_TIMEOUT_SECONDS", 10))

        # ── 3. Attempt providers in strict priority sequence ────────────────
        for i in range(max_attempts):
            api_cfg = ordered_configs[i]
            cfg_id = api_cfg["id"]

            if cfg_id in attempted_ids:
                continue
            attempted_ids.add(cfg_id)

            # Check overall request timeout
            elapsed = time.time() - overall_start
            remaining_timeout = total_timeout - elapsed
            if i > 0 and remaining_timeout <= 0.5:
                logger.warning("Overall lookup timeout approaching; terminating failover loop.")
                last_failure_reason = "Request timeout during provider failover."
                break

            provider_timeout = max(1.0, min(remaining_timeout, total_timeout))

            # Decrypt credential safely
            try:
                credential = self.crypto.decrypt(api_cfg["encrypted_credential"])
            except Exception as exc:
                logger.error("Failed to decrypt credentials for API ID %s: %s", cfg_id, exc.__class__.__name__)
                self.db.set_health_status(
                    cfg_id,
                    health_status="config_error",
                    paused_until=None,
                    error_category="decryption_error",
                    failure_reason=f"Decryption error: {exc.__class__.__name__}",
                )
                self.db.record_event(
                    cfg_id,
                    "auth_failure",
                    f"Decryption error: {exc.__class__.__name__}",
                )
                last_failure_reason = f"Provider {api_cfg['display_name']} configuration error."
                continue

            try:
                adapter = get_provider_adapter(api_cfg["provider_name"])
            except Exception as exc:
                logger.error("Failed to obtain adapter for %s: %s", api_cfg["provider_name"], exc)
                self.db.set_health_status(
                    cfg_id,
                    health_status="config_error",
                    paused_until=None,
                    error_category="adapter_error",
                    failure_reason=f"Unknown provider adapter: {exc}",
                )
                continue

            # Execute provider call (HTTP request - NO long database lock held)
            call_start = time.time()
            try:
                res = adapter.lookup(
                    credential=credential,
                    endpoint=api_cfg["endpoint"],
                    hash_input=hash_input,
                    algorithm=algorithm,
                    timeout=int(provider_timeout),
                )
            except Exception as exc:
                duration = round(time.time() - call_start, 4)
                logger.error("Provider %s raised unhandled exception: %s", api_cfg["display_name"], exc.__class__.__name__)
                from services.providers.base import ProviderLookupResult
                res = ProviderLookupResult(
                    success=False,
                    status="error",
                    found=False,
                    error_category="unexpected_error",
                    error_message=f"Provider call error: {exc.__class__.__name__}",
                    duration=duration,
                )

            # ── 3A. Terminal Lookup: Match found OR Verified negative result ──
            if res.is_terminal_lookup:
                self.db.record_terminal_success(
                    config_id=cfg_id,
                    event_category=res.status,
                    sanitized_message=res.error_message or f"Lookup returned {res.status}",
                    http_status=res.http_status,
                    duration=res.duration,
                    priority=api_cfg.get("priority"),
                )
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

            # Record non-terminal / failure event in history
            self.db.record_event(
                config_id=cfg_id,
                event_category=res.status,
                sanitized_message=res.error_message or f"Lookup returned {res.status}",
                http_status=res.http_status,
                duration=res.duration,
            )

            # ── 3B. Explicit Quota Exhaustion ─────────────────────────────────
            if res.status == "quota_exhausted":
                now_utc = datetime.now(timezone.utc)
                pause_minutes = getattr(self.config, "DEFAULT_PAUSE_DURATION_MINUTES", 60)
                if res.retry_after_seconds:
                    paused_until = (now_utc + timedelta(seconds=res.retry_after_seconds)).isoformat()
                else:
                    paused_until = (now_utc + timedelta(minutes=pause_minutes)).isoformat()

                self.db.set_health_status(
                    cfg_id,
                    health_status="quota_exhausted",
                    paused_until=paused_until,
                    error_category="quota_exhausted",
                    failure_reason=res.error_message or "API quota limit exhausted.",
                )
                last_failure_reason = f"Provider {api_cfg['display_name']} quota exhausted."
                continue

            # ── 3C. Rate Limited (HTTP 429) ────────────────────────────────────
            if res.status == "rate_limited" or res.http_status == 429:
                now_utc = datetime.now(timezone.utc)
                retry_seconds = res.retry_after_seconds or getattr(self.config, "RATE_LIMIT_COOLDOWN_SECONDS", 60)
                paused_until = (now_utc + timedelta(seconds=retry_seconds)).isoformat()

                self.db.set_health_status(
                    cfg_id,
                    health_status="rate_limited",
                    paused_until=paused_until,
                    error_category="rate_limited",
                    failure_reason=res.error_message or f"Rate limited. Retry after {retry_seconds}s.",
                )
                last_failure_reason = f"Provider {api_cfg['display_name']} rate limited."
                continue

            # ── 3D. Authentication / Permission Failure (HTTP 401/403) ────────
            if res.status in ("auth_failed", "config_error") or res.http_status in (401, 403):
                self.db.set_health_status(
                    cfg_id,
                    health_status="auth_failed",
                    paused_until=None,
                    error_category="auth_failed",
                    failure_reason=res.error_message or "Authentication credentials invalid.",
                )
                last_failure_reason = f"Provider {api_cfg['display_name']} authentication failed."
                continue

            # ── 3E. Server Errors (HTTP 5xx) ───────────────────────────────────
            if res.status == "server_error" or (res.http_status and res.http_status >= 500):
                cooldown_sec = getattr(self.config, "SERVER_ERROR_COOLDOWN_SECONDS", 60)
                cooldown_until = (datetime.now(timezone.utc) + timedelta(seconds=cooldown_sec)).isoformat()
                self.db.set_health_status(
                    cfg_id,
                    health_status="degraded",
                    paused_until=cooldown_until,
                    error_category="server_error",
                    failure_reason=res.error_message or f"Server returned HTTP {res.http_status}.",
                )
                last_failure_reason = f"Provider {api_cfg['display_name']} server error."
                continue

            # ── 3F. Network Timeout or Connection Error ────────────────────────
            if res.status in ("timeout", "connection_error") or res.error_category in ("network_timeout", "network_error"):
                cooldown_sec = getattr(self.config, "NETWORK_ERROR_COOLDOWN_SECONDS", 60)
                cooldown_until = (datetime.now(timezone.utc) + timedelta(seconds=cooldown_sec)).isoformat()
                self.db.set_health_status(
                    cfg_id,
                    health_status="temporarily_unavailable",
                    paused_until=cooldown_until,
                    error_category=res.error_category or "network_error",
                    failure_reason=res.error_message or "Network or connection error.",
                )
                last_failure_reason = f"Provider {api_cfg['display_name']} network/connection error."
                continue

            # ── 3G. Invalid provider response / Unexpected Schema ──────────────
            cooldown_until = (datetime.now(timezone.utc) + timedelta(seconds=60)).isoformat()
            self.db.set_health_status(
                cfg_id,
                health_status="degraded",
                paused_until=cooldown_until,
                error_category=res.error_category or "invalid_response",
                failure_reason=res.error_message or "Unexpected provider response.",
            )
            last_failure_reason = f"Provider {api_cfg['display_name']} unexpected response: {res.error_message or res.status}"

        # ── 4. All eligible providers attempted and failed ────────────────────
        total_duration = round(time.time() - overall_start, 4)
        logger.warning("All eligible providers failed or unavailable. Last reason: %s", last_failure_reason)
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
            "error": "All configured APIs are currently unavailable. Please try again later.",
            "message": "All configured APIs are currently unavailable. Please try again later.",
            "duration": total_duration,
            "details": last_failure_reason,
        }
