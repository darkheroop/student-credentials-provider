"""
Automatic API selection and failover coordinator for Student Credentials Provider.

Manages persistent cyclic provider rotation, priority ordering, quota exhaustion exclusion,
rate-limit pause windows, bounded failover, and automatic recovery across multiple API keys.
"""

from datetime import datetime, timedelta, timezone
from typing import Any

from config import Config
from database import Database
from services.crypto import CredentialCrypto
from services.providers.registry import get_provider_adapter


class ApiFailoverCoordinator:
    """Coordinates persistent cyclic API provider rotation, dispatch, and failover."""

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
        Reorder eligible configs (presorted by priority ASC, id ASC) into a cyclic rotation sequence.

        Priority determines the baseline cycle order:
          API A (Priority 1) -> API B (Priority 2) -> API C (Priority 3) -> API A...

        - If last_config_id was used previously and is eligible, rotation starts from the
          next eligible config in priority order (wrapping around cyclically).
        - If last_config_id is no longer in eligible configs (e.g. paused, exhausted, or deleted),
          last_priority is used to resume from the next available priority.
        """
        if not configs:
            return []

        # Case 1: last_config_id is currently among the eligible configs
        if last_config_id is not None:
            indices = [i for i, c in enumerate(configs) if c["id"] == last_config_id]
            if indices:
                start_idx = (indices[0] + 1) % len(configs)
                return configs[start_idx:] + configs[:start_idx]

        # Case 2: last_config_id is absent, but last_priority is known
        if last_priority is not None:
            # Find the first eligible config whose priority is strictly greater than last_priority
            after = [i for i, c in enumerate(configs) if c["priority"] > last_priority]
            if after:
                start_idx = after[0]
                return configs[start_idx:] + configs[:start_idx]
            else:
                # Wrap around to the start of the list
                return configs

        # Case 3: Initial or unspecified rotation state
        return configs

    def execute_lookup(self, hash_input: str, algorithm: str) -> dict[str, Any]:
        """
        Execute a hash lookup across eligible providers with persistent cyclic rotation and failover.
        Failed or exhausted APIs are never deleted; they are marked appropriately in PostgreSQL.
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
                "error": "All configured APIs are currently unavailable. Please try again later.",
                "message": "All configured APIs are currently unavailable. Please try again later.",
                "duration": 0.0,
            }

        # ── 1. Determine cyclic rotation order from persistent database state ─
        rotation_state = self.db.get_rotation_state()
        ordered_configs = self.order_configs_cyclically(
            eligible_configs,
            last_config_id=rotation_state.get("last_config_id"),
            last_priority=rotation_state.get("last_priority"),
        )

        max_attempts = min(len(ordered_configs), self.config.MAX_FAILOVER_ATTEMPTS)
        last_failure_reason = "No provider succeeded."

        # ── 2. Attempt providers in cyclic sequence ─────────────────────────
        for i in range(max_attempts):
            api_cfg = ordered_configs[i]
            cfg_id = api_cfg["id"]

            # Decrypt credential
            try:
                credential = self.crypto.decrypt(api_cfg["encrypted_credential"])
            except Exception as exc:
                self.db.set_health_status(
                    cfg_id,
                    health_status="config_error",
                    error_category="decryption_error",
                    failure_reason=f"Decryption error: {exc.__class__.__name__}",
                )
                self.db.record_event(
                    cfg_id,
                    "auth_failure",
                    f"Decryption error: {exc.__class__.__name__}",
                )
                continue

            adapter = get_provider_adapter(api_cfg["provider_name"])

            # Execute provider call (HTTP request - NO long database lock held)
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

            # ── 2A. Terminal Lookup: Match found OR Legitimate negative result ─
            if res.is_terminal_lookup:
                self.db.record_success(cfg_id, duration=res.duration)
                self.db.update_rotation_state(last_config_id=cfg_id, last_priority=api_cfg["priority"])
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

            # ── 2B. Explicit Quota Exhaustion ───────────────────────────────
            if res.status == "quota_exhausted":
                now_utc = datetime.now(timezone.utc)
                pause_minutes = self.config.DEFAULT_PAUSE_DURATION_MINUTES
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

            # ── 2C. Rate Limited (HTTP 429) ──────────────────────────────────
            if res.status == "rate_limited":
                now_utc = datetime.now(timezone.utc)
                retry_seconds = res.retry_after_seconds or 60
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

            # ── 2D. Authentication Failure (HTTP 401/403) ────────────────────
            if res.status in ("auth_failed", "config_error"):
                self.db.set_health_status(
                    cfg_id,
                    health_status=res.status,
                    paused_until=None,
                    error_category="auth_failed",
                    failure_reason=res.error_message or "Authentication credentials invalid.",
                )
                last_failure_reason = f"Provider {api_cfg['display_name']} authentication failed."
                continue

            # ── 2E. Server Errors (HTTP 5xx) ─────────────────────────────────
            if res.status == "server_error" or (res.http_status and res.http_status >= 500):
                cooldown_until = (datetime.now(timezone.utc) + timedelta(minutes=2)).isoformat()
                self.db.set_health_status(
                    cfg_id,
                    health_status="degraded",
                    paused_until=cooldown_until,
                    error_category="server_error",
                    failure_reason=res.error_message or f"Server returned HTTP {res.http_status}.",
                )
                last_failure_reason = f"Provider {api_cfg['display_name']} server error."
                continue

            # ── 2F. Network Timeout or Connection Error ──────────────────────
            cooldown_until = (datetime.now(timezone.utc) + timedelta(minutes=2)).isoformat()
            self.db.set_health_status(
                cfg_id,
                health_status="temporarily_unavailable",
                paused_until=cooldown_until,
                error_category=res.error_category or "network_error",
                failure_reason=res.error_message or "Network or connection error.",
            )
            last_failure_reason = f"Provider {api_cfg['display_name']} failed: {res.error_message or res.status}"

        # ── 3. All eligible providers attempted and failed ──────────────────
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
            "duration": 0.0,
            "details": last_failure_reason,
        }
