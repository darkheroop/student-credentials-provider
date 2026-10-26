"""
Database module for Student Credentials Provider.

Provides SQLite persistence for dynamic API configurations and event history,
supporting thread-safe connections, automatic schema initialization,
health status tracking, and failover eligibility queries.
"""

import json
import os
import sqlite3
from datetime import datetime, timezone
from typing import Any

from config import Config
from services.crypto import CredentialCrypto


def _utc_now_iso() -> str:
    """Return current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


class Database:
    """SQLite database manager for API configurations and event history."""

    def __init__(self, db_path: str | None = None, config: Config | None = None):
        self.config = config or Config()
        self.db_path = db_path or self.config.DATABASE_PATH
        self._ensure_parent_dir()
        self.init_db()

    def _ensure_parent_dir(self):
        """Ensure parent directory of database file exists."""
        if self.db_path and self.db_path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)

    def get_connection(self) -> sqlite3.Connection:
        """Create and return a new SQLite connection with row factory."""
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn

    def init_db(self):
        """Create database tables and indexes if they do not exist."""
        with self.get_connection() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS api_configurations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    provider_name TEXT NOT NULL,
                    display_name TEXT NOT NULL,
                    endpoint TEXT NOT NULL,
                    encrypted_credential TEXT NOT NULL,
                    auth_config TEXT DEFAULT '{}',
                    provider_config TEXT DEFAULT '{}',
                    priority INTEGER NOT NULL DEFAULT 10,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    health_status TEXT NOT NULL DEFAULT 'active',
                    paused_until TEXT DEFAULT NULL,
                    last_success_at TEXT DEFAULT NULL,
                    last_failure_at TEXT DEFAULT NULL,
                    last_error_category TEXT DEFAULT NULL,
                    notes TEXT DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS api_event_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    api_config_id INTEGER NOT NULL,
                    event_category TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    sanitized_message TEXT NOT NULL,
                    http_status INTEGER DEFAULT NULL,
                    duration REAL DEFAULT 0.0,
                    FOREIGN KEY (api_config_id) REFERENCES api_configurations(id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_api_config_eligibility
                ON api_configurations(enabled, health_status, priority);

                CREATE INDEX IF NOT EXISTS idx_api_event_history_config
                ON api_event_history(api_config_id, timestamp);
            """)
            conn.commit()

    # ── Configuration Queries ───────────────────────────────────────────

    def get_all_configs(self, enabled_only: bool = False) -> list[dict[str, Any]]:
        """Retrieve all API configurations, ordered by priority and creation."""
        with self.get_connection() as conn:
            if enabled_only:
                cursor = conn.execute(
                    "SELECT * FROM api_configurations WHERE enabled = 1 ORDER BY priority ASC, id ASC"
                )
            else:
                cursor = conn.execute(
                    "SELECT * FROM api_configurations ORDER BY priority ASC, id ASC"
                )
            rows = cursor.fetchall()
            return [dict(r) for r in rows]

    def get_config_by_id(self, config_id: int) -> dict[str, Any] | None:
        """Retrieve a specific API configuration by ID."""
        with self.get_connection() as conn:
            cursor = conn.execute("SELECT * FROM api_configurations WHERE id = ?", (config_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_eligible_configs(self) -> list[dict[str, Any]]:
        """
        Retrieve all enabled, healthy, non-paused API configurations,
        ordered by priority (ascending).
        
        Automatically clears expired paused_until windows back to 'active'.
        """
        now_iso = _utc_now_iso()
        with self.get_connection() as conn:
            # First: automatically unpause configurations whose pause window has passed
            conn.execute(
                """
                UPDATE api_configurations
                SET health_status = 'active', paused_until = NULL, updated_at = ?
                WHERE enabled = 1
                  AND paused_until IS NOT NULL
                  AND paused_until <= ?
                """,
                (now_iso, now_iso),
            )
            conn.commit()

            cursor = conn.execute(
                """
                SELECT * FROM api_configurations
                WHERE enabled = 1
                  AND health_status = 'active'
                ORDER BY priority ASC, id ASC
                """
            )
            return [dict(r) for r in cursor.fetchall()]

    def insert_config(
        self,
        provider_name: str,
        display_name: str,
        endpoint: str,
        encrypted_credential: str,
        priority: int = 10,
        enabled: int = 1,
        auth_config: dict | None = None,
        provider_config: dict | None = None,
        notes: str = "",
    ) -> int:
        """Insert a new API configuration record and return its ID."""
        now_iso = _utc_now_iso()
        auth_json = json.dumps(auth_config or {})
        provider_json = json.dumps(provider_config or {})

        with self.get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO api_configurations (
                    provider_name, display_name, endpoint, encrypted_credential,
                    auth_config, provider_config, priority, enabled,
                    health_status, notes, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)
                """,
                (
                    provider_name.strip().lower(),
                    display_name.strip(),
                    endpoint.strip(),
                    encrypted_credential,
                    auth_json,
                    provider_json,
                    int(priority),
                    1 if enabled else 0,
                    (notes or "").strip(),
                    now_iso,
                    now_iso,
                ),
            )
            conn.commit()
            return cursor.lastrowid

    def update_config(
        self,
        config_id: int,
        display_name: str | None = None,
        endpoint: str | None = None,
        encrypted_credential: str | None = None,
        priority: int | None = None,
        enabled: int | None = None,
        notes: str | None = None,
        auth_config: dict | None = None,
        provider_config: dict | None = None,
    ) -> bool:
        """Update an existing configuration without overwriting unset fields."""
        existing = self.get_config_by_id(config_id)
        if not existing:
            return False

        now_iso = _utc_now_iso()
        new_name = display_name.strip() if display_name is not None else existing["display_name"]
        new_endpoint = endpoint.strip() if endpoint is not None else existing["endpoint"]
        new_cred = encrypted_credential if encrypted_credential is not None else existing["encrypted_credential"]
        new_priority = int(priority) if priority is not None else existing["priority"]
        new_enabled = (1 if enabled else 0) if enabled is not None else existing["enabled"]
        new_notes = notes.strip() if notes is not None else existing["notes"]
        new_auth = json.dumps(auth_config) if auth_config is not None else existing["auth_config"]
        new_prov = json.dumps(provider_config) if provider_config is not None else existing["provider_config"]

        with self.get_connection() as conn:
            conn.execute(
                """
                UPDATE api_configurations
                SET display_name = ?,
                    endpoint = ?,
                    encrypted_credential = ?,
                    priority = ?,
                    enabled = ?,
                    notes = ?,
                    auth_config = ?,
                    provider_config = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    new_name,
                    new_endpoint,
                    new_cred,
                    new_priority,
                    new_enabled,
                    new_notes,
                    new_auth,
                    new_prov,
                    now_iso,
                    config_id,
                ),
            )
            conn.commit()
            return True

    def delete_config(self, config_id: int) -> bool:
        """Delete an API configuration and its event history."""
        with self.get_connection() as conn:
            cursor = conn.execute("DELETE FROM api_configurations WHERE id = ?", (config_id,))
            conn.commit()
            return cursor.rowcount > 0

    def set_enabled(self, config_id: int, enabled: bool) -> bool:
        """Toggle an API configuration's enabled state."""
        now_iso = _utc_now_iso()
        with self.get_connection() as conn:
            cursor = conn.execute(
                "UPDATE api_configurations SET enabled = ?, updated_at = ? WHERE id = ?",
                (1 if enabled else 0, now_iso, config_id),
            )
            conn.commit()
            return cursor.rowcount > 0

    def set_health_status(
        self,
        config_id: int,
        health_status: str,
        paused_until: str | None = None,
        error_category: str | None = None,
    ) -> bool:
        """Update the health/availability status of an API configuration."""
        now_iso = _utc_now_iso()
        with self.get_connection() as conn:
            cursor = conn.execute(
                """
                UPDATE api_configurations
                SET health_status = ?,
                    paused_until = ?,
                    last_failure_at = ?,
                    last_error_category = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (health_status, paused_until, now_iso, error_category, now_iso, config_id),
            )
            conn.commit()
            return cursor.rowcount > 0

    def record_success(self, config_id: int, duration: float = 0.0) -> bool:
        """Update last_success_at and reset error category upon successful call."""
        now_iso = _utc_now_iso()
        with self.get_connection() as conn:
            cursor = conn.execute(
                """
                UPDATE api_configurations
                SET health_status = 'active',
                    paused_until = NULL,
                    last_success_at = ?,
                    last_error_category = NULL,
                    updated_at = ?
                WHERE id = ?
                """,
                (now_iso, now_iso, config_id),
            )
            conn.commit()
            return cursor.rowcount > 0

    def reactivate(self, config_id: int) -> bool:
        """Manually reactivate a paused or quota-exhausted configuration."""
        now_iso = _utc_now_iso()
        with self.get_connection() as conn:
            cursor = conn.execute(
                """
                UPDATE api_configurations
                SET health_status = 'active',
                    paused_until = NULL,
                    last_error_category = NULL,
                    updated_at = ?
                WHERE id = ?
                """,
                (now_iso, config_id),
            )
            conn.commit()
            return cursor.rowcount > 0

    # ── Event History ───────────────────────────────────────────────────

    def record_event(
        self,
        config_id: int,
        event_category: str,
        sanitized_message: str,
        http_status: int | None = None,
        duration: float = 0.0,
    ) -> int:
        """Record a sanitized event entry in history."""
        now_iso = _utc_now_iso()
        with self.get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO api_event_history (
                    api_config_id, event_category, timestamp,
                    sanitized_message, http_status, duration
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (config_id, event_category, now_iso, sanitized_message, http_status, float(duration)),
            )
            # Bound history size: keep at most 200 events per config
            conn.execute(
                """
                DELETE FROM api_event_history
                WHERE id IN (
                    SELECT id FROM api_event_history
                    WHERE api_config_id = ?
                    ORDER BY timestamp DESC
                    LIMIT -1 OFFSET 200
                )
                """,
                (config_id,),
            )
            conn.commit()
            return cursor.lastrowid

    def get_events_for_config(self, config_id: int, limit: int = 50) -> list[dict[str, Any]]:
        """Retrieve recent sanitized events for a specific API configuration."""
        with self.get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT * FROM api_event_history
                WHERE api_config_id = ?
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (config_id, limit),
            )
            return [dict(r) for r in cursor.fetchall()]

    # ── Startup Seeding ─────────────────────────────────────────────────

    def seed_default_if_empty(self, crypto: CredentialCrypto) -> bool:
        """
        Seed the initial MD5Decrypt provider from environment variables if the
        configuration table is currently empty.
        """
        all_configs = self.get_all_configs()
        if all_configs:
            return False

        key = self.config.MD5DECRYPT_API_KEY
        if not key or key == "replace_with_your_api_key":
            return False

        encrypted = crypto.encrypt(key)
        self.insert_config(
            provider_name="md5decrypt",
            display_name="MD5Decrypt Default",
            endpoint=self.config.MD5DECRYPT_API_URL or "https://api.md5decrypt.net/",
            encrypted_credential=encrypted,
            priority=10,
            enabled=1,
            notes="Initial default provider seeded from environment variable.",
        )
        return True
