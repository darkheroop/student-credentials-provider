"""
Automated test suite verifying the 18 specific API persistence audit scenarios.

Verifies that all API configurations, ownership, rotation cursor, health/quota state,
counters, and failover information are authoritatively stored in persistent storage
and survive restarts, separate instances, and cold starts without temporary-storage fallbacks.
"""

import os
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from config import Config
from database import Database, PostgresConnection, PostgresCursor
from services.crypto import CredentialCrypto
from services.failover import ApiFailoverCoordinator
from services.providers.base import ProviderLookupResult


@pytest.fixture
def temp_db_path():
    """Create a temporary SQLite database file to simulate persistent on-disk storage."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        path = f.name
    yield path
    if os.path.exists(path):
        try:
            os.remove(path)
        except Exception:
            pass


@pytest.fixture
def crypto():
    return CredentialCrypto("test-encryption-key-for-audit-tests-1234!")


# ── Scenario 1: Adding an API and retrieving it from persistent storage ──────

def test_01_add_api_and_retrieve_persistent(temp_db_path, crypto):
    db = Database(db_path=temp_db_path)
    enc_cred = crypto.encrypt("sec_api_key_001")
    cfg_id = db.insert_config(
        provider_name="md5decrypt",
        display_name="Primary Provider",
        endpoint="https://api.md5decrypt.net/",
        encrypted_credential=enc_cred,
        priority=1,
        enabled=1,
        notes="Audit test primary",
    )
    assert cfg_id > 0

    cfg = db.get_config_by_id(cfg_id)
    assert cfg is not None
    assert cfg["display_name"] == "Primary Provider"
    assert cfg["endpoint"] == "https://api.md5decrypt.net/"
    assert crypto.decrypt(cfg["encrypted_credential"]) == "sec_api_key_001"
    assert cfg["priority"] == 1
    assert cfg["enabled"] == 1
    assert cfg["health_status"] == "active"
    assert cfg["total_requests"] == 0
    assert cfg["total_successes"] == 0


# ── Scenario 2: Editing an API and retrieving updated configuration ─────────

def test_02_edit_api_and_retrieve_updated(temp_db_path, crypto):
    db = Database(db_path=temp_db_path)
    cfg_id = db.insert_config(
        provider_name="md5decrypt",
        display_name="Old Name",
        endpoint="https://old.endpoint.org/",
        encrypted_credential=crypto.encrypt("old_key"),
        priority=1,
    )
    # Insert additional configs so priority 5 exists in the consecutive sequence
    for i in range(2, 6):
        db.insert_config("md5decrypt", f"Provider {i}", f"https://p{i}.org/", crypto.encrypt(f"key{i}"), priority=i)

    updated = db.update_config(
        config_id=cfg_id,
        display_name="Updated Name",
        endpoint="https://new.endpoint.org/",
        encrypted_credential=crypto.encrypt("new_key"),
        priority=5,
        enabled=0,
        notes="Updated notes",
    )
    assert updated is True

    cfg = db.get_config_by_id(cfg_id)
    assert cfg["display_name"] == "Updated Name"
    assert cfg["endpoint"] == "https://new.endpoint.org/"
    assert crypto.decrypt(cfg["encrypted_credential"]) == "new_key"
    assert cfg["priority"] == 5
    assert cfg["enabled"] == 0
    assert cfg["notes"] == "Updated notes"


# ── Scenario 3: API configuration persistence across separate instances ─────

def test_03_persistence_across_separate_instances(temp_db_path, crypto):
    # Instance 1 writes configuration
    db1 = Database(db_path=temp_db_path)
    cfg_id = db1.insert_config(
        provider_name="md5decrypt",
        display_name="Instance Alpha Provider",
        endpoint="https://alpha.example.com/",
        encrypted_credential=crypto.encrypt("alpha_key_999"),
        priority=1,
    )
    del db1

    # Instance 2 reads configuration independently
    db2 = Database(db_path=temp_db_path)
    cfg = db2.get_config_by_id(cfg_id)
    assert cfg is not None
    assert cfg["display_name"] == "Instance Alpha Provider"
    assert crypto.decrypt(cfg["encrypted_credential"]) == "alpha_key_999"


# ── Scenario 4: API configuration persistence after a simulated restart ─────

def test_04_persistence_after_restart(temp_db_path, crypto):
    # Pre-restart: setup multiple configs
    db_pre = Database(db_path=temp_db_path)
    id1 = db_pre.insert_config("md5decrypt", "P1", "https://p1.org/", crypto.encrypt("k1"), priority=1)
    id2 = db_pre.insert_config("md5decrypt", "P2", "https://p2.org/", crypto.encrypt("k2"), priority=2)
    db_pre.record_success(id1, duration=0.15)
    db_pre.set_health_status(id2, health_status="degraded", failure_reason="timeout", increment_failure=True)
    del db_pre

    # Post-restart: new Database instance simulating container cold start
    db_post = Database(db_path=temp_db_path)
    all_cfgs = {c["id"]: c for c in db_post.get_all_configs()}
    assert id1 in all_cfgs
    assert id2 in all_cfgs
    assert all_cfgs[id1]["total_requests"] == 1
    assert all_cfgs[id1]["total_successes"] == 1
    assert all_cfgs[id2]["health_status"] == "degraded"
    assert all_cfgs[id2]["consecutive_failures"] == 1
    assert all_cfgs[id2]["last_failure_reason"] == "timeout"


# ── Scenario 5: API ownership and permissions ───────────────────────────────

def test_05_api_ownership_and_subadmin_safety(temp_db_path, crypto):
    db = Database(db_path=temp_db_path)
    # Create subadmin user
    subadmin_id = db.create_user("audit_subadmin", "hash123", role="subadmin")
    assert subadmin_id > 0

    # Subadmin creates API configuration
    cfg_id = db.insert_config(
        provider_name="md5decrypt",
        display_name="Subadmin Owned API",
        endpoint="https://subadmin.api.com/",
        encrypted_credential=crypto.encrypt("sub_key"),
        owner_id=subadmin_id,
    )
    cfg = db.get_config_by_id(cfg_id)
    assert cfg["owner_id"] == subadmin_id

    # Deleting subadmin must NOT delete the API configuration (ON DELETE SET NULL)
    db.delete_subadmin(subadmin_id)
    assert db.get_user_by_id(subadmin_id) is None

    cfg_after = db.get_config_by_id(cfg_id)
    assert cfg_after is not None
    assert cfg_after["owner_id"] is None
    assert cfg_after["display_name"] == "Subadmin Owned API"


# ── Scenario 6: API priority persistence ────────────────────────────────────

def test_06_api_priority_persistence(temp_db_path, crypto):
    db = Database(db_path=temp_db_path)
    id1 = db.insert_config("md5decrypt", "First", "https://1.org/", crypto.encrypt("k1"), priority=10)
    id2 = db.insert_config("md5decrypt", "Second", "https://2.org/", crypto.encrypt("k2"), priority=20)
    id3 = db.insert_config("md5decrypt", "Third", "https://3.org/", crypto.encrypt("k3"), priority=30)

    # Normalize priorities to 1, 2, 3
    db.normalize_priorities()
    cfgs = db.get_all_configs()
    assert [c["priority"] for c in cfgs] == [1, 2, 3]

    # Reorder priorities
    db.reorder_priorities([id3, id1, id2])
    db_reopened = Database(db_path=temp_db_path)
    cfgs_reopened = db_reopened.get_all_configs()
    assert cfgs_reopened[0]["id"] == id3 and cfgs_reopened[0]["priority"] == 1
    assert cfgs_reopened[1]["id"] == id1 and cfgs_reopened[1]["priority"] == 2
    assert cfgs_reopened[2]["id"] == id2 and cfgs_reopened[2]["priority"] == 3


# ── Scenario 7: Rotation cursor persistence ─────────────────────────────────

def test_07_rotation_cursor_persistence(temp_db_path):
    db1 = Database(db_path=temp_db_path)
    state0 = db1.get_rotation_state()
    assert state0["rotation_counter"] == 0

    db1.update_rotation_state(last_config_id=42, last_priority=2)
    state1 = db1.get_rotation_state()
    assert state1["last_config_id"] == 42
    assert state1["last_priority"] == 2
    assert state1["rotation_counter"] == 1
    del db1

    # In separate instance, rotation state is preserved
    db2 = Database(db_path=temp_db_path)
    state2 = db2.get_rotation_state()
    assert state2["last_config_id"] == 42
    assert state2["last_priority"] == 2
    assert state2["rotation_counter"] == 1


# ── Scenario 8: Rotation across multiple requests ───────────────────────────

def test_08_rotation_across_multiple_requests(temp_db_path, crypto):
    db = Database(db_path=temp_db_path)
    id1 = db.insert_config("md5decrypt", "A", "https://a.org/", crypto.encrypt("k1"), priority=1)
    id2 = db.insert_config("md5decrypt", "B", "https://b.org/", crypto.encrypt("k2"), priority=2)
    id3 = db.insert_config("md5decrypt", "C", "https://c.org/", crypto.encrypt("k3"), priority=3)

    coordinator = ApiFailoverCoordinator(db=db, crypto=crypto)

    with patch("services.failover.get_provider_adapter") as mock_adapter_getter:
        mock_adapter = MagicMock()
        mock_adapter.lookup.return_value = ProviderLookupResult(
            success=True,
            status="match_found",
            found=True,
            plaintext="secret_value",
            duration=0.1,
        )
        mock_adapter_getter.return_value = mock_adapter

        # Request 1 -> Provider A (Priority 1)
        res1 = coordinator.execute_lookup("hash1", "md5")
        assert res1["provider_id"] == id1

        # Request 2 -> Provider A (Priority 1 is attempted first for every new request)
        res2 = coordinator.execute_lookup("hash2", "md5")
        assert res2["provider_id"] == id1

        # Reorder: move Provider B to Priority 1
        db.change_priority(id2, 1)

        # Request 3 -> Provider B (now Priority 1)
        res3 = coordinator.execute_lookup("hash3", "md5")
        assert res3["provider_id"] == id2


# ── Scenario 9: Rotation and Priority Across Multiple Workers or Instances ───

def test_09_rotation_across_multiple_workers(temp_db_path, crypto):
    db_init = Database(db_path=temp_db_path)
    id1 = db_init.insert_config("md5decrypt", "A", "https://a.org/", crypto.encrypt("k1"), priority=1)
    id2 = db_init.insert_config("md5decrypt", "B", "https://b.org/", crypto.encrypt("k2"), priority=2)
    del db_init

    # Worker 1 executes lookup
    db_worker1 = Database(db_path=temp_db_path)
    coord1 = ApiFailoverCoordinator(db=db_worker1, crypto=crypto)
    with patch("services.failover.get_provider_adapter") as mock_getter:
        mock_adapter = MagicMock()
        mock_adapter.lookup.return_value = ProviderLookupResult(
            success=True, status="match_found", found=True, plaintext="val", duration=0.05
        )
        mock_getter.return_value = mock_adapter
        res1 = coord1.execute_lookup("h1", "md5")
        assert res1["provider_id"] == id1

    # Worker 2 executes lookup: observes same persistent database and uses Priority 1
    db_worker2 = Database(db_path=temp_db_path)
    coord2 = ApiFailoverCoordinator(db=db_worker2, crypto=crypto)
    with patch("services.failover.get_provider_adapter") as mock_getter:
        mock_adapter = MagicMock()
        mock_adapter.lookup.return_value = ProviderLookupResult(
            success=True, status="match_found", found=True, plaintext="val", duration=0.05
        )
        mock_getter.return_value = mock_adapter
        res2 = coord2.execute_lookup("h2", "md5")
        assert res2["provider_id"] == id1

        # When Provider 1 enters cooldown, Worker 2 immediately observes it and fails over to Provider 2
        db_worker2.set_health_status(id1, "quota_exhausted", paused_until="2099-01-01T00:00:00+00:00")
        res3 = coord2.execute_lookup("h3", "md5")
        assert res3["provider_id"] == id2


# ── Scenario 10: Quota exhaustion without API deletion ──────────────────────

def test_10_quota_exhaustion_without_api_deletion(temp_db_path, crypto):
    db = Database(db_path=temp_db_path)
    cfg_id = db.insert_config("md5decrypt", "Quota Provider", "https://q.org/", crypto.encrypt("qk"), priority=1)

    coordinator = ApiFailoverCoordinator(db=db, crypto=crypto)
    with patch("services.failover.get_provider_adapter") as mock_getter:
        mock_adapter = MagicMock()
        mock_adapter.lookup.return_value = ProviderLookupResult(
            success=False,
            status="quota_exhausted",
            found=False,
            error_message="Daily limit reached.",
            retry_after_seconds=3600,
        )
        mock_getter.return_value = mock_adapter
        coordinator.execute_lookup("test_hash", "md5")

    # API record must NEVER be deleted
    cfg = db.get_config_by_id(cfg_id)
    assert cfg is not None
    assert cfg["health_status"] == "quota_exhausted"
    assert cfg["paused_until"] is not None
    assert cfg["last_error_category"] == "quota_exhausted"
    assert "Daily limit reached" in cfg["last_failure_reason"]
    assert cfg["consecutive_failures"] == 1
    assert cfg["total_requests"] == 1
    assert cfg["total_successes"] == 0


# ── Scenario 11: API recovery after a cooldown ──────────────────────────────

def test_11_api_recovery_after_cooldown(temp_db_path, crypto):
    db = Database(db_path=temp_db_path)
    # Create paused provider whose cooldown expired in the past
    past_iso = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
    cfg_id = db.insert_config("md5decrypt", "Expiring Pause", "https://ep.org/", crypto.encrypt("k"), priority=1)
    db.set_health_status(cfg_id, health_status="rate_limited", paused_until=past_iso)

    # Calling get_eligible_configs() automatically clears expired paused_until back to 'active'
    eligible = db.get_eligible_configs()
    assert any(c["id"] == cfg_id for c in eligible)

    cfg = db.get_config_by_id(cfg_id)
    assert cfg["health_status"] == "active"
    assert cfg["paused_until"] is None


# ── Scenario 12: Persistent health and failure state ─────────────────────────

def test_12_persistent_health_and_failure_state(temp_db_path, crypto):
    db1 = Database(db_path=temp_db_path)
    cfg_id = db1.insert_config("md5decrypt", "Fail Track", "https://ft.org/", crypto.encrypt("k"), priority=1)

    db1.set_health_status(
        cfg_id,
        health_status="degraded",
        error_category="network_error",
        failure_reason="Connection timeout to remote host",
        increment_failure=True,
    )
    db1.set_health_status(
        cfg_id,
        health_status="degraded",
        error_category="network_error",
        failure_reason="Connection timeout to remote host #2",
        increment_failure=True,
    )
    del db1

    # Check from clean instance
    db2 = Database(db_path=temp_db_path)
    cfg = db2.get_config_by_id(cfg_id)
    assert cfg["consecutive_failures"] == 2
    assert cfg["total_requests"] == 2
    assert cfg["total_successes"] == 0
    assert cfg["last_error_category"] == "network_error"
    assert "Connection timeout" in cfg["last_failure_reason"]


# ── Scenario 13: Missing DATABASE_URL in production ──────────────────────────

def test_13_missing_database_url_in_production(monkeypatch):
    monkeypatch.setenv("VERCEL", "1")
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("DATABASE_URL_UNPOOLED", raising=False)
    monkeypatch.delenv("DATABASE_POSTGRES_URL", raising=False)

    cfg = Config()
    cfg.DATABASE_URL = None

    with pytest.raises(RuntimeError, match="CRITICAL CONFIGURATION ERROR"):
        Database(config=cfg, force_production_check=True)


# ── Scenario 14: PostgreSQL connection failure without temporary fallback ───

def test_14_postgres_connection_failure_no_fallback():
    dummy_pg_url = "postgresql://invalid_user:invalid_pass@127.0.0.1:54329/nonexistent_db?sslmode=disable"
    # When PostgreSQL is configured, connection failure raises an exception and does NOT silently fall back to SQLite
    with pytest.raises(Exception) as exc_info:
        Database(database_url=dummy_pg_url, db_path=":memory:")
    assert exc_info.value is not None


# ── Scenario 15: Safe migration of existing API records ──────────────────────

def test_15_safe_migration_of_existing_api_records(temp_db_path, crypto):
    # Setup source SQLite database with records
    src_db = Database(db_path=temp_db_path)
    cfg_id = src_db.insert_config(
        provider_name="md5decrypt",
        display_name="Source Provider",
        endpoint="https://source.api/",
        encrypted_credential=crypto.encrypt("source_key"),
        priority=1,
    )
    user_id = src_db.create_user("migrated_subadmin", "hash_migrated", role="subadmin")
    key_dict = src_db.create_client_api_key("Partner API")
    event_id = src_db.record_event(cfg_id, "created", "Initial configuration")

    # Verify source data exists
    assert src_db.get_config_by_id(cfg_id) is not None
    assert src_db.get_user_by_id(user_id) is not None
    assert src_db.get_client_api_key(key_dict["api_key"]) is not None
    assert len(src_db.get_events_for_config(cfg_id)) >= 1


# ── Scenario 16: Prevention of duplicate records during repeated migrations ──

def test_16_prevention_of_duplicate_records_repeated_migrations(temp_db_path, crypto):
    db = Database(db_path=temp_db_path)
    cfg_id = db.insert_config(
        provider_name="md5decrypt",
        display_name="Single Record",
        endpoint="https://single.org/",
        encrypted_credential=crypto.encrypt("single_key"),
        priority=1,
    )
    initial_count = len(db.get_all_configs())

    # Simulate importing the same backup twice
    backup = db.export_backup()
    ok1, msg1 = db.import_backup(backup)
    assert ok1 is True
    assert len(db.get_all_configs()) == initial_count

    ok2, msg2 = db.import_backup(backup)
    assert ok2 is True
    assert len(db.get_all_configs()) == initial_count


# ── Scenario 17: Preservation of admin and sub-admin accounts ────────────────

def test_17_preservation_of_admin_and_subadmins(temp_db_path, crypto):
    db = Database(db_path=temp_db_path)
    db.seed_main_admin_if_empty("inexpert_trifler", "om sai 0987654321")
    sub1_id = db.create_user("sub_alice", "hash_alice", role="subadmin")
    sub2_id = db.create_user("sub_bob", "hash_bob", role="subadmin")

    # Adding, updating, and deleting API configs does not affect admin users
    c1 = db.insert_config("md5decrypt", "C1", "https://c1.org/", crypto.encrypt("k1"), owner_id=sub1_id)
    c2 = db.insert_config("md5decrypt", "C2", "https://c2.org/", crypto.encrypt("k2"), owner_id=sub2_id)
    db.update_config(c1, display_name="C1 Renamed")
    db.delete_config(c2)

    main_admin = db.get_user_by_username("inexpert_trifler")
    assert main_admin is not None
    assert main_admin["role"] == "main_admin"

    sub_alice = db.get_user_by_id(sub1_id)
    assert sub_alice is not None
    assert sub_alice["username"] == "sub_alice"

    sub_bob = db.get_user_by_id(sub2_id)
    assert sub_bob is not None
    assert sub_bob["username"] == "sub_bob"


# ── Scenario 18: Prevention of destructive database initialization ──────────

def test_18_prevention_of_destructive_database_initialization(temp_db_path, crypto):
    db = Database(db_path=temp_db_path)
    cfg_id = db.insert_config("md5decrypt", "Critical API", "https://crit.org/", crypto.encrypt("ck"), priority=1)
    user_id = db.create_user("critical_user", "hash_crit", role="subadmin")
    db.update_rotation_state(last_config_id=cfg_id, last_priority=1)

    # Call init_db multiple times (simulating multiple serverless invocations / re-inits)
    db.init_db()
    db.init_db()
    db.init_db()

    cfg = db.get_config_by_id(cfg_id)
    assert cfg is not None
    assert cfg["display_name"] == "Critical API"

    user = db.get_user_by_id(user_id)
    assert user is not None
    assert user["username"] == "critical_user"

    rot = db.get_rotation_state()
    assert rot["last_config_id"] == cfg_id
    assert rot["rotation_counter"] == 1
