"""
Automated tests for automatic priority reordering, shift behaviors, concurrency safety,
and authorization rules in Student Credentials Provider.

Covers all 18 scenarios specified in Section 9 of the requirements.
"""

import os
import tempfile
import threading
from unittest.mock import MagicMock, patch

import pytest
from flask import json

from app import app
from config import Config
from database import Database
from services.crypto import CredentialCrypto
from services.failover import ApiFailoverCoordinator
from services.priority import validate_priority_input, calculate_reordered_sequence
from services.providers.base import ProviderLookupResult


@pytest.fixture
def temp_db():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        path = f.name
    db = Database(db_path=path)
    crypto = CredentialCrypto("test-priority-secret-encryption-key-123!")
    yield db, crypto, path
    if os.path.exists(path):
        try:
            os.remove(path)
        except Exception:
            pass


@pytest.fixture
def client(temp_db):
    db, crypto, _ = temp_db
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False

    with patch("admin_routes.Database", return_value=db):
        with app.test_client() as c:
            yield c, db, crypto


# ── 1. Moving the last API to priority 1 (Example A) ─────────────────────────

def test_01_move_last_api_to_priority_1(temp_db):
    db, crypto, _ = temp_db
    # Before: API 1 (P1), API 2 (P2), API 3 (P3)
    id1 = db.insert_config("md5decrypt", "API 1", "https://api1.org/", crypto.encrypt("k1"), priority=1)
    id2 = db.insert_config("md5decrypt", "API 2", "https://api2.org/", crypto.encrypt("k2"), priority=2)
    id3 = db.insert_config("md5decrypt", "API 3", "https://api3.org/", crypto.encrypt("k3"), priority=3)

    # Change API 3 priority to 1
    updated = db.change_priority(id3, 1)

    # Expected: API 3 (P1), API 1 (P2), API 2 (P3)
    assert [c["id"] for c in updated] == [id3, id1, id2]
    assert [c["priority"] for c in updated] == [1, 2, 3]


# ── 2. Moving the first API to the last position (Example B) ─────────────────

def test_02_move_first_api_to_last_position(temp_db):
    db, crypto, _ = temp_db
    # Before: API 1 (P1), API 2 (P2), API 3 (P3)
    id1 = db.insert_config("md5decrypt", "API 1", "https://api1.org/", crypto.encrypt("k1"), priority=1)
    id2 = db.insert_config("md5decrypt", "API 2", "https://api2.org/", crypto.encrypt("k2"), priority=2)
    id3 = db.insert_config("md5decrypt", "API 3", "https://api3.org/", crypto.encrypt("k3"), priority=3)

    # Change API 1 priority to 3
    updated = db.change_priority(id1, 3)

    # Expected: API 2 (P1), API 3 (P2), API 1 (P3)
    assert [c["id"] for c in updated] == [id2, id3, id1]
    assert [c["priority"] for c in updated] == [1, 2, 3]


# ── 3. Moving an API to a middle position (Example C & D) ───────────────────

def test_03_move_api_to_middle_position(temp_db):
    db, crypto, _ = temp_db
    # Example C: API 3 moved to priority 2
    id1 = db.insert_config("md5decrypt", "API 1", "https://api1.org/", crypto.encrypt("k1"), priority=1)
    id2 = db.insert_config("md5decrypt", "API 2", "https://api2.org/", crypto.encrypt("k2"), priority=2)
    id3 = db.insert_config("md5decrypt", "API 3", "https://api3.org/", crypto.encrypt("k3"), priority=3)

    updated_c = db.change_priority(id3, 2)
    # Expected: API 1 (P1), API 3 (P2), API 2 (P3)
    assert [c["id"] for c in updated_c] == [id1, id3, id2]
    assert [c["priority"] for c in updated_c] == [1, 2, 3]

    # Reset
    db.normalize_priorities()

    # Example D: API 1 moved to priority 2
    # Before: API 1 (P1), API 3 (P2), API 2 (P3) -> normalize gives [id1, id3, id2] as [P1, P2, P3]
    # Let's test standard [API 1 (P1), API 2 (P2), API 3 (P3)]
    db.reorder_priorities([id1, id2, id3])
    updated_d = db.change_priority(id1, 2)
    # Expected: API 2 (P1), API 1 (P2), API 3 (P3)
    assert [c["id"] for c in updated_d] == [id2, id1, id3]
    assert [c["priority"] for c in updated_d] == [1, 2, 3]


# ── 4. Moving an API one position up ─────────────────────────────────────────

def test_04_move_one_position_up(temp_db):
    db, crypto, _ = temp_db
    id1 = db.insert_config("md5decrypt", "API 1", "https://1.org/", crypto.encrypt("k1"), priority=1)
    id2 = db.insert_config("md5decrypt", "API 2", "https://2.org/", crypto.encrypt("k2"), priority=2)
    id3 = db.insert_config("md5decrypt", "API 3", "https://3.org/", crypto.encrypt("k3"), priority=3)

    success = db.move_priority(id2, "up")
    assert success is True

    cfgs = db.get_all_configs()
    assert [c["id"] for c in cfgs] == [id2, id1, id3]
    assert [c["priority"] for c in cfgs] == [1, 2, 3]

    # Moving top item up is a safe no-op returning False
    assert db.move_priority(id2, "up") is False


# ── 5. Moving an API one position down ───────────────────────────────────────

def test_05_move_one_position_down(temp_db):
    db, crypto, _ = temp_db
    id1 = db.insert_config("md5decrypt", "API 1", "https://1.org/", crypto.encrypt("k1"), priority=1)
    id2 = db.insert_config("md5decrypt", "API 2", "https://2.org/", crypto.encrypt("k2"), priority=2)
    id3 = db.insert_config("md5decrypt", "API 3", "https://3.org/", crypto.encrypt("k3"), priority=3)

    success = db.move_priority(id2, "down")
    assert success is True

    cfgs = db.get_all_configs()
    assert [c["id"] for c in cfgs] == [id1, id3, id2]
    assert [c["priority"] for c in cfgs] == [1, 2, 3]

    # Moving bottom item down is a safe no-op returning False
    assert db.move_priority(id2, "down") is False


# ── 6. Reordering a single API ───────────────────────────────────────────────

def test_06_reorder_single_api(temp_db):
    db, crypto, _ = temp_db
    id1 = db.insert_config("md5decrypt", "Sole API", "https://solo.org/", crypto.encrypt("k1"), priority=1)

    updated1 = db.change_priority(id1, 1)
    assert len(updated1) == 1
    assert updated1[0]["priority"] == 1

    # Setting priority 5 on single API clamps to 1
    updated2 = db.change_priority(id1, 5)
    assert len(updated2) == 1
    assert updated2[0]["priority"] == 1


# ── 7. Rejecting priority zero ───────────────────────────────────────────────

def test_07_reject_priority_zero():
    with pytest.raises(ValueError, match="greater than or equal to 1"):
        validate_priority_input(0)

    with pytest.raises(ValueError, match="greater than or equal to 1"):
        validate_priority_input("0")


# ── 8. Rejecting negative priorities ─────────────────────────────────────────

def test_08_reject_negative_priorities():
    with pytest.raises(ValueError, match="greater than or equal to 1"):
        validate_priority_input(-1)

    with pytest.raises(ValueError, match="greater than or equal to 1"):
        validate_priority_input("-5")


# ── 9. Rejecting malformed priority values ───────────────────────────────────

def test_09_reject_malformed_priority_values():
    malformed_values = ["abc", "1.5", 2.7, True, False, None, "", [], {}]
    for val in malformed_values:
        with pytest.raises(ValueError):
            validate_priority_input(val)


# ── 10. Ensuring there are no duplicate priorities ───────────────────────────

def test_10_no_duplicate_priorities(temp_db):
    db, crypto, _ = temp_db
    ids = [
        db.insert_config("md5decrypt", f"API {i}", f"https://api{i}.org/", crypto.encrypt(f"k{i}"), priority=i)
        for i in range(1, 6)
    ]

    # Perform multiple shifts and out-of-bound requests
    db.change_priority(ids[4], 1)
    db.change_priority(ids[2], 99)  # Clamped to 5
    db.change_priority(ids[0], 2)

    cfgs = db.get_all_configs()
    priorities = [c["priority"] for c in cfgs]
    assert len(priorities) == len(set(priorities)), "Priorities must be strictly unique"


# ── 11. Ensuring priorities remain consecutive ───────────────────────────────

def test_11_priorities_remain_consecutive(temp_db):
    db, crypto, _ = temp_db
    ids = [
        db.insert_config("md5decrypt", f"API {i}", f"https://api{i}.org/", crypto.encrypt(f"k{i}"), priority=i)
        for i in range(1, 6)
    ]

    # Move elements back and forth
    db.change_priority(ids[0], 4)
    db.change_priority(ids[3], 1)

    cfgs = db.get_all_configs()
    priorities = [c["priority"] for c in cfgs]
    assert priorities == list(range(1, len(ids) + 1)), "Priorities must strictly equal 1..N"


# ── 12. Rolling back when a database update fails ────────────────────────────

def test_12_rollback_on_database_update_failure(temp_db):
    db, crypto, _ = temp_db
    id1 = db.insert_config("md5decrypt", "API 1", "https://1.org/", crypto.encrypt("k1"), priority=1)
    id2 = db.insert_config("md5decrypt", "API 2", "https://2.org/", crypto.encrypt("k2"), priority=2)

    # Monkeypatch execute during priority shift to simulate DB failure
    original_get_conn = db.get_connection

    class FailingConnection:
        def __init__(self, real_conn):
            self.real_conn = real_conn
            self.call_count = 0

        def execute(self, sql, params=()):
            if "UPDATE api_configurations SET priority = ?" in sql:
                self.call_count += 1
                if self.call_count > 1:
                    raise RuntimeError("Simulated Database Disk Failure during reorder")
            return self.real_conn.execute(sql, params)

        def commit(self):
            self.real_conn.commit()

        def rollback(self):
            self.real_conn.rollback()

        def close(self):
            self.real_conn.close()

    from contextlib import contextmanager
    @contextmanager
    def failing_get_conn():
        with original_get_conn() as real:
            yield FailingConnection(real)

    db.get_connection = failing_get_conn

    with pytest.raises(RuntimeError, match="Simulated Database Disk Failure"):
        db.change_priority(id2, 1)

    # Restore connection and verify rollback
    db.get_connection = original_get_conn
    cfgs = db.get_all_configs()
    assert cfgs[0]["id"] == id1 and cfgs[0]["priority"] == 1
    assert cfgs[1]["id"] == id2 and cfgs[1]["priority"] == 2


# ── 13. Handling concurrent priority changes ────────────────────────────────

def test_13_handling_concurrent_priority_changes(temp_db):
    db, crypto, _ = temp_db
    ids = [
        db.insert_config("md5decrypt", f"API {i}", f"https://api{i}.org/", crypto.encrypt(f"k{i}"), priority=i)
        for i in range(1, 5)
    ]

    errors = []

    def worker_a():
        try:
            for _ in range(5):
                db.change_priority(ids[3], 1)
        except Exception as e:
            errors.append(e)

    def worker_b():
        try:
            for _ in range(5):
                db.change_priority(ids[0], 4)
        except Exception as e:
            errors.append(e)

    t1 = threading.Thread(target=worker_a)
    t2 = threading.Thread(target=worker_b)
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    # Final DB state must be consecutive 1..N and unique
    cfgs = db.get_all_configs()
    priorities = [c["priority"] for c in cfgs]
    assert priorities == [1, 2, 3, 4]
    assert len(set(priorities)) == 4


# ── 14. Assigning the correct priority to a newly added API ──────────────────

def test_14_assign_correct_priority_new_api(temp_db):
    db, crypto, _ = temp_db
    id1 = db.insert_config("md5decrypt", "P1", "https://1.org/", crypto.encrypt("k1"), priority=1)
    id2 = db.insert_config("md5decrypt", "P2", "https://2.org/", crypto.encrypt("k2"), priority=2)
    id3 = db.insert_config("md5decrypt", "P3", "https://3.org/", crypto.encrypt("k3"), priority=3)

    # Reorder
    db.change_priority(id3, 1)

    # Add a new API with no priority specified -> must receive 4
    id4 = db.insert_config("md5decrypt", "P4", "https://4.org/", crypto.encrypt("k4"))
    cfg4 = db.get_config_by_id(id4)
    assert cfg4["priority"] == 4

    # Add a new API with priority 1 specified -> must become priority 1 and shift others to 2..5
    id5 = db.insert_config("md5decrypt", "P5", "https://5.org/", crypto.encrypt("k5"), priority=1)
    cfg5 = db.get_config_by_id(id5)
    assert cfg5["priority"] == 1

    all_cfgs = db.get_all_configs()
    assert [c["priority"] for c in all_cfgs] == [1, 2, 3, 4, 5]


# ── 15. Normalizing priorities after manual deletion ─────────────────────────

def test_15_normalize_priorities_after_manual_deletion(temp_db):
    db, crypto, _ = temp_db
    id1 = db.insert_config("md5decrypt", "P1", "https://1.org/", crypto.encrypt("k1"), priority=1)
    id2 = db.insert_config("md5decrypt", "P2", "https://2.org/", crypto.encrypt("k2"), priority=2)
    id3 = db.insert_config("md5decrypt", "P3", "https://3.org/", crypto.encrypt("k3"), priority=3)

    # Delete middle API
    deleted = db.delete_config(id2)
    assert deleted is True

    remaining = db.get_all_configs()
    assert len(remaining) == 2
    assert [c["id"] for c in remaining] == [id1, id3]
    assert [c["priority"] for c in remaining] == [1, 2]


# ── 16. Preserving API credentials and ownership ─────────────────────────────

def test_16_preserve_credentials_and_ownership(temp_db):
    db, crypto, _ = temp_db
    user_id = db.create_user("sub_owner", "pwd_hash", role="subadmin")
    secret_key = "super_confidential_api_token_xyz"
    cfg_id = db.insert_config(
        provider_name="md5decrypt",
        display_name="Secure Provider",
        endpoint="https://secure.endpoint.io/",
        encrypted_credential=crypto.encrypt(secret_key),
        priority=2,
        notes="Secret provider notes",
        owner_id=user_id,
    )
    # Add dummy neighbors
    db.insert_config("md5decrypt", "P1", "https://1.org/", crypto.encrypt("k1"), priority=1)
    db.insert_config("md5decrypt", "P3", "https://3.org/", crypto.encrypt("k3"), priority=3)

    # Reorder
    db.change_priority(cfg_id, 1)

    reordered = db.get_config_by_id(cfg_id)
    assert reordered["priority"] == 1
    assert reordered["owner_id"] == user_id
    assert reordered["endpoint"] == "https://secure.endpoint.io/"
    assert reordered["notes"] == "Secret provider notes"
    assert crypto.decrypt(reordered["encrypted_credential"]) == secret_key


# ── 17. Preserving cyclic rotation and failover after reordering ─────────────

def test_17_preserve_cyclic_rotation_and_failover_after_reorder(temp_db):
    db, crypto, _ = temp_db
    id1 = db.insert_config("md5decrypt", "A", "https://a.org/", crypto.encrypt("k1"), priority=1)
    id2 = db.insert_config("md5decrypt", "B", "https://b.org/", crypto.encrypt("k2"), priority=2)
    id3 = db.insert_config("md5decrypt", "C", "https://c.org/", crypto.encrypt("k3"), priority=3)

    coord = ApiFailoverCoordinator(db=db, crypto=crypto)

    with patch("services.failover.get_provider_adapter") as mock_getter:
        mock_adapter = MagicMock()
        mock_adapter.lookup.return_value = ProviderLookupResult(
            success=True, status="match_found", found=True, plaintext="hit", duration=0.01
        )
        mock_getter.return_value = mock_adapter

        # Request 1 uses Provider A (Priority 1)
        res1 = coord.execute_lookup("h1", "md5")
        assert res1["provider_id"] == id1

        # Now reorder: move C to priority 1. New sequence: C (P1), A (P2), B (P3)
        db.change_priority(id3, 1)

        # Next cyclic request should advance from last used (A) to the next in sequence: B (P3)
        res2 = coord.execute_lookup("h2", "md5")
        assert res2["provider_id"] == id2

        # Next request cycles to C (P1)
        res3 = coord.execute_lookup("h3", "md5")
        assert res3["provider_id"] == id3


# ── 18. Enforcing administrator and sub-admin permissions ────────────────────

def test_18_enforce_admin_and_subadmin_permissions():
    from datetime import datetime, timezone
    from app import app, db, crypto
    app.config["TESTING"] = True

    # Ensure main admin user exists
    db.seed_main_admin_if_empty("inexpert_trifler", "om sai 0987654321")
    main_admin = db.get_user_by_username("inexpert_trifler")
    assert main_admin is not None
    main_admin_id = main_admin["id"]

    ts = int(datetime.now(timezone.utc).timestamp() * 1000)
    sub1_uname = f"sub1_perm_{ts}"
    sub2_uname = f"sub2_perm_{ts}"
    sub1_id = db.create_user(sub1_uname, "hash1", role="subadmin")
    sub2_id = db.create_user(sub2_uname, "hash2", role="subadmin")

    # Subadmin 1 creates an API
    c1 = db.insert_config("md5decrypt", "Sub1 API", "https://s1.org/", crypto.encrypt("k1"), priority=1, owner_id=sub1_id)
    # Subadmin 2 creates an API
    c2 = db.insert_config("md5decrypt", "Sub2 API", "https://s2.org/", crypto.encrypt("k2"), priority=2, owner_id=sub2_id)

    with app.test_client() as c:
        # 1. Subadmin 1 logs in
        with c.session_transaction() as sess:
            sess["admin_authenticated"] = True
            sess["user_id"] = sub1_id
            sess["username"] = sub1_uname
            sess["role"] = "subadmin"
            sess["csrf_token"] = "valid_csrf_token_123"

        # Subadmin 1 changes their own API priority -> Success
        res = c.post(
            f"/admin/api/configs/{c1}/priority",
            data=json.dumps({"priority": 2, "csrf_token": "valid_csrf_token_123"}),
            content_type="application/json",
            headers={"X-CSRF-Token": "valid_csrf_token_123"},
        )
        assert res.status_code == 200
        assert res.get_json()["success"] is True

        # Subadmin 1 attempts to change Subadmin 2's API priority -> 403 Forbidden
        res_forbidden = c.post(
            f"/admin/api/configs/{c2}/priority",
            data=json.dumps({"priority": 1, "csrf_token": "valid_csrf_token_123"}),
            content_type="application/json",
            headers={"X-CSRF-Token": "valid_csrf_token_123"},
        )
        assert res_forbidden.status_code == 403
        assert "Access denied" in res_forbidden.get_json()["error"]

        # 2. Main Admin logs in
        with c.session_transaction() as sess:
            sess["admin_authenticated"] = True
            sess["user_id"] = main_admin_id
            sess["username"] = "inexpert_trifler"
            sess["role"] = "main_admin"
            sess["csrf_token"] = "valid_csrf_token_123"

        # Main Admin can reorder any API
        res_admin = c.post(
            f"/admin/api/configs/{c2}/priority",
            data=json.dumps({"priority": 1, "csrf_token": "valid_csrf_token_123"}),
            content_type="application/json",
            headers={"X-CSRF-Token": "valid_csrf_token_123"},
        )
        assert res_admin.status_code == 200
        assert res_admin.get_json()["success"] is True
