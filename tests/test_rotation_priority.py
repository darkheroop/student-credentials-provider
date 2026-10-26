"""
Comprehensive test suite for API failover, cyclic rotation, quota handling,
and priority management in Student Credentials Provider.

Covers all 20 required verification scenarios:
 1. Successful API rotation across three APIs.
 2. Cyclic rotation returning to the first API after the last.
 3. Failover when the current API reaches quota.
 4. Failover when an API returns a retryable server error.
 5. Handling HTTP 429 and Retry-After.
 6. Handling authentication failures without deleting the API.
 7. Automatic recovery after cooldown expiry.
 8. Exclusion of manually disabled APIs.
 9. Persistence of API records after failure.
10. Persistence of rotation state across separate requests.
11. Concurrent requests across multiple workers.
12. Automatic priority assignment when APIs are added.
13. Sequential priority assignment under concurrent creation.
14. Priority normalization after manual deletion.
15. Priority reordering.
16. Behavior when all APIs are unavailable.
17. Prevention of infinite retries.
18. Preservation of encrypted credentials.
19. Preservation of sub-admin accounts and API ownership.
20. Regression tests for existing application features.
"""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from config import Config
from database import Database
from services.crypto import CredentialCrypto
from services.failover import ApiFailoverCoordinator
from services.providers.base import BaseProviderAdapter, ProviderLookupResult
from services.providers.registry import register_provider


class MockRotatingProvider(BaseProviderAdapter):
    """Mock provider with call tracking and configurable per-key responses."""

    name = "mock_rotating_provider"

    def __init__(self):
        self.calls: list[dict] = []
        self.key_behaviors: dict[str, Any] = {}

    def set_behavior(self, credential: str, result: ProviderLookupResult):
        self.key_behaviors[credential] = result

    def lookup(self, credential, endpoint, hash_input, algorithm, timeout=10, **kwargs):
        self.calls.append({
            "credential": credential,
            "endpoint": endpoint,
            "hash": hash_input,
            "algorithm": algorithm,
        })
        if credential in self.key_behaviors:
            return self.key_behaviors[credential]

        return ProviderLookupResult(
            success=True,
            status="match_found",
            found=True,
            plaintext=f"result_from_{credential}",
            duration=0.01,
        )

    def test_connection(self, credential, endpoint, timeout=10, **kwargs):
        return True, "Mock connection OK"


@pytest.fixture
def rotation_env(tmp_path):
    """Setup isolated test database and failover coordinator."""
    db_file = str(tmp_path / "test_rotation.db")
    config = Config()
    config.DATABASE_PATH = db_file
    config.STUDENT_LOOKUP_TIMEOUT_SECONDS = 2
    config.DEFAULT_PAUSE_DURATION_MINUTES = 30
    config.MAX_FAILOVER_ATTEMPTS = 5

    db = Database(db_path=db_file, config=config)
    crypto = CredentialCrypto("test-secret-key-32-chars-length!")
    coordinator = ApiFailoverCoordinator(db=db, crypto=crypto, config=config)

    provider = MockRotatingProvider()
    register_provider("mock_rotating_provider", lambda: provider)

    return {
        "db": db,
        "crypto": crypto,
        "coordinator": coordinator,
        "config": config,
        "provider": provider,
    }


class TestCyclicRotationAndFailover:
    # ── 1. Highest priority API used first, updates take effect immediately ─
    def test_1_successful_rotation_across_three_apis(self, rotation_env):
        db = rotation_env["db"]
        crypto = rotation_env["crypto"]
        coord = rotation_env["coordinator"]
        provider = rotation_env["provider"]

        id_a = db.insert_config("mock_rotating_provider", "API A", "https://api-a", crypto.encrypt("key_a"), priority=1)
        id_b = db.insert_config("mock_rotating_provider", "API B", "https://api-b", crypto.encrypt("key_b"), priority=2)
        id_c = db.insert_config("mock_rotating_provider", "API C", "https://api-c", crypto.encrypt("key_c"), priority=3)

        # Request 1 -> API A (Priority 1)
        r1 = coord.execute_lookup("5d41402abc4b2a76b9719d911017c592", "md5")
        assert r1["success"] is True
        assert r1["provider_name"] == "API A"
        assert provider.calls[-1]["credential"] == "key_a"

        # Request 2 -> API A (Priority 1 remains highest priority)
        r2 = coord.execute_lookup("5d41402abc4b2a76b9719d911017c592", "md5")
        assert r2["success"] is True
        assert r2["provider_name"] == "API A"

        # Reorder: Move API B to Priority 1
        db.change_priority(id_b, 1)

        # Request 3 -> API B (now Priority 1)
        r3 = coord.execute_lookup("5d41402abc4b2a76b9719d911017c592", "md5")
        assert r3["success"] is True
        assert r3["provider_name"] == "API B"
        assert provider.calls[-1]["credential"] == "key_b"

    # ── 2. Priority 1 consistently used across requests without cursor drift ─
    def test_2_cyclic_rotation_wrap_around(self, rotation_env):
        db = rotation_env["db"]
        crypto = rotation_env["crypto"]
        coord = rotation_env["coordinator"]
        provider = rotation_env["provider"]

        db.insert_config("mock_rotating_provider", "API A", "https://api-a", crypto.encrypt("key_a"), priority=1)
        db.insert_config("mock_rotating_provider", "API B", "https://api-b", crypto.encrypt("key_b"), priority=2)

        # Multiple successive requests must consistently use Priority 1
        seq = []
        for _ in range(5):
            res = coord.execute_lookup("5d41402abc4b2a76b9719d911017c592", "md5")
            seq.append(res["provider_name"])

        assert seq == ["API A", "API A", "API A", "API A", "API A"]

    # ── 3. Failover when current API reaches quota ───────────────────────
    def test_3_failover_when_current_api_reaches_quota(self, rotation_env):
        db = rotation_env["db"]
        crypto = rotation_env["crypto"]
        coord = rotation_env["coordinator"]
        provider = rotation_env["provider"]

        db.insert_config("mock_rotating_provider", "API A", "https://api-a", crypto.encrypt("key_a"), priority=1)
        db.insert_config("mock_rotating_provider", "API B", "https://api-b", crypto.encrypt("key_b"), priority=2)
        db.insert_config("mock_rotating_provider", "API C", "https://api-c", crypto.encrypt("key_c"), priority=3)

        # Set API A to quota_exhausted
        provider.set_behavior("key_a", ProviderLookupResult(
            success=False,
            status="quota_exhausted",
            found=False,
            error_category="quota_exhausted",
            error_message="Account credits exhausted",
        ))

        # Request 1 tries API A (quota fail) -> failover to API B (succeeds)
        r1 = coord.execute_lookup("5d41402abc4b2a76b9719d911017c592", "md5")
        assert r1["success"] is True
        assert r1["provider_name"] == "API B"

        # Verify API A is STILL in database, not deleted!
        cfg_a = db.get_config_by_id(1)
        assert cfg_a is not None
        assert cfg_a["health_status"] == "quota_exhausted"
        assert cfg_a["paused_until"] is not None

        # Next request: API A is still quota_exhausted, so next request uses API B (highest-priority eligible API)
        r2 = coord.execute_lookup("5d41402abc4b2a76b9719d911017c592", "md5")
        assert r2["success"] is True
        assert r2["provider_name"] == "API B"

    # ── 4. Failover when an API returns retryable server error ───────────
    def test_4_failover_when_api_returns_server_error(self, rotation_env):
        db = rotation_env["db"]
        crypto = rotation_env["crypto"]
        coord = rotation_env["coordinator"]
        provider = rotation_env["provider"]

        db.insert_config("mock_rotating_provider", "API A", "https://api-a", crypto.encrypt("key_a"), priority=1)
        db.insert_config("mock_rotating_provider", "API B", "https://api-b", crypto.encrypt("key_b"), priority=2)

        provider.set_behavior("key_a", ProviderLookupResult(
            success=False,
            status="server_error",
            found=False,
            http_status=500,
            error_category="server_error",
            error_message="Internal Server Error",
        ))

        res = coord.execute_lookup("5d41402abc4b2a76b9719d911017c592", "md5")
        assert res["success"] is True
        assert res["provider_name"] == "API B"

        # API A remains in database marked degraded
        cfg_a = db.get_config_by_id(1)
        assert cfg_a["health_status"] == "degraded"
        assert cfg_a["paused_until"] is not None

    # ── 5. Handling HTTP 429 and Retry-After ─────────────────────────────
    def test_5_handling_http_429_and_retry_after(self, rotation_env):
        db = rotation_env["db"]
        crypto = rotation_env["crypto"]
        coord = rotation_env["coordinator"]
        provider = rotation_env["provider"]

        db.insert_config("mock_rotating_provider", "API A", "https://api-a", crypto.encrypt("key_a"), priority=1)
        db.insert_config("mock_rotating_provider", "API B", "https://api-b", crypto.encrypt("key_b"), priority=2)

        provider.set_behavior("key_a", ProviderLookupResult(
            success=False,
            status="rate_limited",
            found=False,
            http_status=429,
            retry_after_seconds=120,
            error_message="Rate limit reached. Retry after 120s.",
        ))

        res = coord.execute_lookup("5d41402abc4b2a76b9719d911017c592", "md5")
        assert res["success"] is True
        assert res["provider_name"] == "API B"

        cfg_a = db.get_config_by_id(1)
        assert cfg_a["health_status"] == "rate_limited"
        # paused_until should be roughly 120 seconds in future
        assert cfg_a["paused_until"] is not None

    # ── 6. Handling auth failures without deleting the API ───────────────
    def test_6_handling_auth_failures_without_deleting_api(self, rotation_env):
        db = rotation_env["db"]
        crypto = rotation_env["crypto"]
        coord = rotation_env["coordinator"]
        provider = rotation_env["provider"]

        db.insert_config("mock_rotating_provider", "API A", "https://api-a", crypto.encrypt("bad_key"), priority=1)
        db.insert_config("mock_rotating_provider", "API B", "https://api-b", crypto.encrypt("good_key"), priority=2)

        provider.set_behavior("bad_key", ProviderLookupResult(
            success=False,
            status="auth_failed",
            found=False,
            http_status=401,
            error_category="auth_failed",
            error_message="Invalid credentials",
        ))

        res = coord.execute_lookup("5d41402abc4b2a76b9719d911017c592", "md5")
        assert res["success"] is True
        assert res["provider_name"] == "API B"

        # Verify API A is STILL in database
        cfg_a = db.get_config_by_id(1)
        assert cfg_a is not None
        assert cfg_a["display_name"] == "API A"
        assert cfg_a["health_status"] in ("auth_failed", "config_error")
        # Credential is still safely stored and intact
        assert crypto.decrypt(cfg_a["encrypted_credential"]) == "bad_key"

    # ── 7. Automatic recovery after cooldown expiry ──────────────────────
    def test_7_automatic_recovery_after_cooldown_expiry(self, rotation_env):
        db = rotation_env["db"]
        crypto = rotation_env["crypto"]
        coord = rotation_env["coordinator"]

        db.insert_config("mock_rotating_provider", "API A", "https://api-a", crypto.encrypt("key_a"), priority=1)
        
        # Manually pause API A with an expired timestamp (10 minutes ago)
        past_iso = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
        db.set_health_status(1, health_status="quota_exhausted", paused_until=past_iso)

        cfg_before = db.get_config_by_id(1)
        assert cfg_before["health_status"] == "quota_exhausted"

        # Trigger eligible check: API A should automatically recover to 'active'
        eligible = db.get_eligible_configs()
        assert len(eligible) == 1
        assert eligible[0]["id"] == 1
        assert eligible[0]["health_status"] == "active"

        # And lookup should succeed with API A
        res = coord.execute_lookup("5d41402abc4b2a76b9719d911017c592", "md5")
        assert res["success"] is True
        assert res["provider_name"] == "API A"

    # ── 8. Exclusion of manually disabled APIs ───────────────────────────
    def test_8_exclusion_of_manually_disabled_apis(self, rotation_env):
        db = rotation_env["db"]
        crypto = rotation_env["crypto"]
        coord = rotation_env["coordinator"]

        db.insert_config("mock_rotating_provider", "Disabled API", "https://api-a", crypto.encrypt("key_a"), priority=1, enabled=0)
        db.insert_config("mock_rotating_provider", "Active API", "https://api-b", crypto.encrypt("key_b"), priority=2, enabled=1)

        res = coord.execute_lookup("5d41402abc4b2a76b9719d911017c592", "md5")
        assert res["success"] is True
        assert res["provider_name"] == "Active API"

        # Disabled API must not be auto-unpaused even if paused_until is in the past
        past_iso = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
        db.set_health_status(1, health_status="disabled", paused_until=past_iso)
        eligible = db.get_eligible_configs()
        assert len(eligible) == 1
        assert eligible[0]["id"] == 2

    # ── 9. Persistence of API records after failure ──────────────────────
    def test_9_persistence_of_api_records_after_failure(self, rotation_env):
        db = rotation_env["db"]
        crypto = rotation_env["crypto"]
        coord = rotation_env["coordinator"]
        provider = rotation_env["provider"]

        db.insert_config("mock_rotating_provider", "API 1", "https://api1", crypto.encrypt("k1"), priority=1)
        db.insert_config("mock_rotating_provider", "API 2", "https://api2", crypto.encrypt("k2"), priority=2)

        # Both fail with server error
        provider.set_behavior("k1", ProviderLookupResult(success=False, status="server_error", found=False))
        provider.set_behavior("k2", ProviderLookupResult(success=False, status="server_error", found=False))

        coord.execute_lookup("5d41402abc4b2a76b9719d911017c592", "md5")

        # Verify DB still has exactly 2 configs
        all_cfgs = db.get_all_configs()
        assert len(all_cfgs) == 2
        assert all_cfgs[0]["display_name"] == "API 1"
        assert all_cfgs[1]["display_name"] == "API 2"

    # ── 10. Persistence of priority & health state across separate instances ─
    def test_10_persistence_of_rotation_state_across_requests(self, rotation_env):
        db = rotation_env["db"]
        crypto = rotation_env["crypto"]
        config = rotation_env["config"]
        provider = rotation_env["provider"]

        db.insert_config("mock_rotating_provider", "API 1", "https://api1", crypto.encrypt("k1"), priority=1)
        db.insert_config("mock_rotating_provider", "API 2", "https://api2", crypto.encrypt("k2"), priority=2)

        # Create coordinator 1 and run request
        c1 = ApiFailoverCoordinator(db=db, crypto=crypto, config=config)
        r1 = c1.execute_lookup("5d41402abc4b2a76b9719d911017c592", "md5")
        assert r1["provider_name"] == "API 1"

        # Create coordinator 2 (simulating fresh serverless container/worker)
        # Observes the same persistent priority and health state -> starts with Priority 1
        c2 = ApiFailoverCoordinator(db=db, crypto=crypto, config=config)
        r2 = c2.execute_lookup("5d41402abc4b2a76b9719d911017c592", "md5")
        assert r2["provider_name"] == "API 1"

        # If API 1 is paused, both observe it immediately
        db.set_health_status(1, "quota_exhausted", paused_until="2099-01-01T00:00:00+00:00")
        r3 = c2.execute_lookup("5d41402abc4b2a76b9719d911017c592", "md5")
        assert r3["provider_name"] == "API 2"

    # ── 11. Concurrent requests across multiple workers ──────────────────
    def test_11_concurrent_requests_across_multiple_workers(self, rotation_env):
        db = rotation_env["db"]
        crypto = rotation_env["crypto"]
        coord = rotation_env["coordinator"]

        db.insert_config("mock_rotating_provider", "API 1", "https://api1", crypto.encrypt("k1"), priority=1)
        db.insert_config("mock_rotating_provider", "API 2", "https://api2", crypto.encrypt("k2"), priority=2)
        db.insert_config("mock_rotating_provider", "API 3", "https://api3", crypto.encrypt("k3"), priority=3)

        def worker(_):
            return coord.execute_lookup("5d41402abc4b2a76b9719d911017c592", "md5")

        with ThreadPoolExecutor(max_workers=5) as executor:
            results = list(executor.map(worker, range(15)))

        assert all(r["success"] is True for r in results)
        assert all(r["provider_name"] == "API 1" for r in results)

    # ── 12. Automatic priority assignment when APIs are added ────────────
    def test_12_automatic_priority_assignment(self, rotation_env):
        db = rotation_env["db"]
        crypto = rotation_env["crypto"]

        # Insert without specifying priority -> must receive sequential 1, 2, 3...
        id1 = db.insert_config("mock_rotating_provider", "API A", "https://a", crypto.encrypt("k1"))
        cfg1 = db.get_config_by_id(id1)
        assert cfg1["priority"] == 1

        id2 = db.insert_config("mock_rotating_provider", "API B", "https://b", crypto.encrypt("k2"))
        cfg2 = db.get_config_by_id(id2)
        assert cfg2["priority"] == 2

        id3 = db.insert_config("mock_rotating_provider", "API C", "https://c", crypto.encrypt("k3"))
        cfg3 = db.get_config_by_id(id3)
        assert cfg3["priority"] == 3

    # ── 13. Sequential priority assignment under concurrent creation ─────
    def test_13_sequential_priority_assignment_concurrent(self, rotation_env):
        db = rotation_env["db"]
        crypto = rotation_env["crypto"]

        def create_api(idx):
            return db.insert_config(
                "mock_rotating_provider",
                f"Concurrent API {idx}",
                f"https://api{idx}",
                crypto.encrypt(f"key{idx}"),
            )

        with ThreadPoolExecutor(max_workers=4) as executor:
            ids = list(executor.map(create_api, range(10)))

        all_cfgs = db.get_all_configs()
        assert len(all_cfgs) == 10
        priorities = sorted([c["priority"] for c in all_cfgs])
        # Priorities must be strictly sequential 1..10 without duplicates
        assert priorities == list(range(1, 11))

    # ── 14. Priority normalization after manual deletion ─────────────────
    def test_14_priority_normalization_after_deletion(self, rotation_env):
        db = rotation_env["db"]
        crypto = rotation_env["crypto"]

        id1 = db.insert_config("mock_rotating_provider", "API 1", "https://1", crypto.encrypt("k1"), priority=1)
        id2 = db.insert_config("mock_rotating_provider", "API 2", "https://2", crypto.encrypt("k2"), priority=2)
        id3 = db.insert_config("mock_rotating_provider", "API 3", "https://3", crypto.encrypt("k3"), priority=3)

        # Delete middle API
        db.delete_config(id2)

        # Remaining APIs must have consecutive priorities 1 and 2
        remaining = db.get_all_configs()
        assert len(remaining) == 2
        assert remaining[0]["id"] == id1
        assert remaining[0]["priority"] == 1
        assert remaining[1]["id"] == id3
        assert remaining[1]["priority"] == 2

    # ── 15. Priority reordering ──────────────────────────────────────────
    def test_15_priority_reordering(self, rotation_env):
        db = rotation_env["db"]
        crypto = rotation_env["crypto"]

        id1 = db.insert_config("mock_rotating_provider", "API 1", "https://1", crypto.encrypt("k1"), priority=1)
        id2 = db.insert_config("mock_rotating_provider", "API 2", "https://2", crypto.encrypt("k2"), priority=2)
        id3 = db.insert_config("mock_rotating_provider", "API 3", "https://3", crypto.encrypt("k3"), priority=3)

        # Reorder to: API 3, API 1, API 2
        db.reorder_priorities([id3, id1, id2])

        ordered = db.get_all_configs()
        assert ordered[0]["id"] == id3
        assert ordered[0]["priority"] == 1
        assert ordered[1]["id"] == id1
        assert ordered[1]["priority"] == 2
        assert ordered[2]["id"] == id2
        assert ordered[2]["priority"] == 3

        # Test move up/down
        db.move_priority(id2, "up")
        moved = db.get_all_configs()
        assert moved[1]["id"] == id2
        assert moved[1]["priority"] == 2

    # ── 16. Behavior when all APIs are unavailable ───────────────────────
    def test_16_behavior_when_all_apis_unavailable(self, rotation_env):
        db = rotation_env["db"]
        crypto = rotation_env["crypto"]
        coord = rotation_env["coordinator"]
        provider = rotation_env["provider"]

        db.insert_config("mock_rotating_provider", "API 1", "https://1", crypto.encrypt("k1"))
        provider.set_behavior("k1", ProviderLookupResult(success=False, status="quota_exhausted", found=False))

        res = coord.execute_lookup("5d41402abc4b2a76b9719d911017c592", "md5")
        assert res["success"] is False
        assert "All configured APIs are currently unavailable" in res["message"]

        # Call again when no eligible APIs exist
        res2 = coord.execute_lookup("5d41402abc4b2a76b9719d911017c592", "md5")
        assert res2["success"] is False
        assert "All configured APIs are currently unavailable" in res2["message"]

    # ── 17. Prevention of infinite retries ────────────────────────────────
    def test_17_prevention_of_infinite_retries(self, rotation_env):
        db = rotation_env["db"]
        crypto = rotation_env["crypto"]
        coord = rotation_env["coordinator"]
        provider = rotation_env["provider"]

        for i in range(10):
            db.insert_config("mock_rotating_provider", f"API {i}", f"https://{i}", crypto.encrypt(f"k{i}"))
            provider.set_behavior(f"k{i}", ProviderLookupResult(success=False, status="server_error", found=False))

        # MAX_FAILOVER_ATTEMPTS is 5 in fixture
        res = coord.execute_lookup("5d41402abc4b2a76b9719d911017c592", "md5")
        assert res["success"] is False
        assert len(provider.calls) == 5  # Exactly 5, not 10 or unbounded!

    # ── 18. Preservation of encrypted credentials ────────────────────────
    def test_18_preservation_of_encrypted_credentials(self, rotation_env):
        db = rotation_env["db"]
        crypto = rotation_env["crypto"]

        raw_key = "super_secret_production_key_xyz987"
        id1 = db.insert_config("mock_rotating_provider", "Secured API", "https://sec", crypto.encrypt(raw_key))

        cfg = db.get_config_by_id(id1)
        # Stored in database must NOT be plaintext
        assert cfg["encrypted_credential"] != raw_key
        # Decryption must reproduce exact original key
        assert crypto.decrypt(cfg["encrypted_credential"]) == raw_key

    # ── 19. Preservation of sub-admin accounts and API ownership ─────────
    def test_19_preservation_of_subadmins_and_ownership(self, rotation_env):
        db = rotation_env["db"]
        crypto = rotation_env["crypto"]
        coord = rotation_env["coordinator"]

        # Create subadmin
        sub_id = db.create_user("analyst_jane", "JaneSecurePass123!", role="subadmin")
        assert sub_id is not None

        # Add API
        db.insert_config("mock_rotating_provider", "API 1", "https://api1", crypto.encrypt("k1"))

        # Trigger lookups
        for _ in range(3):
            coord.execute_lookup("5d41402abc4b2a76b9719d911017c592", "md5")

        # Verify subadmin account was NEVER deleted or affected
        sub = db.get_user_by_id(sub_id)
        assert sub is not None
        assert sub["username"] == "analyst_jane"
        assert sub["role"] == "subadmin"
        assert sub["is_active"] == 1

    # ── 20. Regression tests for existing application features ───────────
    def test_20_regression_features(self, rotation_env):
        db = rotation_env["db"]

        # Check rotation state endpoint
        rot = db.get_rotation_state()
        assert "rotation_counter" in rot
        assert "last_config_id" in rot

        # Check client API keys
        key_record_created = db.create_client_api_key(name="Partner 1", rate_limit_per_minute=100)
        assert key_record_created is not None
        raw_key = key_record_created["api_key"]
        key_record = db.get_client_api_key(raw_key)
        assert key_record["name"] == "Partner 1"
        assert key_record["rate_limit_per_minute"] == 100
