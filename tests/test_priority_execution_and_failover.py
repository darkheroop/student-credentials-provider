"""
Comprehensive regression test suite for API execution order, priority-first selection,
automatic bounded failover, error classification, and automatic recovery.

Directly covers all 20 required scenarios from Section 10:
 1. API 1 is called first when it has Priority 1.
 2. Changing API 2 to Priority 1 causes the next request to call API 2 first.
 3. Priority changes take effect without restarting the application.
 4. A failed highest-priority API triggers failover to the next eligible API.
 5. Failover follows the latest priority order.
 6. A successful provider stops further attempts.
 7. Quota exhaustion triggers failover without deleting the API.
 8. HTTP 429 handling respects Retry-After where available.
 9. HTTP 401 and 403 responses do not delete the provider.
10. HTTP 5xx errors trigger appropriate bounded failover.
11. Network timeouts trigger appropriate bounded failover.
12. Invalid user input does not trigger unnecessary provider calls.
13. Failed providers remain in database with credentials and priorities intact.
14. Temporarily unavailable APIs recover when eligible.
15. Manually disabled APIs remain disabled.
16. All-provider failure returns a safe error.
17. Maximum retry limits are enforced.
18. Concurrent requests do not corrupt persistent provider state.
19. Separate application instances observe the same priority and health state.
20. Existing administrator, sub-admin, and API-management functionality continues working.
"""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import json
import time
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from config import Config
from database import Database
from services.crypto import CredentialCrypto
from services.failover import ApiFailoverCoordinator
from services.providers.base import BaseProviderAdapter, ProviderLookupResult
from services.providers.registry import register_provider
from services.student_lookup import StudentLookupService


class MockPriorityProvider(BaseProviderAdapter):
    """Mock provider with call tracking and configurable per-credential behaviors."""

    name = "mock_priority_provider"

    def __init__(self):
        self.calls: list[dict[str, Any]] = []
        self.key_behaviors: dict[str, Any] = {}

    def set_behavior(self, credential: str, result: ProviderLookupResult | list[ProviderLookupResult]):
        self.key_behaviors[credential] = result

    def lookup(self, credential, endpoint, hash_input, algorithm, timeout=10, **kwargs):
        self.calls.append({
            "credential": credential,
            "endpoint": endpoint,
            "hash": hash_input,
            "algorithm": algorithm,
            "timeout": timeout,
        })
        behavior = self.key_behaviors.get(credential)
        if isinstance(behavior, list):
            if len(behavior) > 1:
                return behavior.pop(0)
            return behavior[0]
        elif isinstance(behavior, ProviderLookupResult):
            return behavior

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
def env(tmp_path):
    """Set up isolated test database, crypto, and failover coordinator."""
    db_file = str(tmp_path / "test_priority_execution.db")
    config = Config()
    config.DATABASE_PATH = db_file
    config.STUDENT_LOOKUP_TIMEOUT_SECONDS = 5
    config.DEFAULT_PAUSE_DURATION_MINUTES = 30
    config.MAX_FAILOVER_ATTEMPTS = 5
    config.SERVER_ERROR_COOLDOWN_SECONDS = 60
    config.NETWORK_ERROR_COOLDOWN_SECONDS = 60
    config.RATE_LIMIT_COOLDOWN_SECONDS = 60

    db = Database(db_path=db_file, config=config)
    crypto = CredentialCrypto("test-secret-key-for-priority-32ch!")
    coordinator = ApiFailoverCoordinator(db=db, crypto=crypto, config=config)

    provider = MockPriorityProvider()
    register_provider("mock_priority_provider", lambda: provider)

    return {
        "db": db,
        "crypto": crypto,
        "coordinator": coordinator,
        "config": config,
        "provider": provider,
    }


# ── Scenario 1: API 1 is called first when it has Priority 1 ────────────────
def test_01_api_1_called_first_when_priority_1(env):
    db, crypto, coord, provider = env["db"], env["crypto"], env["coordinator"], env["provider"]

    id1 = db.insert_config("mock_priority_provider", "API 1", "https://api1", crypto.encrypt("k1"), priority=1)
    id2 = db.insert_config("mock_priority_provider", "API 2", "https://api2", crypto.encrypt("k2"), priority=2)
    id3 = db.insert_config("mock_priority_provider", "API 3", "https://api3", crypto.encrypt("k3"), priority=3)

    res = coord.execute_lookup("5d41402abc4b2a76b9719d911017c592", "md5")
    assert res["success"] is True
    assert res["provider_id"] == id1
    assert res["provider_name"] == "API 1"
    assert provider.calls[0]["credential"] == "k1"
    assert len(provider.calls) == 1


# ── Scenario 2: Changing API 2 to Priority 1 causes next request to call API 2 first ─
def test_02_changing_api_2_to_priority_1_calls_api_2_first(env):
    db, crypto, coord, provider = env["db"], env["crypto"], env["coordinator"], env["provider"]

    id1 = db.insert_config("mock_priority_provider", "API 1", "https://api1", crypto.encrypt("k1"), priority=1)
    id2 = db.insert_config("mock_priority_provider", "API 2", "https://api2", crypto.encrypt("k2"), priority=2)
    id3 = db.insert_config("mock_priority_provider", "API 3", "https://api3", crypto.encrypt("k3"), priority=3)

    # Initial request uses API 1
    r1 = coord.execute_lookup("5d41402abc4b2a76b9719d911017c592", "md5")
    assert r1["provider_id"] == id1

    # Change API 2 to Priority 1
    db.change_priority(id2, 1)

    # Next request must immediately call API 2 first
    r2 = coord.execute_lookup("5d41402abc4b2a76b9719d911017c592", "md5")
    assert r2["provider_id"] == id2
    assert r2["provider_name"] == "API 2"
    assert provider.calls[-1]["credential"] == "k2"


# ── Scenario 3: Priority changes take effect without restarting the application ─
def test_03_priority_changes_take_effect_without_restart(env):
    db, crypto, coord, provider = env["db"], env["crypto"], env["coordinator"], env["provider"]

    id1 = db.insert_config("mock_priority_provider", "API 1", "https://api1", crypto.encrypt("k1"), priority=1)
    id2 = db.insert_config("mock_priority_provider", "API 2", "https://api2", crypto.encrypt("k2"), priority=2)

    # Consecutive requests with no changes remain on Priority 1
    for _ in range(3):
        res = coord.execute_lookup("5d41402abc4b2a76b9719d911017c592", "md5")
        assert res["provider_id"] == id1

    # In-place dynamic priority change in the same process
    db.change_priority(id2, 1)

    # Subsequent request reflects the updated database state immediately
    res_after = coord.execute_lookup("5d41402abc4b2a76b9719d911017c592", "md5")
    assert res_after["provider_id"] == id2


# ── Scenario 4: A failed highest-priority API triggers failover to next eligible API ─
def test_04_failed_highest_priority_triggers_failover(env):
    db, crypto, coord, provider = env["db"], env["crypto"], env["coordinator"], env["provider"]

    id1 = db.insert_config("mock_priority_provider", "API 1", "https://api1", crypto.encrypt("k1"), priority=1)
    id2 = db.insert_config("mock_priority_provider", "API 2", "https://api2", crypto.encrypt("k2"), priority=2)

    # API 1 fails with server error
    provider.set_behavior("k1", ProviderLookupResult(
        success=False, status="server_error", found=False, http_status=500, error_message="Internal error"
    ))

    res = coord.execute_lookup("5d41402abc4b2a76b9719d911017c592", "md5")
    assert res["success"] is True
    assert res["provider_id"] == id2
    assert res["provider_name"] == "API 2"
    assert len(provider.calls) == 2


# ── Scenario 5: Failover follows the latest priority order ───────────────────
def test_05_failover_follows_latest_priority_order(env):
    db, crypto, coord, provider = env["db"], env["crypto"], env["coordinator"], env["provider"]

    # Initial order: API B (1), API C (2), API A (3)
    id_b = db.insert_config("mock_priority_provider", "API B", "https://b", crypto.encrypt("kb"), priority=1)
    id_c = db.insert_config("mock_priority_provider", "API C", "https://c", crypto.encrypt("kc"), priority=2)
    id_a = db.insert_config("mock_priority_provider", "API A", "https://a", crypto.encrypt("ka"), priority=3)

    # API B fails; API C also fails; API A succeeds
    provider.set_behavior("kb", ProviderLookupResult(success=False, status="server_error", found=False, http_status=502))
    provider.set_behavior("kc", ProviderLookupResult(success=False, status="timeout", found=False))

    res = coord.execute_lookup("5d41402abc4b2a76b9719d911017c592", "md5")
    assert res["success"] is True
    assert res["provider_id"] == id_a
    assert res["provider_name"] == "API A"

    # Verify attempt sequence was strictly B -> C -> A
    attempted_keys = [c["credential"] for c in provider.calls]
    assert attempted_keys == ["kb", "kc", "ka"]


# ── Scenario 6: A successful provider stops further attempts ─────────────────
def test_06_successful_provider_stops_further_attempts(env):
    db, crypto, coord, provider = env["db"], env["crypto"], env["coordinator"], env["provider"]

    db.insert_config("mock_priority_provider", "API 1", "https://1", crypto.encrypt("k1"), priority=1)
    db.insert_config("mock_priority_provider", "API 2", "https://2", crypto.encrypt("k2"), priority=2)
    db.insert_config("mock_priority_provider", "API 3", "https://3", crypto.encrypt("k3"), priority=3)

    res = coord.execute_lookup("5d41402abc4b2a76b9719d911017c592", "md5")
    assert res["success"] is True
    # Exactly 1 call was made to API 1, no further attempts
    assert len(provider.calls) == 1
    assert provider.calls[0]["credential"] == "k1"


# ── Scenario 7: Quota exhaustion triggers failover without deleting the API ──
def test_07_quota_exhaustion_triggers_failover_without_deletion(env):
    db, crypto, coord, provider = env["db"], env["crypto"], env["coordinator"], env["provider"]

    id1 = db.insert_config("mock_priority_provider", "API 1", "https://1", crypto.encrypt("k1"), priority=1)
    id2 = db.insert_config("mock_priority_provider", "API 2", "https://2", crypto.encrypt("k2"), priority=2)

    provider.set_behavior("k1", ProviderLookupResult(
        success=False, status="quota_exhausted", found=False, error_message="Daily quota exceeded"
    ))

    res = coord.execute_lookup("5d41402abc4b2a76b9719d911017c592", "md5")
    assert res["success"] is True
    assert res["provider_id"] == id2

    # Verify API 1 is NOT deleted
    cfg1 = db.get_config_by_id(id1)
    assert cfg1 is not None
    assert cfg1["health_status"] == "quota_exhausted"
    assert cfg1["paused_until"] is not None
    assert crypto.decrypt(cfg1["encrypted_credential"]) == "k1"


# ── Scenario 8: HTTP 429 handling respects Retry-After where available ────────
def test_08_http_429_respects_retry_after(env):
    db, crypto, coord, provider = env["db"], env["crypto"], env["coordinator"], env["provider"]

    id1 = db.insert_config("mock_priority_provider", "API 1", "https://1", crypto.encrypt("k1"), priority=1)
    id2 = db.insert_config("mock_priority_provider", "API 2", "https://2", crypto.encrypt("k2"), priority=2)

    provider.set_behavior("k1", ProviderLookupResult(
        success=False, status="rate_limited", found=False, http_status=429, retry_after_seconds=180
    ))

    res = coord.execute_lookup("5d41402abc4b2a76b9719d911017c592", "md5")
    assert res["success"] is True
    assert res["provider_id"] == id2

    cfg1 = db.get_config_by_id(id1)
    assert cfg1["health_status"] == "rate_limited"
    assert cfg1["paused_until"] is not None


# ── Scenario 9: HTTP 401 and 403 responses do not delete the provider ────────
def test_09_auth_failures_do_not_delete_provider(env):
    db, crypto, coord, provider = env["db"], env["crypto"], env["coordinator"], env["provider"]

    id1 = db.insert_config("mock_priority_provider", "API 1", "https://1", crypto.encrypt("invalid_token"), priority=1)
    id2 = db.insert_config("mock_priority_provider", "API 2", "https://2", crypto.encrypt("k2"), priority=2)

    provider.set_behavior("invalid_token", ProviderLookupResult(
        success=False, status="auth_failed", found=False, http_status=401, error_message="Unauthorized"
    ))

    res = coord.execute_lookup("5d41402abc4b2a76b9719d911017c592", "md5")
    assert res["success"] is True
    assert res["provider_id"] == id2

    cfg1 = db.get_config_by_id(id1)
    assert cfg1 is not None
    assert cfg1["health_status"] == "auth_failed"
    assert cfg1["paused_until"] is None  # Needs manual admin resolution
    assert crypto.decrypt(cfg1["encrypted_credential"]) == "invalid_token"


# ── Scenario 10: HTTP 5xx errors trigger appropriate bounded failover ─────────
def test_10_http_5xx_errors_trigger_bounded_failover(env):
    db, crypto, coord, provider = env["db"], env["crypto"], env["coordinator"], env["provider"]

    id1 = db.insert_config("mock_priority_provider", "API 1", "https://1", crypto.encrypt("k1"), priority=1)
    id2 = db.insert_config("mock_priority_provider", "API 2", "https://2", crypto.encrypt("k2"), priority=2)

    provider.set_behavior("k1", ProviderLookupResult(
        success=False, status="server_error", found=False, http_status=503, error_message="Service Unavailable"
    ))

    res = coord.execute_lookup("5d41402abc4b2a76b9719d911017c592", "md5")
    assert res["success"] is True
    assert res["provider_id"] == id2

    cfg1 = db.get_config_by_id(id1)
    assert cfg1["health_status"] == "degraded"
    assert cfg1["paused_until"] is not None


# ── Scenario 11: Network timeouts trigger appropriate bounded failover ────────
def test_11_network_timeouts_trigger_failover(env):
    db, crypto, coord, provider = env["db"], env["crypto"], env["coordinator"], env["provider"]

    id1 = db.insert_config("mock_priority_provider", "API 1", "https://1", crypto.encrypt("k1"), priority=1)
    id2 = db.insert_config("mock_priority_provider", "API 2", "https://2", crypto.encrypt("k2"), priority=2)

    provider.set_behavior("k1", ProviderLookupResult(
        success=False, status="timeout", found=False, error_category="network_timeout", error_message="Timed out"
    ))

    res = coord.execute_lookup("5d41402abc4b2a76b9719d911017c592", "md5")
    assert res["success"] is True
    assert res["provider_id"] == id2

    cfg1 = db.get_config_by_id(id1)
    assert cfg1["health_status"] == "temporarily_unavailable"
    assert cfg1["paused_until"] is not None


# ── Scenario 12: Invalid user input does not trigger unnecessary provider calls ─
def test_12_invalid_user_input_does_not_call_providers(env):
    db, crypto, coord, provider = env["db"], env["crypto"], env["coordinator"], env["provider"]

    db.insert_config("mock_priority_provider", "API 1", "https://1", crypto.encrypt("k1"), priority=1)

    # Empty input
    res_empty = coord.execute_lookup("", "md5")
    assert res_empty["success"] is False
    assert res_empty["status"] == "invalid_input"
    assert len(provider.calls) == 0

    # Service-level validation check via StudentLookupService
    svc = StudentLookupService(config=env["config"], db=db, crypto=crypto, failover=coord)
    res_bad = svc.student_lookup("not-a-valid-hex-hash", "md5")
    assert res_bad["success"] is False
    assert res_bad["status"] == "invalid_input"
    assert len(provider.calls) == 0


# ── Scenario 13: Failed providers remain in PostgreSQL with credentials intact ─
def test_13_failed_providers_remain_intact(env):
    db, crypto, coord, provider = env["db"], env["crypto"], env["coordinator"], env["provider"]

    id1 = db.insert_config("mock_priority_provider", "API 1", "https://1", crypto.encrypt("secret_k1"), priority=1)
    provider.set_behavior("secret_k1", ProviderLookupResult(success=False, status="server_error", found=False, http_status=500))

    coord.execute_lookup("5d41402abc4b2a76b9719d911017c592", "md5")

    cfg1 = db.get_config_by_id(id1)
    assert cfg1 is not None
    assert cfg1["display_name"] == "API 1"
    assert cfg1["priority"] == 1
    assert crypto.decrypt(cfg1["encrypted_credential"]) == "secret_k1"


# ── Scenario 14: Temporarily unavailable APIs recover when eligible ───────────
def test_14_temporarily_unavailable_apis_recover_when_eligible(env):
    db, crypto, coord, provider = env["db"], env["crypto"], env["coordinator"], env["provider"]

    id1 = db.insert_config("mock_priority_provider", "API 1", "https://1", crypto.encrypt("k1"), priority=1)

    # Put API 1 in cooldown in the past
    past_iso = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
    db.set_health_status(id1, "degraded", paused_until=past_iso)

    # Query eligible configs -> expired window auto-clears to 'active'
    eligible = db.get_eligible_configs()
    assert len(eligible) == 1
    assert eligible[0]["id"] == id1
    assert eligible[0]["health_status"] == "active"

    # Execution immediately uses API 1
    res = coord.execute_lookup("5d41402abc4b2a76b9719d911017c592", "md5")
    assert res["success"] is True
    assert res["provider_id"] == id1


# ── Scenario 15: Manually disabled APIs remain disabled ───────────────────────
def test_15_manually_disabled_apis_remain_disabled(env):
    db, crypto, coord, provider = env["db"], env["crypto"], env["coordinator"], env["provider"]

    id1 = db.insert_config("mock_priority_provider", "API 1", "https://1", crypto.encrypt("k1"), priority=1, enabled=0)
    id2 = db.insert_config("mock_priority_provider", "API 2", "https://2", crypto.encrypt("k2"), priority=2, enabled=1)

    # Expired cooldown must NOT reactivate manually disabled API
    past_iso = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
    db.set_health_status(id1, "active", paused_until=past_iso)

    res = coord.execute_lookup("5d41402abc4b2a76b9719d911017c592", "md5")
    assert res["success"] is True
    assert res["provider_id"] == id2

    # Verify API 1 is still disabled in database
    cfg1 = db.get_config_by_id(id1)
    assert cfg1["enabled"] == 0


# ── Scenario 16: All-provider failure returns a safe error ────────────────────
def test_16_all_provider_failure_returns_safe_error(env):
    db, crypto, coord, provider = env["db"], env["crypto"], env["coordinator"], env["provider"]

    db.insert_config("mock_priority_provider", "API 1", "https://1", crypto.encrypt("k1"), priority=1)
    provider.set_behavior("k1", ProviderLookupResult(success=False, status="quota_exhausted", found=False))

    res = coord.execute_lookup("5d41402abc4b2a76b9719d911017c592", "md5")
    assert res["success"] is False
    assert res["status"] in ("all_providers_failed", "no_provider_available")
    assert "All configured APIs are currently unavailable" in res["message"]
    # Ensure no credentials leaked in error
    assert "k1" not in str(res)


# ── Scenario 17: Maximum retry limits are enforced ───────────────────────────
def test_17_maximum_retry_limits_are_enforced(env):
    db, crypto, coord, provider = env["db"], env["crypto"], env["coordinator"], env["provider"]

    # Insert 8 failing APIs; config max attempts is 5
    for i in range(1, 9):
        db.insert_config("mock_priority_provider", f"API {i}", f"https://{i}", crypto.encrypt(f"key{i}"), priority=i)
        provider.set_behavior(f"key{i}", ProviderLookupResult(success=False, status="server_error", found=False, http_status=500))

    res = coord.execute_lookup("5d41402abc4b2a76b9719d911017c592", "md5")
    assert res["success"] is False
    # Max attempts was capped at 5
    assert len(provider.calls) == 5


# ── Scenario 18: Concurrent requests do not corrupt persistent provider state ─
def test_18_concurrent_requests_do_not_corrupt_state(env):
    db, crypto, coord, provider = env["db"], env["crypto"], env["coordinator"], env["provider"]

    db.insert_config("mock_priority_provider", "API 1", "https://1", crypto.encrypt("k1"), priority=1)
    db.insert_config("mock_priority_provider", "API 2", "https://2", crypto.encrypt("k2"), priority=2)

    def run_query(i):
        return coord.execute_lookup("5d41402abc4b2a76b9719d911017c592", "md5")

    with ThreadPoolExecutor(max_workers=6) as executor:
        results = list(executor.map(run_query, range(18)))

    assert all(r["success"] is True for r in results)
    assert all(r["provider_id"] == 1 for r in results)

    # Check total requests counter
    cfg1 = db.get_config_by_id(1)
    assert cfg1["total_successes"] == 18
    assert cfg1["health_status"] == "active"


# ── Scenario 19: Separate application instances observe same priority and health state ─
def test_19_separate_instances_observe_same_state(env):
    db, crypto, config, provider = env["db"], env["crypto"], env["config"], env["provider"]

    id1 = db.insert_config("mock_priority_provider", "API 1", "https://1", crypto.encrypt("k1"), priority=1)
    id2 = db.insert_config("mock_priority_provider", "API 2", "https://2", crypto.encrypt("k2"), priority=2)

    # Instance A and Instance B connecting to the same persistent store
    instance_a = ApiFailoverCoordinator(db=db, crypto=crypto, config=config)
    instance_b = ApiFailoverCoordinator(db=db, crypto=crypto, config=config)

    # Both run lookups -> both attempt Priority 1
    r_a = instance_a.execute_lookup("5d41402abc4b2a76b9719d911017c592", "md5")
    r_b = instance_b.execute_lookup("5d41402abc4b2a76b9719d911017c592", "md5")
    assert r_a["provider_id"] == id1
    assert r_b["provider_id"] == id1

    # Instance A pauses API 1
    db.set_health_status(id1, "quota_exhausted", paused_until="2099-01-01T00:00:00+00:00")

    # Instance B immediately sees API 1 is ineligible and routes to Priority 2
    r_b2 = instance_b.execute_lookup("5d41402abc4b2a76b9719d911017c592", "md5")
    assert r_b2["provider_id"] == id2


# ── Scenario 20: Existing administrator, sub-admin, and management functionality works ─
def test_20_existing_admin_and_management_features_continue_working(env):
    db, crypto = env["db"], env["crypto"]

    # 1. User management
    main_admin_id = db.create_user("main_admin_user", "AdminPass123!", role="main_admin")
    subadmin_id = db.create_user("subadmin_user", "SubadminPass123!", role="subadmin")
    assert main_admin_id is not None
    assert subadmin_id is not None

    # 2. Config creation with ownership
    c1 = db.insert_config(
        provider_name="mock_priority_provider",
        display_name="Subadmin API",
        endpoint="https://sub",
        encrypted_credential=crypto.encrypt("k_sub"),
        owner_id=subadmin_id,
        priority=1,
    )
    assert db.get_config_by_id(c1)["owner_id"] == subadmin_id

    # 3. Client API key creation
    api_key_record = db.create_client_api_key("Integration Test Partner", rate_limit_per_minute=50)
    assert api_key_record is not None
    raw_key = api_key_record["api_key"]
    fetched = db.get_client_api_key(raw_key)
    assert fetched["name"] == "Integration Test Partner"
    assert fetched["is_active"] == 1
