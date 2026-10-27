"""
Unit and integration tests for automatic provider failover and priority rotation logic.

Tests cover all required scenarios from Section 9:
- Test A: Two providers (A #1, B #2). Provider A returns HTTP 429 with Retry-After.
          Provider B promoted to #1, A demoted to #2. Failover to B succeeds.
- Test B: Four providers (A #1, B #2, C #3, D #4). Provider A fails (500), B fails (429), C succeeds.
          Order shifts cleanly: B #1, C #2, D #3, A #4, then C #1, D #2, A #3, B #4.
- Test C: Provider timeout. Provider A times out, demoted to last, fails over to next provider.
- Test D: Invalid request. Bad hash format / malformed input returns 400 with zero priority shifts.
- Test E: No-match response. Legitimate negative result returns terminal not_found with zero priority shifts.
- Test F: All providers fail. Bounded failover returns safe 503 without infinite loop; each attempted once.
- Test G: Persistence across reloads. Priorities survive new database connections / process re-instantiation.
- Test H: Concurrent failures. Parallel executions maintain atomic consistency (consecutive 1..N, no duplicates).
- Test I: Manual reorder followed by automatic rotation. Admin sets order, subsequent failure rotates from that order.
- Test J: Cooldown expiration preserves demoted priority (demoted provider stays demoted after recovery).
"""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import time
from typing import Any
import pytest

from config import Config
from database import Database
from services.crypto import CredentialCrypto
from services.failover import ApiFailoverCoordinator
from services.providers.base import BaseProviderAdapter, ProviderLookupResult
from services.providers.registry import register_provider
from services.student_lookup import StudentLookupService


class MockRotatableProvider(BaseProviderAdapter):
    """Mock provider with call history and configurable per-credential responses."""

    name = "mock_rotatable_provider"

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
            plaintext=f"plaintext_for_{credential}",
            duration=0.02,
        )

    def test_connection(self, credential, endpoint, timeout=10, **kwargs):
        return True, "Mock connection OK"


@pytest.fixture
def rotation_env(tmp_path):
    """Create an isolated test environment with SQLite database, crypto, and failover coordinator."""
    db_file = str(tmp_path / "test_rotation.db")
    config = Config()
    config.DATABASE_PATH = db_file
    config.STUDENT_LOOKUP_TIMEOUT_SECONDS = 5
    config.DEFAULT_PAUSE_DURATION_MINUTES = 30
    config.MAX_FAILOVER_ATTEMPTS = 5
    config.SERVER_ERROR_COOLDOWN_SECONDS = 60
    config.NETWORK_ERROR_COOLDOWN_SECONDS = 60
    config.RATE_LIMIT_COOLDOWN_SECONDS = 60

    db = Database(db_path=db_file, config=config)
    crypto = CredentialCrypto("test-rotation-secret-32-chars!!")
    coordinator = ApiFailoverCoordinator(db=db, crypto=crypto, config=config)

    provider = MockRotatableProvider()
    register_provider("mock_rotatable_provider", lambda: provider)

    lookup_service = StudentLookupService(
        config=config,
        db=db,
        crypto=crypto,
        failover=coordinator,
    )
    # Enable coordinator dispatch in test environment
    lookup_service.enable_live_in_tests = True

    return {
        "db": db,
        "crypto": crypto,
        "coordinator": coordinator,
        "config": config,
        "provider": provider,
        "lookup_service": lookup_service,
        "db_path": db_file,
    }


# ── Test A: Two providers, HTTP 429 with Retry-After ─────────────────────────
def test_scenario_a_two_providers_http_429_retry_after(rotation_env):
    """
    Provider A (#1) returns HTTP 429 with Retry-After: 120.
    Verify:
      1. Provider B is promoted to Priority #1.
      2. Provider A is moved to Priority #2.
      3. Provider A is marked 'rate_limited' with paused_until set.
      4. Lookup continues with Provider B and succeeds.
    """
    db = rotation_env["db"]
    crypto = rotation_env["crypto"]
    coord = rotation_env["coordinator"]
    provider = rotation_env["provider"]

    id_a = db.insert_config("mock_rotatable_provider", "Provider A", "https://api-a", crypto.encrypt("key-a"), priority=1)
    id_b = db.insert_config("mock_rotatable_provider", "Provider B", "https://api-b", crypto.encrypt("key-b"), priority=2)

    # Provider A returns 429 rate limited with Retry-After: 120
    provider.set_behavior("key-a", ProviderLookupResult(
        success=False,
        status="rate_limited",
        found=False,
        http_status=429,
        retry_after_seconds=120,
        error_category="rate_limit",
        error_message="Too Many Requests",
    ))
    # Provider B succeeds
    provider.set_behavior("key-b", ProviderLookupResult(
        success=True,
        status="match_found",
        found=True,
        plaintext="secret_resolved_b",
    ))

    result = coord.execute_lookup("5d41402abc4b2a76b9719d911017c592", "md5")

    # Lookup must succeed via Provider B
    assert result["success"] is True
    assert result["found"] is True
    assert result["plaintext"] == "secret_resolved_b"
    assert result["provider_id"] == id_b
    assert result["provider_name"] == "Provider B"

    # Verify both providers were called in sequence
    assert [c["credential"] for c in provider.calls] == ["key-a", "key-b"]

    # Verify priorities updated in database
    cfg_b = db.get_config_by_id(id_b)
    cfg_a = db.get_config_by_id(id_a)
    assert cfg_b["priority"] == 1
    assert cfg_b["health_status"] == "active"
    assert cfg_a["priority"] == 2
    assert cfg_a["health_status"] == "rate_limited"
    assert cfg_a["paused_until"] is not None

    # Check paused_until is ~120s in the future
    now_utc = datetime.now(timezone.utc)
    paused_until = datetime.fromisoformat(cfg_a["paused_until"])
    assert paused_until > now_utc + timedelta(seconds=100)


# ── Test B: Four providers, cascading failover ───────────────────────────────
def test_scenario_b_four_providers_cascading_failover(rotation_env):
    """
    Four providers: A (#1), B (#2), C (#3), D (#4).
    Provider A fails with 500. Provider B fails with 429. Provider C succeeds.
    Verify:
      1. After A fails: B #1, C #2, D #3, A #4.
      2. After B fails: C #1, D #2, A #3, B #4.
      3. Final order in database: C is #1, D is #2, A is #3, B is #4.
      4. Priorities are strictly consecutive 1..4 without gaps or duplicates.
    """
    db = rotation_env["db"]
    crypto = rotation_env["crypto"]
    coord = rotation_env["coordinator"]
    provider = rotation_env["provider"]

    id_a = db.insert_config("mock_rotatable_provider", "Provider A", "https://api-a", crypto.encrypt("key-a"), priority=1)
    id_b = db.insert_config("mock_rotatable_provider", "Provider B", "https://api-b", crypto.encrypt("key-b"), priority=2)
    id_c = db.insert_config("mock_rotatable_provider", "Provider C", "https://api-c", crypto.encrypt("key-c"), priority=3)
    id_d = db.insert_config("mock_rotatable_provider", "Provider D", "https://api-d", crypto.encrypt("key-d"), priority=4)

    provider.set_behavior("key-a", ProviderLookupResult(
        success=False, status="server_error", found=False, http_status=500, error_message="Internal Server Error"
    ))
    provider.set_behavior("key-b", ProviderLookupResult(
        success=False, status="rate_limited", found=False, http_status=429, retry_after_seconds=60, error_message="Rate limit"
    ))
    provider.set_behavior("key-c", ProviderLookupResult(
        success=True, status="match_found", found=True, plaintext="result_from_c"
    ))

    result = coord.execute_lookup("5d41402abc4b2a76b9719d911017c592", "md5")

    assert result["success"] is True
    assert result["provider_id"] == id_c
    assert result["plaintext"] == "result_from_c"

    # Calls made in order: key-a -> key-b -> key-c
    assert [c["credential"] for c in provider.calls] == ["key-a", "key-b", "key-c"]

    # Verify final priorities in database
    configs = {c["id"]: c for c in db.get_all_configs()}
    assert configs[id_c]["priority"] == 1
    assert configs[id_d]["priority"] == 2
    assert configs[id_a]["priority"] == 3
    assert configs[id_b]["priority"] == 4

    priorities = sorted(c["priority"] for c in configs.values())
    assert priorities == [1, 2, 3, 4]


# ── Test C: Provider timeout ────────────────────────────────────────────────
def test_scenario_c_provider_timeout_failover(rotation_env):
    """
    Provider A (#1) times out.
    Verify:
      1. Provider A demoted to Priority #2 (health_status='temporarily_unavailable').
      2. Provider B promoted to Priority #1.
      3. Request succeeds via Provider B.
    """
    db = rotation_env["db"]
    crypto = rotation_env["crypto"]
    coord = rotation_env["coordinator"]
    provider = rotation_env["provider"]

    id_a = db.insert_config("mock_rotatable_provider", "Provider A", "https://api-a", crypto.encrypt("key-a"), priority=1)
    id_b = db.insert_config("mock_rotatable_provider", "Provider B", "https://api-b", crypto.encrypt("key-b"), priority=2)

    provider.set_behavior("key-a", ProviderLookupResult(
        success=False, status="timeout", found=False, error_category="network_timeout", error_message="Request timed out"
    ))
    provider.set_behavior("key-b", ProviderLookupResult(
        success=True, status="match_found", found=True, plaintext="result_b"
    ))

    res = coord.execute_lookup("5d41402abc4b2a76b9719d911017c592", "md5")
    assert res["success"] is True
    assert res["provider_id"] == id_b

    cfg_a = db.get_config_by_id(id_a)
    cfg_b = db.get_config_by_id(id_b)
    assert cfg_b["priority"] == 1
    assert cfg_a["priority"] == 2
    assert cfg_a["health_status"] == "temporarily_unavailable"


# ── Test D: Invalid request (Non-qualifying) ─────────────────────────────────
def test_scenario_d_invalid_request_no_priority_shift(rotation_env):
    """
    Malformed user input (invalid hex characters or incorrect length).
    Verify:
      1. Validation rejects request immediately with 400 / invalid_input.
      2. Zero provider adapter calls are made.
      3. Zero priority shifts occur; database priorities remain unchanged.
    """
    db = rotation_env["db"]
    crypto = rotation_env["crypto"]
    provider = rotation_env["provider"]
    lookup_svc = rotation_env["lookup_service"]

    id_a = db.insert_config("mock_rotatable_provider", "Provider A", "https://api-a", crypto.encrypt("key-a"), priority=1)
    id_b = db.insert_config("mock_rotatable_provider", "Provider B", "https://api-b", crypto.encrypt("key-b"), priority=2)

    # Invalid input (not hex, wrong length)
    bad_res = lookup_svc.student_lookup("invalid_not_a_hash_value!", "md5")
    assert bad_res["success"] is False
    assert bad_res["status"] == "invalid_input"

    # Zero provider calls
    assert len(provider.calls) == 0

    # Priorities unchanged
    assert db.get_config_by_id(id_a)["priority"] == 1
    assert db.get_config_by_id(id_b)["priority"] == 2


# ── Test E: Verified no-match response (Non-qualifying) ──────────────────────
def test_scenario_e_verified_no_match_no_priority_shift(rotation_env):
    """
    Provider responds with verified negative result (found=False, match_not_found).
    Verify:
      1. Request terminates immediately with found=False.
      2. Provider A is NOT rotated or demoted (remains Priority #1, active).
      3. No failover to Provider B is attempted.
    """
    db = rotation_env["db"]
    crypto = rotation_env["crypto"]
    coord = rotation_env["coordinator"]
    provider = rotation_env["provider"]

    id_a = db.insert_config("mock_rotatable_provider", "Provider A", "https://api-a", crypto.encrypt("key-a"), priority=1)
    id_b = db.insert_config("mock_rotatable_provider", "Provider B", "https://api-b", crypto.encrypt("key-b"), priority=2)

    provider.set_behavior("key-a", ProviderLookupResult(
        success=True,
        status="not_found",
        found=False,
        error_message="Hash not found in database",
    ))

    res = coord.execute_lookup("5d41402abc4b2a76b9719d911017c592", "md5")

    assert res["success"] is True
    assert res["found"] is False
    assert res["status"] == "not_found"
    assert res["provider_id"] == id_a

    # Only Provider A was called
    assert len(provider.calls) == 1
    assert provider.calls[0]["credential"] == "key-a"

    # Priorities remain intact
    assert db.get_config_by_id(id_a)["priority"] == 1
    assert db.get_config_by_id(id_a)["health_status"] == "active"
    assert db.get_config_by_id(id_b)["priority"] == 2


# ── Test F: All providers fail ──────────────────────────────────────────────
def test_scenario_f_all_providers_unavailable(rotation_env):
    """
    All providers fail with qualifying errors.
    Verify:
      1. Bounded failover terminates safely without infinite loop.
      2. Each provider is attempted exactly once.
      3. Returns safe error status 'all_providers_failed'.
      4. All providers have valid consecutive priorities 1..3 with no duplicates.
    """
    db = rotation_env["db"]
    crypto = rotation_env["crypto"]
    coord = rotation_env["coordinator"]
    provider = rotation_env["provider"]

    id_a = db.insert_config("mock_rotatable_provider", "Provider A", "https://api-a", crypto.encrypt("key-a"), priority=1)
    id_b = db.insert_config("mock_rotatable_provider", "Provider B", "https://api-b", crypto.encrypt("key-b"), priority=2)
    id_c = db.insert_config("mock_rotatable_provider", "Provider C", "https://api-c", crypto.encrypt("key-c"), priority=3)

    provider.set_behavior("key-a", ProviderLookupResult(success=False, status="server_error", found=False, http_status=500))
    provider.set_behavior("key-b", ProviderLookupResult(success=False, status="server_error", found=False, http_status=502))
    provider.set_behavior("key-c", ProviderLookupResult(success=False, status="server_error", found=False, http_status=503))

    res = coord.execute_lookup("5d41402abc4b2a76b9719d911017c592", "md5")

    assert res["success"] is False
    assert res["status"] == "all_providers_failed"

    # Exactly 3 attempts made
    assert len(provider.calls) == 3
    assert [c["credential"] for c in provider.calls] == ["key-a", "key-b", "key-c"]

    # Check priorities remain strictly 1..3
    all_cfgs = db.get_all_configs()
    priorities = sorted(c["priority"] for c in all_cfgs)
    assert priorities == [1, 2, 3]


# ── Test G: Persistence across reloads ──────────────────────────────────────
def test_scenario_g_persistence_across_database_connections(rotation_env):
    """
    Verify updated priorities survive database connection closing and re-instantiation.
    """
    db = rotation_env["db"]
    crypto = rotation_env["crypto"]
    coord = rotation_env["coordinator"]
    provider = rotation_env["provider"]
    db_path = rotation_env["db_path"]
    config = rotation_env["config"]

    id_a = db.insert_config("mock_rotatable_provider", "Provider A", "https://api-a", crypto.encrypt("key-a"), priority=1)
    id_b = db.insert_config("mock_rotatable_provider", "Provider B", "https://api-b", crypto.encrypt("key-b"), priority=2)

    # Provider A fails with 429
    provider.set_behavior("key-a", ProviderLookupResult(
        success=False, status="rate_limited", found=False, http_status=429, retry_after_seconds=60
    ))
    coord.execute_lookup("5d41402abc4b2a76b9719d911017c592", "md5")

    # Instantiate a completely fresh Database instance pointing to the same file
    new_db = Database(db_path=db_path, config=config)

    cfg_b = new_db.get_config_by_id(id_b)
    cfg_a = new_db.get_config_by_id(id_a)
    assert cfg_b["priority"] == 1
    assert cfg_a["priority"] == 2
    assert cfg_a["health_status"] == "rate_limited"


# ── Test H: Concurrent failures safety ──────────────────────────────────────
def test_scenario_h_concurrent_failures_safety(rotation_env):
    """
    Multiple concurrent failures must not create duplicate priorities or gaps.
    """
    db = rotation_env["db"]
    crypto = rotation_env["crypto"]

    ids = [
        db.insert_config("mock_rotatable_provider", f"Provider {i}", f"https://api-{i}", crypto.encrypt(f"key-{i}"), priority=i)
        for i in range(1, 6)
    ]

    def trigger_demote(cid):
        db.demote_failed_provider_to_last(
            config_id=cid,
            health_status="temporarily_unavailable",
            paused_until=None,
            error_category="concurrency_test",
            failure_reason="Concurrent test failure",
        )

    # Run concurrent demotions across multiple threads
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(trigger_demote, cid) for cid in ids]
        for f in futures:
            f.result()

    # Priorities must be strictly a permutation of 1..5
    configs = db.get_all_configs()
    priorities = sorted(c["priority"] for c in configs)
    assert priorities == [1, 2, 3, 4, 5]


# ── Test I: Manual reorder followed by automatic rotation ────────────────────
def test_scenario_i_manual_reorder_then_automatic_rotation(rotation_env):
    """
    Admin manually changes priority order, and subsequent failure rotates from that order.
    """
    db = rotation_env["db"]
    crypto = rotation_env["crypto"]
    coord = rotation_env["coordinator"]
    provider = rotation_env["provider"]

    id_a = db.insert_config("mock_rotatable_provider", "Provider A", "https://api-a", crypto.encrypt("key-a"), priority=1)
    id_b = db.insert_config("mock_rotatable_provider", "Provider B", "https://api-b", crypto.encrypt("key-b"), priority=2)
    id_c = db.insert_config("mock_rotatable_provider", "Provider C", "https://api-c", crypto.encrypt("key-c"), priority=3)

    # Admin changes Provider C to Priority 1
    # Resulting order: C #1, A #2, B #3
    db.change_priority(id_c, 1)

    cfgs = {c["id"]: c for c in db.get_all_configs()}
    assert cfgs[id_c]["priority"] == 1
    assert cfgs[id_a]["priority"] == 2
    assert cfgs[id_b]["priority"] == 3

    # Now Provider C fails with 429
    provider.set_behavior("key-c", ProviderLookupResult(
        success=False, status="rate_limited", found=False, http_status=429, retry_after_seconds=60
    ))
    provider.set_behavior("key-a", ProviderLookupResult(
        success=True, status="match_found", found=True, plaintext="result_a"
    ))

    res = coord.execute_lookup("5d41402abc4b2a76b9719d911017c592", "md5")
    assert res["success"] is True
    assert res["provider_id"] == id_a

    # After C fails, it rotates to last:
    # A becomes #1, B becomes #2, C becomes #3
    cfgs_after = {c["id"]: c for c in db.get_all_configs()}
    assert cfgs_after[id_a]["priority"] == 1
    assert cfgs_after[id_b]["priority"] == 2
    assert cfgs_after[id_c]["priority"] == 3


# ── Test J: Cooldown expiration preserves demoted priority ───────────────────
def test_scenario_j_cooldown_expiration_preserves_demoted_priority(rotation_env):
    """
    When a demoted provider's cooldown expires, it returns to 'active' health status,
    but PRESERVES its demoted priority (does NOT jump back to Priority #1).
    """
    db = rotation_env["db"]
    crypto = rotation_env["crypto"]
    coord = rotation_env["coordinator"]
    provider = rotation_env["provider"]

    id_a = db.insert_config("mock_rotatable_provider", "Provider A", "https://api-a", crypto.encrypt("key-a"), priority=1)
    id_b = db.insert_config("mock_rotatable_provider", "Provider B", "https://api-b", crypto.encrypt("key-b"), priority=2)

    # Provider A fails with short cooldown
    past_paused_until = (datetime.now(timezone.utc) - timedelta(seconds=10)).isoformat()
    db.demote_failed_provider_to_last(
        id_a,
        health_status="rate_limited",
        paused_until=past_paused_until,
        error_category="rate_limit",
        failure_reason="429 Too Many Requests",
    )

    # Verify A is demoted to 2, B is promoted to 1
    assert db.get_config_by_id(id_a)["priority"] == 2
    assert db.get_config_by_id(id_b)["priority"] == 1

    # Calling get_eligible_configs unpauses expired records back to active
    eligible = db.get_eligible_configs()
    eligible_by_id = {c["id"]: c for c in eligible}

    assert id_a in eligible_by_id
    assert eligible_by_id[id_a]["health_status"] == "active"
    assert eligible_by_id[id_a]["paused_until"] is None
    # CRITICAL: Priority must STILL be 2, NOT 1!
    assert eligible_by_id[id_a]["priority"] == 2
    assert eligible_by_id[id_b]["priority"] == 1
