"""
Tests for dynamic API selection and automatic failover coordinator.
"""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from config import Config
from database import Database
from services.crypto import CredentialCrypto
from services.failover import ApiFailoverCoordinator
from services.providers.base import BaseProviderAdapter, ProviderLookupResult
from services.providers.registry import register_provider


@pytest.fixture
def failover_env(tmp_path):
    """Setup an isolated database and failover coordinator."""
    db_file = str(tmp_path / "test_failover.db")
    config = Config()
    config.DATABASE_PATH = db_file
    config.STUDENT_LOOKUP_TIMEOUT_SECONDS = 2
    config.DEFAULT_PAUSE_DURATION_MINUTES = 30
    config.MAX_FAILOVER_ATTEMPTS = 5

    db = Database(db_path=db_file, config=config)
    crypto = CredentialCrypto("test-encryption-key-for-failover-testing-123")
    coordinator = ApiFailoverCoordinator(db=db, crypto=crypto, config=config)

    return {
        "db": db,
        "crypto": crypto,
        "coordinator": coordinator,
        "config": config,
    }


class MockProvider(BaseProviderAdapter):
    """Configurable mock provider adapter for deterministic testing."""

    name = "mock_provider"

    def __init__(self, behavior_fn=None):
        self.call_count = 0
        self.called_with = []
        self.behavior_fn = behavior_fn

    def lookup(self, credential, endpoint, hash_input, algorithm, timeout=10, **kwargs):
        self.call_count += 1
        self.called_with.append((credential, endpoint, hash_input))
        if self.behavior_fn:
            return self.behavior_fn(credential, endpoint, hash_input, algorithm)
        return ProviderLookupResult(
            success=True,
            status="match_found",
            found=True,
            plaintext="hello",
            duration=0.01,
        )

    def test_connection(self, credential, endpoint, timeout=10, **kwargs):
        return True, "Mock connection successful."


class TestApiFailover:
    def test_single_working_api_returns_valid_result(self, failover_env):
        db = failover_env["db"]
        crypto = failover_env["crypto"]
        coord = failover_env["coordinator"]

        mock_adapter = MockProvider()
        register_provider("mock_provider", lambda: mock_adapter)

        db.insert_config(
            provider_name="mock_provider",
            display_name="Primary API",
            endpoint="https://api.test/v1",
            encrypted_credential=crypto.encrypt("key_1"),
            priority=10,
        )

        res = coord.execute_lookup("5d41402abc4b2a76b9719d911017c592", "md5")
        assert res["success"] is True
        assert res["found"] is True
        assert res["plaintext"] == "hello"
        assert res["provider_name"] == "Primary API"
        assert mock_adapter.call_count == 1

    def test_first_api_quota_exhausted_second_succeeds(self, failover_env):
        db = failover_env["db"]
        crypto = failover_env["crypto"]
        coord = failover_env["coordinator"]

        def mock_behavior(credential, endpoint, hash_input, algorithm):
            if credential == "key_exhausted":
                return ProviderLookupResult(
                    success=False,
                    status="quota_exhausted",
                    found=False,
                    error_category="quota_exhausted",
                    error_message="Daily limit reached.",
                )
            return ProviderLookupResult(
                success=True,
                status="match_found",
                found=True,
                plaintext="recovered_data",
            )

        adapter = MockProvider(behavior_fn=mock_behavior)
        register_provider("mock_provider", lambda: adapter)

        # Provider 1: high priority (10) but exhausted
        db.insert_config(
            provider_name="mock_provider",
            display_name="Exhausted API",
            endpoint="https://api.test/v1",
            encrypted_credential=crypto.encrypt("key_exhausted"),
            priority=10,
        )
        # Provider 2: lower priority (20), working
        db.insert_config(
            provider_name="mock_provider",
            display_name="Backup API",
            endpoint="https://api.test/v2",
            encrypted_credential=crypto.encrypt("key_backup"),
            priority=20,
        )

        res = coord.execute_lookup("5d41402abc4b2a76b9719d911017c592", "md5")
        assert res["success"] is True
        assert res["found"] is True
        assert res["plaintext"] == "recovered_data"
        assert res["provider_name"] == "Backup API"
        assert adapter.call_count == 2

        # Verify Provider 1 is now marked quota_exhausted and paused
        cfg1 = db.get_config_by_id(1)
        assert cfg1["health_status"] == "quota_exhausted"
        assert cfg1["paused_until"] is not None

    def test_two_apis_quota_exhausted_third_succeeds(self, failover_env):
        db = failover_env["db"]
        crypto = failover_env["crypto"]
        coord = failover_env["coordinator"]

        def mock_behavior(credential, endpoint, hash_input, algorithm):
            if credential in ("key_1", "key_2"):
                return ProviderLookupResult(
                    success=False,
                    status="quota_exhausted",
                    found=False,
                    error_category="quota_exhausted",
                )
            return ProviderLookupResult(
                success=True,
                status="match_found",
                found=True,
                plaintext="third_api_success",
            )

        adapter = MockProvider(behavior_fn=mock_behavior)
        register_provider("mock_provider", lambda: adapter)

        db.insert_config("mock_provider", "API 1", "https://api1", crypto.encrypt("key_1"), priority=10)
        db.insert_config("mock_provider", "API 2", "https://api2", crypto.encrypt("key_2"), priority=20)
        db.insert_config("mock_provider", "API 3", "https://api3", crypto.encrypt("key_3"), priority=30)

        res = coord.execute_lookup("5d41402abc4b2a76b9719d911017c592", "md5")
        assert res["success"] is True
        assert res["plaintext"] == "third_api_success"
        assert res["provider_name"] == "API 3"
        assert adapter.call_count == 3

    def test_all_apis_unavailable(self, failover_env):
        db = failover_env["db"]
        crypto = failover_env["crypto"]
        coord = failover_env["coordinator"]

        def mock_behavior(credential, endpoint, hash_input, algorithm):
            return ProviderLookupResult(
                success=False,
                status="quota_exhausted",
                found=False,
            )

        adapter = MockProvider(behavior_fn=mock_behavior)
        register_provider("mock_provider", lambda: adapter)

        db.insert_config("mock_provider", "API 1", "https://api1", crypto.encrypt("k1"), priority=10)
        db.insert_config("mock_provider", "API 2", "https://api2", crypto.encrypt("k2"), priority=20)

        res = coord.execute_lookup("5d41402abc4b2a76b9719d911017c592", "md5")
        assert res["success"] is False
        assert res["status"] == "all_providers_failed"

    def test_disabled_api_is_never_called(self, failover_env):
        db = failover_env["db"]
        crypto = failover_env["crypto"]
        coord = failover_env["coordinator"]

        adapter = MockProvider()
        register_provider("mock_provider", lambda: adapter)

        # Insert disabled API
        db.insert_config(
            provider_name="mock_provider",
            display_name="Disabled API",
            endpoint="https://api.test",
            encrypted_credential=crypto.encrypt("k_disabled"),
            priority=5,
            enabled=0,
        )

        res = coord.execute_lookup("5d41402abc4b2a76b9719d911017c592", "md5")
        assert res["success"] is False
        assert res["status"] == "no_provider_available"
        assert adapter.call_count == 0

    def test_quota_exhausted_api_is_not_retried_on_every_request(self, failover_env):
        db = failover_env["db"]
        crypto = failover_env["crypto"]
        coord = failover_env["coordinator"]

        def mock_behavior(credential, endpoint, hash_input, algorithm):
            if credential == "k_fail":
                return ProviderLookupResult(success=False, status="quota_exhausted", found=False)
            return ProviderLookupResult(success=True, status="match_found", found=True, plaintext="ok")

        adapter = MockProvider(behavior_fn=mock_behavior)
        register_provider("mock_provider", lambda: adapter)

        db.insert_config("mock_provider", "Flaky API", "https://api1", crypto.encrypt("k_fail"), priority=10)
        db.insert_config("mock_provider", "Stable API", "https://api2", crypto.encrypt("k_ok"), priority=20)

        # First request: Flaky fails, Stable succeeds (2 calls)
        res1 = coord.execute_lookup("5d41402abc4b2a76b9719d911017c592", "md5")
        assert res1["success"] is True
        assert adapter.call_count == 2

        # Second request: Flaky is now paused, so it MUST NOT be retried! Only Stable is called (1 call)
        res2 = coord.execute_lookup("5d41402abc4b2a76b9719d911017c592", "md5")
        assert res2["success"] is True
        assert adapter.call_count == 3  # 2 + 1 = 3, not 4!

    def test_rate_limited_api_respects_retry_window(self, failover_env):
        db = failover_env["db"]
        crypto = failover_env["crypto"]
        coord = failover_env["coordinator"]

        def mock_behavior(credential, endpoint, hash_input, algorithm):
            if credential == "k_ratelimit":
                return ProviderLookupResult(
                    success=False,
                    status="rate_limited",
                    found=False,
                    retry_after_seconds=3600,
                )
            return ProviderLookupResult(success=True, status="match_found", found=True, plaintext="ok")

        adapter = MockProvider(behavior_fn=mock_behavior)
        register_provider("mock_provider", lambda: adapter)

        db.insert_config("mock_provider", "Rate Limited API", "https://api1", crypto.encrypt("k_ratelimit"), priority=10)
        db.insert_config("mock_provider", "Backup API", "https://api2", crypto.encrypt("k_backup"), priority=20)

        coord.execute_lookup("5d41402abc4b2a76b9719d911017c592", "md5")

        cfg1 = db.get_config_by_id(1)
        assert cfg1["health_status"] == "rate_limited"
        assert cfg1["paused_until"] is not None

        # Verify it won't be called on next request
        adapter.call_count = 0
        coord.execute_lookup("5d41402abc4b2a76b9719d911017c592", "md5")
        assert adapter.call_count == 1  # Only backup was called

    def test_authentication_errors_not_classified_as_quota(self, failover_env):
        db = failover_env["db"]
        crypto = failover_env["crypto"]
        coord = failover_env["coordinator"]

        def mock_behavior(credential, endpoint, hash_input, algorithm):
            if credential == "k_bad":
                return ProviderLookupResult(
                    success=False,
                    status="auth_failed",
                    found=False,
                    error_category="auth_failed",
                    error_message="Invalid API Key",
                    http_status=401,
                )
            return ProviderLookupResult(success=True, status="match_found", found=True, plaintext="auth_ok")

        adapter = MockProvider(behavior_fn=mock_behavior)
        register_provider("mock_provider", lambda: adapter)

        db.insert_config("mock_provider", "Bad Key API", "https://api1", crypto.encrypt("k_bad"), priority=10)
        db.insert_config("mock_provider", "Good Key API", "https://api2", crypto.encrypt("k_good"), priority=20)

        coord.execute_lookup("5d41402abc4b2a76b9719d911017c592", "md5")

        cfg1 = db.get_config_by_id(1)
        assert cfg1["health_status"] == "auth_failed"
        assert cfg1["last_error_category"] == "auth_failed"

    def test_valid_negative_lookup_not_treated_as_provider_failure(self, failover_env):
        db = failover_env["db"]
        crypto = failover_env["crypto"]
        coord = failover_env["coordinator"]

        def mock_behavior(credential, endpoint, hash_input, algorithm):
            return ProviderLookupResult(
                success=True,
                status="not_found",
                found=False,
                plaintext=None,
            )

        adapter = MockProvider(behavior_fn=mock_behavior)
        register_provider("mock_provider", lambda: adapter)

        db.insert_config("mock_provider", "Primary API", "https://api1", crypto.encrypt("k1"), priority=10)
        db.insert_config("mock_provider", "Secondary API", "https://api2", crypto.encrypt("k2"), priority=20)

        res = coord.execute_lookup("5d41402abc4b2a76b9719d911017c592", "md5")
        assert res["success"] is True
        assert res["status"] == "not_found"
        assert res["found"] is False

        # Should NOT failover to secondary on legitimate negative result!
        assert adapter.call_count == 1

        # Primary should still be active
        cfg1 = db.get_config_by_id(1)
        assert cfg1["health_status"] == "active"
        assert cfg1["last_success_at"] is not None

    def test_concurrent_failover_safety(self, failover_env):
        db = failover_env["db"]
        crypto = failover_env["crypto"]
        coord = failover_env["coordinator"]

        adapter = MockProvider()
        register_provider("mock_provider", lambda: adapter)

        db.insert_config("mock_provider", "Concurrent API", "https://api1", crypto.encrypt("k1"), priority=10)

        def worker(_):
            return coord.execute_lookup("5d41402abc4b2a76b9719d911017c592", "md5")

        with ThreadPoolExecutor(max_workers=5) as executor:
            results = list(executor.map(worker, range(10)))

        assert all(r["success"] is True for r in results)
        assert adapter.call_count == 10
