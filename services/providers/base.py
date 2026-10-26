"""
Base provider adapter interface for external lookup services.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any


@dataclass
class ProviderLookupResult:
    """Standardized result returned by a provider adapter."""

    success: bool
    status: str  # match_found, not_found, quota_exhausted, rate_limited, auth_failed, server_error, timeout, error
    found: bool
    plaintext: str | None = None
    retry_after_seconds: int | None = None
    error_category: str | None = None
    error_message: str | None = None
    http_status: int | None = None
    duration: float = 0.0

    @property
    def is_terminal_lookup(self) -> bool:
        """Return True if this response is a valid terminal lookup (match found or verified not found)."""
        return self.status in ("match_found", "not_found")

    @property
    def should_failover(self) -> bool:
        """Return True if the failure is provider-specific and eligible for failover."""
        return self.status in (
            "quota_exhausted",
            "rate_limited",
            "auth_failed",
            "server_error",
            "timeout",
            "connection_error",
            "error",
        )


class BaseProviderAdapter(ABC):
    """Abstract base class for all external credential lookup providers."""

    name: str = "base"

    @abstractmethod
    def lookup(
        self,
        credential: str,
        endpoint: str,
        hash_input: str,
        algorithm: str,
        timeout: int = 10,
        auth_config: dict[str, Any] | None = None,
        provider_config: dict[str, Any] | None = None,
    ) -> ProviderLookupResult:
        """
        Execute a hash lookup request against the provider.
        """
        pass

    @abstractmethod
    def test_connection(
        self,
        credential: str,
        endpoint: str,
        timeout: int = 10,
        auth_config: dict[str, Any] | None = None,
        provider_config: dict[str, Any] | None = None,
    ) -> tuple[bool, str]:
        """
        Perform a safe connection check against the provider without burning unnecessary quota.
        Returns (success: bool, message: str).
        """
        pass
