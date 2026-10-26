"""
MD5Decrypt provider adapter.

Encapsulates HTTP transport, request formatting, failure classification,
and response parsing for both modern Bearer JSON API and legacy GET formats.
"""

import json
import time
from typing import Any

import requests

from services.providers.base import BaseProviderAdapter, ProviderLookupResult


class Md5DecryptAdapter(BaseProviderAdapter):
    """Adapter for MD5Decrypt (https://api.md5decrypt.net/)."""

    name: str = "md5decrypt"

    # Known quota error indicators in messages/codes
    _QUOTA_KEYWORDS = (
        "credit",
        "quota",
        "limit reached",
        "no credit",
        "out of credit",
        "daily limit",
        "exhausted",
        "error code : 002",
        "error code : 003",
    )

    _AUTH_KEYWORDS = (
        "unauthorized",
        "invalid key",
        "invalid token",
        "bad key",
        "bad code",
        "authentification",
        "authentication",
        "error code : 001",
    )

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
        """Execute a hash lookup request with detailed failure classification."""
        start_time = time.time()
        url = endpoint.strip() if endpoint else "https://api.md5decrypt.net/"

        # Choose between modern Bearer JSON API and legacy GET API
        is_legacy = "api.php" in url or (auth_config and auth_config.get("format") == "legacy")

        try:
            if is_legacy:
                return self._lookup_legacy(credential, url, hash_input, algorithm, timeout, start_time)
            return self._lookup_modern(credential, url, hash_input, algorithm, timeout, start_time)
        except requests.exceptions.Timeout:
            duration = round(time.time() - start_time, 4)
            return ProviderLookupResult(
                success=False,
                status="timeout",
                found=False,
                error_category="network_timeout",
                error_message="Request to MD5Decrypt timed out.",
                duration=duration,
            )
        except requests.exceptions.ConnectionError:
            duration = round(time.time() - start_time, 4)
            return ProviderLookupResult(
                success=False,
                status="connection_error",
                found=False,
                error_category="network_error",
                error_message="Could not establish connection to MD5Decrypt.",
                duration=duration,
            )
        except Exception as exc:
            duration = round(time.time() - start_time, 4)
            # Never include raw exception args that could contain credentials
            return ProviderLookupResult(
                success=False,
                status="error",
                found=False,
                error_category="unexpected_error",
                error_message=f"Provider request error: {exc.__class__.__name__}",
                duration=duration,
            )

    def _lookup_modern(
        self,
        credential: str,
        url: str,
        hash_input: str,
        algorithm: str,
        timeout: int,
        start_time: float,
    ) -> ProviderLookupResult:
        """Call the modern Bearer JSON POST API."""
        headers = {
            "Authorization": f"Bearer {credential}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "StudentCredentialsProvider/2.0",
        }
        payload = {
            "action": "lookup",
            "hashes": [hash_input],
        }

        resp = requests.post(url, headers=headers, json=payload, timeout=timeout)
        duration = round(time.time() - start_time, 4)

        # ── HTTP Level Error Classification ─────────────────────────────────
        if resp.status_code == 429:
            retry_after = self._parse_retry_after(resp)
            return ProviderLookupResult(
                success=False,
                status="rate_limited",
                found=False,
                retry_after_seconds=retry_after,
                error_category="rate_limited",
                error_message="MD5Decrypt rate limit exceeded (HTTP 429).",
                http_status=429,
                duration=duration,
            )

        if resp.status_code in (401, 403):
            return ProviderLookupResult(
                success=False,
                status="auth_failed",
                found=False,
                error_category="auth_failed",
                error_message="MD5Decrypt authentication failed (HTTP 401/403).",
                http_status=resp.status_code,
                duration=duration,
            )

        if resp.status_code >= 500:
            return ProviderLookupResult(
                success=False,
                status="server_error",
                found=False,
                error_category="server_error",
                error_message=f"MD5Decrypt server returned HTTP {resp.status_code}.",
                http_status=resp.status_code,
                duration=duration,
            )

        # ── Parse JSON Body ─────────────────────────────────────────────────
        try:
            body = resp.json()
        except ValueError:
            # Fallback text check
            text_lower = resp.text.lower()
            if any(q in text_lower for q in self._QUOTA_KEYWORDS):
                return ProviderLookupResult(
                    success=False,
                    status="quota_exhausted",
                    found=False,
                    error_category="quota_exhausted",
                    error_message="MD5Decrypt quota limit reached.",
                    http_status=resp.status_code,
                    duration=duration,
                )
            return ProviderLookupResult(
                success=False,
                status="error",
                found=False,
                error_category="invalid_response",
                error_message="MD5Decrypt returned invalid non-JSON response.",
                http_status=resp.status_code,
                duration=duration,
            )

        # ── Check Business Logic in JSON Body ───────────────────────────────
        if isinstance(body, dict):
            # Check for API-level error fields
            error_msg = str(body.get("error") or body.get("message") or "")
            err_lower = error_msg.lower()

            if any(k in err_lower for k in self._QUOTA_KEYWORDS):
                return ProviderLookupResult(
                    success=False,
                    status="quota_exhausted",
                    found=False,
                    error_category="quota_exhausted",
                    error_message="MD5Decrypt account credits exhausted.",
                    http_status=resp.status_code,
                    duration=duration,
                )

            if any(k in err_lower for k in self._AUTH_KEYWORDS):
                return ProviderLookupResult(
                    success=False,
                    status="auth_failed",
                    found=False,
                    error_category="auth_failed",
                    error_message="MD5Decrypt rejected authentication credential.",
                    http_status=resp.status_code,
                    duration=duration,
                )

            # Check results list
            results = body.get("results")
            if isinstance(results, list) and len(results) > 0:
                first = results[0]
                if isinstance(first, dict):
                    found = bool(first.get("found"))
                    plaintext = first.get("plaintext")
                    if found and plaintext:
                        return ProviderLookupResult(
                            success=True,
                            status="match_found",
                            found=True,
                            plaintext=str(plaintext),
                            http_status=resp.status_code,
                            duration=duration,
                        )
                    return ProviderLookupResult(
                        success=True,
                        status="not_found",
                        found=False,
                        plaintext=None,
                        http_status=resp.status_code,
                        duration=duration,
                    )

            # Direct dictionary response e.g. {"found": true, "plaintext": "..."}
            if "found" in body:
                found = bool(body["found"])
                plaintext = body.get("plaintext")
                if found and plaintext:
                    return ProviderLookupResult(
                        success=True,
                        status="match_found",
                        found=True,
                        plaintext=str(plaintext),
                        http_status=resp.status_code,
                        duration=duration,
                    )
                return ProviderLookupResult(
                    success=True,
                    status="not_found",
                    found=False,
                    plaintext=None,
                    http_status=resp.status_code,
                    duration=duration,
                )

        # Unrecognized JSON format
        return ProviderLookupResult(
            success=False,
            status="error",
            found=False,
            error_category="unexpected_schema",
            error_message="MD5Decrypt returned unexpected response structure.",
            http_status=resp.status_code,
            duration=duration,
        )

    def _lookup_legacy(
        self,
        credential: str,
        url: str,
        hash_input: str,
        algorithm: str,
        timeout: int,
        start_time: float,
    ) -> ProviderLookupResult:
        """Call the legacy GET API format (email:code)."""
        email, code = credential, credential
        if ":" in credential:
            parts = credential.split(":", 1)
            email, code = parts[0], parts[1]

        params = {
            "hash": hash_input,
            "hash_type": algorithm.lower(),
            "email": email,
            "code": code,
        }

        resp = requests.get(url, params=params, timeout=timeout)
        duration = round(time.time() - start_time, 4)
        raw_text = resp.text.strip()
        text_upper = raw_text.upper()

        if "ERROR CODE : 001" in text_upper:
            return ProviderLookupResult(
                success=False,
                status="auth_failed",
                found=False,
                error_category="auth_failed",
                error_message="MD5Decrypt legacy authentication failed (code 001).",
                http_status=resp.status_code,
                duration=duration,
            )

        if "ERROR CODE : 002" in text_upper or "ERROR CODE : 003" in text_upper:
            return ProviderLookupResult(
                success=False,
                status="quota_exhausted",
                found=False,
                error_category="quota_exhausted",
                error_message="MD5Decrypt daily quota or rate limit reached.",
                http_status=resp.status_code,
                duration=duration,
            )

        if "ERROR" in text_upper:
            return ProviderLookupResult(
                success=False,
                status="error",
                found=False,
                error_category="provider_error",
                error_message=f"MD5Decrypt returned error: {raw_text}",
                http_status=resp.status_code,
                duration=duration,
            )

        if not raw_text:
            return ProviderLookupResult(
                success=True,
                status="not_found",
                found=False,
                plaintext=None,
                http_status=resp.status_code,
                duration=duration,
            )

        return ProviderLookupResult(
            success=True,
            status="match_found",
            found=True,
            plaintext=raw_text,
            http_status=resp.status_code,
            duration=duration,
        )

    def test_connection(
        self,
        credential: str,
        endpoint: str,
        timeout: int = 10,
        auth_config: dict[str, Any] | None = None,
        provider_config: dict[str, Any] | None = None,
    ) -> tuple[bool, str]:
        """
        Verify provider accessibility with a synthetic MD5 lookup.
        """
        # Test using MD5 of 'hello' (5d41402abc4b2a76b9719d911017c592)
        test_hash = "5d41402abc4b2a76b9719d911017c592"
        res = self.lookup(credential, endpoint, test_hash, "md5", timeout=timeout, auth_config=auth_config)

        if res.status in ("match_found", "not_found"):
            return True, f"Connection verified successfully (Latency: {res.duration}s)."

        if res.status == "quota_exhausted":
            return False, "Provider is reachable, but the account quota is exhausted."

        if res.status == "rate_limited":
            return False, "Provider is reachable, but currently rate-limited (HTTP 429)."

        if res.status == "auth_failed":
            return False, "Connection failed: Invalid API key or unauthorized credential."

        return False, f"Connection test failed: {res.error_message or res.status}"

    def _parse_retry_after(self, resp: requests.Response) -> int | None:
        """Parse Retry-After header as integer seconds if present."""
        retry_val = resp.headers.get("Retry-After")
        if retry_val and retry_val.isdigit():
            return int(retry_val)
        return None
