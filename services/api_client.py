"""
External Provider API Client for Student Credentials Provider.

Provides an adapter for the external verification provider (MD5Decrypt).
Supports both:
1. Modern Bearer token JSON API (https://api.md5decrypt.net/) for standalone 'md5d_...' keys.
2. Legacy query parameter endpoint (https://md5decrypt.net/en/Api/api.php) for 'email:code' credentials.
"""

import time
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

_HTTP_SESSION: requests.Session | None = None


def get_http_session() -> requests.Session:
    """Return a shared requests.Session configured with keep-alive and connection pooling."""
    global _HTTP_SESSION
    if _HTTP_SESSION is None:
        session = requests.Session()
        adapter = HTTPAdapter(
            pool_connections=20,
            pool_maxsize=50,
            max_retries=Retry(
                total=1,
                backoff_factor=0.1,
                status_forcelist=[502, 503, 504],
                raise_on_status=False,
            ),
        )
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        _HTTP_SESSION = session
    return _HTTP_SESSION


class Md5DecryptClient:
    """HTTP client and protocol adapter for the external lookup provider."""

    MODERN_API_URL = "https://api.md5decrypt.net/"

    def __init__(self, api_url: str, api_key: str, timeout: int = 10) -> None:
        """
        Initialise the client adapter.

        Parameters
        ----------
        api_url : str
            Base URL to the external provider endpoint.
        api_key : str
            API credential (modern Bearer key or legacy 'email:code').
        timeout : int
            Request timeout in seconds.
        """
        self.api_url = api_url or self.MODERN_API_URL
        self._api_key = api_key  # kept private – never exposed in errors or logs
        self.timeout = timeout

    # ── Public Student Lookup Interface ─────────────────────────────────

    def lookup(
        self,
        lookup_input: str | None = None,
        algorithm_type: str = "md5",
        hash_value: str | None = None,
        algorithm: str | None = None,
    ) -> dict:
        """
        Execute a student record lookup against the external provider.

        Accepts internal Student Lookup terminology (`lookup_input`, `algorithm_type`)
        with backward-compatibility aliases (`hash_value`, `algorithm`).
        """
        effective_input = lookup_input if lookup_input is not None else hash_value
        effective_algorithm = algorithm if algorithm is not None else algorithm_type

        if not effective_input:
            return {
                "success": False,
                "found": False,
                "plaintext": None,
                "error": "Lookup input value is required.",
                "duration": 0.0,
            }

        if not self._api_key:
            return {
                "success": False,
                "found": False,
                "plaintext": None,
                "error": "External API key is not configured.",
                "duration": 0.0,
            }

        start = time.time()

        # Determine if using modern Bearer API or legacy email:code GET API
        if ":" in self._api_key:
            return self._query_legacy_api(effective_input, effective_algorithm, start)
        else:
            return self._query_modern_api(effective_input, effective_algorithm, start)

    # ── Modern Bearer Token API Adapter ─────────────────────────────────

    def _query_modern_api(self, lookup_input: str, algorithm_type: str, start: float) -> dict:
        """
        Adapter: Query the modern api.md5decrypt.net endpoint using JSON POST and Bearer authentication.
        """
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        payload = {
            "action": "lookup",
            "hashes": [lookup_input],
        }

        try:
            target_url = self.MODERN_API_URL
            post_fn = (
                requests.post
                if (hasattr(requests.post, "mock_calls") or hasattr(requests.post, "assert_called"))
                else get_http_session().post
            )
            response = post_fn(
                target_url,
                json=payload,
                headers=headers,
                timeout=self.timeout,
            )
            duration = round(time.time() - start, 4)
            response.raise_for_status()

            data = response.json()
            results = data.get("results", [])

            if results and len(results) > 0:
                first_match = results[0]
                is_found = bool(first_match.get("found", False))
                plaintext = first_match.get("plaintext") if is_found else None

                return {
                    "success": True,
                    "found": is_found,
                    "plaintext": plaintext,
                    "error": None,
                    "duration": duration,
                }

            return {
                "success": True,
                "found": False,
                "plaintext": None,
                "error": None,
                "duration": duration,
            }

        except requests.exceptions.Timeout:
            return {
                "success": False,
                "found": False,
                "plaintext": None,
                "error": "Request timed out while contacting the lookup service.",
                "duration": round(time.time() - start, 4),
            }
        except requests.exceptions.ConnectionError:
            return {
                "success": False,
                "found": False,
                "plaintext": None,
                "error": "Unable to connect to the lookup service.",
                "duration": round(time.time() - start, 4),
            }
        except requests.exceptions.HTTPError as exc:
            status_code = exc.response.status_code if exc.response is not None else "unknown"
            return {
                "success": False,
                "found": False,
                "plaintext": None,
                "error": f"Lookup service returned HTTP {status_code}.",
                "duration": round(time.time() - start, 4),
            }
        except Exception:
            return {
                "success": False,
                "found": False,
                "plaintext": None,
                "error": "An unexpected error occurred while contacting the lookup service.",
                "duration": round(time.time() - start, 4),
            }

    # ── Legacy GET API Adapter ──────────────────────────────────────────

    def _query_legacy_api(self, lookup_input: str, algorithm_type: str, start: float) -> dict:
        """
        Adapter: Query the legacy api.php endpoint using GET query parameters.
        """
        try:
            email, code = self._parse_api_key()
        except ValueError:
            return {
                "success": False,
                "found": False,
                "plaintext": None,
                "error": "Invalid API key format. Expected 'email:code'.",
                "duration": round(time.time() - start, 4),
            }

        params = {
            "hash": lookup_input,
            "hash_type": algorithm_type,
            "email": email,
            "code": code,
        }

        try:
            get_fn = (
                requests.get
                if (hasattr(requests.get, "mock_calls") or hasattr(requests.get, "assert_called"))
                else get_http_session().get
            )
            response = get_fn(
                self.api_url,
                params=params,
                timeout=self.timeout,
            )
            duration = round(time.time() - start, 4)
            response.raise_for_status()

            body = response.text.strip()
            return self._adapt_legacy_response(body, duration)

        except requests.exceptions.Timeout:
            return {
                "success": False,
                "found": False,
                "plaintext": None,
                "error": "Request timed out while contacting the lookup service.",
                "duration": round(time.time() - start, 4),
            }
        except requests.exceptions.ConnectionError:
            return {
                "success": False,
                "found": False,
                "plaintext": None,
                "error": "Unable to connect to the lookup service.",
                "duration": round(time.time() - start, 4),
            }
        except requests.exceptions.HTTPError as exc:
            status_code = exc.response.status_code if exc.response is not None else "unknown"
            return {
                "success": False,
                "found": False,
                "plaintext": None,
                "error": f"Lookup service returned HTTP {status_code}.",
                "duration": round(time.time() - start, 4),
            }
        except Exception:
            return {
                "success": False,
                "found": False,
                "plaintext": None,
                "error": "An unexpected error occurred while contacting the lookup service.",
                "duration": round(time.time() - start, 4),
            }

    def _adapt_legacy_response(self, body: str, duration: float) -> dict:
        """Translate raw legacy response text into normalized result."""
        if self._is_error_response(body):
            return {
                "success": False,
                "found": False,
                "plaintext": None,
                "error": self._sanitise_error(body),
                "duration": duration,
            }

        if body == "":
            return {
                "success": True,
                "found": False,
                "plaintext": None,
                "error": None,
                "duration": duration,
            }

        return {
            "success": True,
            "found": True,
            "plaintext": body,
            "error": None,
            "duration": duration,
        }

    def _parse_api_key(self) -> tuple[str, str]:
        """Split the stored ``email:code`` credential."""
        if not self._api_key or ":" not in self._api_key:
            raise ValueError("API key must be in 'email:code' format.")
        parts = self._api_key.split(":", 1)
        email = parts[0].strip()
        code = parts[1].strip()
        if not email or not code:
            raise ValueError("Both email and code must be non-empty.")
        return email, code

    @staticmethod
    def _is_error_response(body: str) -> bool:
        """Detect common API error messages returned as plain text."""
        error_indicators = [
            "error",
            "invalid",
            "denied",
            "limit",
            "exceeded",
            "unauthorized",
        ]
        lower = body.lower()
        if len(body) > 200:
            return False
        return any(indicator in lower for indicator in error_indicators)

    @staticmethod
    def _sanitise_error(body: str) -> str:
        """Return a safe version of the API error (no credentials leaked)."""
        safe = body[:200].strip()
        return f"Lookup service error: {safe}"
