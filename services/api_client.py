"""
External Provider API Client for Student Credentials Provider.

Provides an adapter for the external verification provider (MD5Decrypt.net).
Maps internal Student Lookup terminology to the external provider's required
protocol format, while isolating external field requirements from the rest
of the application.
"""

import time
import requests


class Md5DecryptClient:
    """HTTP client and protocol adapter for the external lookup provider."""

    def __init__(self, api_url: str, api_key: str, timeout: int = 10) -> None:
        """
        Initialise the client adapter.

        Parameters
        ----------
        api_url : str
            Full URL to the external provider endpoint.
        api_key : str
            Combined credential in ``"email:code"`` format.
        timeout : int
            Request timeout in seconds.
        """
        self.api_url = api_url
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

        Parameters
        ----------
        lookup_input : str
            The credential or digest string to verify.
        algorithm_type : str
            Algorithm identifier (e.g., "md5", "sha256").

        Returns
        -------
        dict
            Normalised Student Lookup result::
                {
                    "success": bool,
                    "found": bool,
                    "plaintext": str | None,
                    "error": str | None,
                    "duration": float,
                }
        """
        # Resolve argument aliases
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

        start = time.time()

        try:
            email, code = self._parse_api_key()
        except ValueError:
            duration = time.time() - start
            return {
                "success": False,
                "found": False,
                "plaintext": None,
                "error": "Invalid API key format. Expected 'email:code'.",
                "duration": round(duration, 4),
            }

        # Adapter: construct external provider request using provider-required field names
        provider_params = self._build_provider_request(
            lookup_input=effective_input,
            algorithm_type=effective_algorithm,
            email=email,
            code=code,
        )

        try:
            response = requests.get(
                self.api_url,
                params=provider_params,
                timeout=self.timeout,
            )
            duration = time.time() - start
            response.raise_for_status()

            body = response.text.strip()
            return self._adapt_provider_response(body, duration)

        except requests.exceptions.Timeout:
            duration = time.time() - start
            return {
                "success": False,
                "found": False,
                "plaintext": None,
                "error": "Request timed out while contacting the lookup service.",
                "duration": round(duration, 4),
            }

        except requests.exceptions.ConnectionError:
            duration = time.time() - start
            return {
                "success": False,
                "found": False,
                "plaintext": None,
                "error": "Unable to connect to the lookup service.",
                "duration": round(duration, 4),
            }

        except requests.exceptions.HTTPError as exc:
            duration = time.time() - start
            status_code = exc.response.status_code if exc.response is not None else "unknown"
            return {
                "success": False,
                "found": False,
                "plaintext": None,
                "error": f"Lookup service returned HTTP {status_code}.",
                "duration": round(duration, 4),
            }

        except requests.exceptions.RequestException:
            duration = time.time() - start
            return {
                "success": False,
                "found": False,
                "plaintext": None,
                "error": "An unexpected error occurred while contacting the lookup service.",
                "duration": round(duration, 4),
            }

        except Exception:
            duration = time.time() - start
            return {
                "success": False,
                "found": False,
                "plaintext": None,
                "error": "An unexpected error occurred while contacting the lookup service.",
                "duration": round(duration, 4),
            }

    # ── Provider Protocol Adapters ──────────────────────────────────────

    def _build_provider_request(
        self,
        lookup_input: str,
        algorithm_type: str,
        email: str,
        code: str,
    ) -> dict:
        """
        Adapter: Map internal Student Lookup parameters to the external provider's
        required HTTP parameter contract.

        CRITICAL: The external provider (MD5Decrypt.net) strictly expects 'hash'
        and 'hash_type' parameters in its GET query string.
        """
        return {
            "hash": lookup_input,
            "hash_type": algorithm_type,
            "email": email,
            "code": code,
        }

    def _adapt_provider_response(self, body: str, duration: float) -> dict:
        """
        Adapter: Translate raw provider response text into normalized Student Lookup result.
        """
        if self._is_error_response(body):
            return {
                "success": False,
                "found": False,
                "plaintext": None,
                "error": self._sanitise_error(body),
                "duration": round(duration, 4),
            }

        if body == "":
            return {
                "success": True,
                "found": False,
                "plaintext": None,
                "error": None,
                "duration": round(duration, 4),
            }

        return {
            "success": True,
            "found": True,
            "plaintext": body,
            "error": None,
            "duration": round(duration, 4),
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
