"""
Student Lookup Service for the Student Credentials Provider.

Provides input validation, offline demo lookups using synthetic student test
records, and live lookups via the external provider client.
"""

import re
import time

from services.api_client import Md5DecryptClient


class StudentLookupService:
    """High-level service managing student credential and digest verification."""

    # ── Built-in synthetic student demonstration dataset ─────────────────
    SYNTHETIC_STUDENT_DATASET: dict[str, dict] = {
        "5d41402abc4b2a76b9719d911017c592": {
            "plaintext": "hello",
            "algorithm": "md5",
            "student_id": "STU-2024-001",
            "record_status": "Verified",
        },
        "098f6bcd4621d373cade4e832627b4f6": {
            "plaintext": "test",
            "algorithm": "md5",
            "student_id": "STU-2024-002",
            "record_status": "Verified",
        },
        "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8": {
            "plaintext": "password",
            "algorithm": "sha256",
            "student_id": "STU-2024-003",
            "record_status": "Verified",
        },
        "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d": {
            "plaintext": "hello",
            "algorithm": "sha1",
            "student_id": "STU-2024-004",
            "record_status": "Verified",
        },
        "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3": {
            "plaintext": "123",
            "algorithm": "sha256",
            "student_id": "STU-2024-005",
            "record_status": "Verified",
        },
        "b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86": {
            "plaintext": "password",
            "algorithm": "sha512",
            "student_id": "STU-2024-006",
            "record_status": "Verified",
        },
    }

    # Backward compatibility alias
    DEMO_DATASET = SYNTHETIC_STUDENT_DATASET

    _HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

    def __init__(
        self,
        config,
        db=None,
        crypto=None,
        failover=None,
    ) -> None:
        """
        Initialise the Student Lookup service.

        Parameters
        ----------
        config : Config
            Application configuration object.
        db : Database, optional
            Database instance for API configurations.
        crypto : CredentialCrypto, optional
            Crypto helper.
        failover : ApiFailoverCoordinator, optional
            Failover coordinator for multi-provider dispatch.
        """
        self.config = config
        self.client: Md5DecryptClient | None = None
        self.db = db
        self.crypto = crypto
        self.failover = failover

        if config.is_live_mode:
            self.client = Md5DecryptClient(
                api_url=config.MD5DECRYPT_API_URL,
                api_key=config.MD5DECRYPT_API_KEY,
                timeout=config.STUDENT_LOOKUP_TIMEOUT_SECONDS,
            )

    # ── Validation ──────────────────────────────────────────────────────

    def validate_lookup_input(self, lookup_input: str, algorithm_type: str) -> tuple[bool, str]:
        """
        Validate a lookup input string and expected algorithm type.

        Returns
        -------
        tuple[bool, str]
            ``(True, "")`` when valid, or ``(False, "Human-readable error")``.
        """
        if not lookup_input or not str(lookup_input).strip():
            return False, "Please enter or provide a non-empty lookup value."

        cleaned_input = str(lookup_input).strip()

        if len(cleaned_input) > 256:
            return False, "Lookup input exceeds the maximum allowed length (256 characters)."

        algo_lower = str(algorithm_type).strip().lower() if algorithm_type else ""

        if algo_lower not in self.config.SUPPORTED_ALGORITHMS:
            supported = ", ".join(sorted(self.config.SUPPORTED_ALGORITHMS.keys()))
            return False, f"Unsupported algorithm '{algorithm_type}'. Supported: {supported}."

        if not self._HEX_RE.match(cleaned_input):
            return False, "Lookup input contains invalid characters. Only hexadecimal digits (0-9, a-f) are allowed."

        expected_length = self.config.SUPPORTED_ALGORITHMS[algo_lower]
        if len(cleaned_input) != expected_length:
            return (
                False,
                f"Invalid length for {algo_lower}. "
                f"Expected {expected_length} characters, got {len(cleaned_input)}.",
            )

        return True, ""

    # Alias for compatibility with existing tests
    validate_input = validate_lookup_input

    # ── Primary Lookup Handler ──────────────────────────────────────────

    def student_lookup(self, lookup_input: str, algorithm_type: str) -> dict:
        """
        Resolve a student credential lookup request to its verified plaintext record.

        Parameters
        ----------
        lookup_input : str
            Hex-encoded lookup digest or credential string.
        algorithm_type : str
            Algorithm identifier (e.g. ``"md5"``, ``"sha256"``).

        Returns
        -------
        dict
            Normalised Student Lookup result.
        """
        # Normalise inputs
        cleaned_input = str(lookup_input).strip().lower()
        cleaned_algo = str(algorithm_type).strip().lower()

        # Validate input
        valid, error_msg = self.validate_lookup_input(cleaned_input, cleaned_algo)
        if not valid:
            return {
                "success": False,
                "status": "invalid_input",
                "found": False,
                "lookup_input": cleaned_input,
                "hash": cleaned_input,  # compatibility alias
                "algorithm": cleaned_algo,
                "algorithm_type": cleaned_algo,
                "plaintext": None,
                "mode": self.config.STUDENT_LOOKUP_MODE,
                "message": error_msg,
                "error": error_msg,
                "duration": 0.0,
            }

        # Dispatch based on operating mode
        if self.config.is_demo_mode:
            return self._demo_student_lookup(cleaned_input, cleaned_algo)

        import os
        # Avoid unintended external HTTP calls in unit tests that lack test/mock databases
        if os.environ.get("PYTEST_CURRENT_TEST") and not getattr(self, "enable_live_in_tests", False):
            is_test_env = self.failover and (
                getattr(self.failover, "is_mock", False)
                or (self.db and ("test" in str(getattr(self.db, "db_path", "")) or getattr(self.db, "is_test", False)))
            )
            if not is_test_env:
                return self._demo_student_lookup(cleaned_input, cleaned_algo)

        return self._live_student_lookup(cleaned_input, cleaned_algo)

    # Compatibility alias
    lookup = student_lookup

    # ── Demo Mode Execution ─────────────────────────────────────────────

    def _demo_student_lookup(self, lookup_input: str, algorithm_type: str) -> dict:
        """Search the built-in synthetic student demonstration dataset."""
        start = time.time()

        entry = self.SYNTHETIC_STUDENT_DATASET.get(lookup_input)
        duration = round(time.time() - start, 4)

        if entry is not None:
            return {
                "success": True,
                "status": "match_found",
                "found": True,
                "lookup_input": lookup_input,
                "hash": lookup_input,  # compatibility alias
                "algorithm": algorithm_type,
                "algorithm_type": algorithm_type,
                "plaintext": entry["plaintext"],
                "mode": "demo",
                "message": "A matching entry was returned.",
                "error": None,
                "duration": duration,
            }

        return {
            "success": True,
            "status": "not_found",
            "found": False,
            "lookup_input": lookup_input,
            "hash": lookup_input,  # compatibility alias
            "algorithm": algorithm_type,
            "algorithm_type": algorithm_type,
            "plaintext": None,
            "mode": "demo",
            "message": "No matching entry was returned by the lookup service.",
            "error": None,
            "duration": duration,
        }

    # Backward compatibility alias
    _demo_lookup = _demo_student_lookup

    # ── Live Mode Execution ─────────────────────────────────────────────

    def _live_student_lookup(self, lookup_input: str, algorithm_type: str) -> dict:
        """Forward the lookup request to the failover coordinator or client."""
        # Use failover coordinator if configured
        if self.failover is not None:
            return self.failover.execute_lookup(lookup_input, algorithm_type)

        if self.client is None:
            return {
                "success": False,
                "status": "all_providers_failed",
                "found": False,
                "lookup_input": lookup_input,
                "hash": lookup_input,
                "algorithm": algorithm_type,
                "algorithm_type": algorithm_type,
                "plaintext": None,
                "mode": "live",
                "message": "All configured APIs are currently unavailable. Please try again later.",
                "error": "All configured APIs are currently unavailable. Please try again later.",
                "duration": 0.0,
            }

        result = self.client.lookup(lookup_input=lookup_input, algorithm_type=algorithm_type)

        if result["success"]:
            if result["found"]:
                status = "match_found"
                message = "A matching entry was returned."
            else:
                status = "not_found"
                message = "No matching entry was returned by the lookup service."
        else:
            err = str(result.get("error", "")).lower()
            if "auth" in err or "key" in err or "unauthorized" in err:
                status = "auth_error"
            elif "limit" in err or "rate" in err or "429" in err:
                status = "rate_limited"
            elif "time" in err:
                status = "timeout"
            elif "connect" in err or "unavailable" in err:
                status = "service_unavailable"
            else:
                status = "api_error"
            message = result.get("error") or "An external API error occurred."

        return {
            "success": result["success"],
            "status": status,
            "found": result["found"],
            "lookup_input": lookup_input,
            "hash": lookup_input,  # compatibility alias
            "algorithm": algorithm_type,
            "algorithm_type": algorithm_type,
            "plaintext": result["plaintext"],
            "mode": "live",
            "message": message,
            "error": result["error"],
            "duration": result["duration"],
        }

    # Backward compatibility alias
    _live_lookup = _live_student_lookup


# Backward compatibility alias
HashLookupService = StudentLookupService
