# Student Credentials Provider (SCP)
### An Advanced Educational Hash Analysis and Verification Platform

> **"Understand the Hash. Verify the Data. Learn the Security."**

[![Python Version](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/framework-Flask%203.1-success.svg)](https://palletsprojects.com/p/flask/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Security: Educational](https://img.shields.io/badge/Purpose-Academic%20%26%20Forensic%20Education-orange.svg)]()

---

## 1. Project Title
**STUDENT CREDENTIALS PROVIDER (SCP)**  
*An Advanced Educational Hash Analysis, Verification, and Digital Forensics Learning Platform.*

---

## 2. Abstract
The Student Credentials Provider (SCP) is a full-stack educational cybersecurity web application engineered to teach computer science and cybersecurity students the practical mechanics of cryptographic hashes, digest representation, hash lookup databases, and secure external API communication. Unlike popular misconceptions that view hash lookups as mathematical reversal or "cracking," this platform explicitly demonstrates that hash lookups are high-speed database searches against pre-computed digest repositories (rainbow tables and indexed dictionaries). Built using Flask (Python 3.11+), modern Vanilla JavaScript (ES6+), and responsive CSS3, SCP integrates with the MD5Decrypt API while providing an isolated, deterministic demonstration mode for local laboratory training. Strict server-side validation, defensive HTTP headers, client-level rate limiting, and zero credential persistence ensure that the application serves strictly legitimate educational and research purposes.

---

## 3. Introduction
In foundational cybersecurity curricula, students frequently struggle to distinguish between:
1. **Cryptographic Hashing:** One-way mathematical compression functions that produce fixed-length digests.
2. **Encryption:** Two-way reversible transformations requiring a cryptographic key to decrypt ciphertext.
3. **Data Encoding:** Reversible representation conversions (e.g., Base64, Hexadecimal) designed for transmission rather than confidentiality.

When students observe automated tools recovering plaintexts from digests, they often misunderstand the phenomenon as mathematical inversion. The Student Credentials Provider provides an interactive, transparent laboratory environment where each step of the hash lookup lifecycle—input sanitization, format verification, client-server transport, upstream API dispatch, response normalization, and forensic result interpretation—is made completely observable and academically clear.

---

## 4. Problem Statement
Academic institutions require practical laboratory tools to teach cryptographic concepts without exposing students to weaponized exploitation utilities, credential-harvesting scripts, or dangerous password-cracking software. Furthermore, many educational web applications lack production-grade engineering principles: they neglect server-side validation, fail to isolate third-party API keys, omit security headers, and expose raw stack traces upon error.

There is a distinct need for a clean, secure, production-quality demonstration platform that:
- Connects modern frontend interfaces to secure backend architectures.
- Safely interfaces with real-world cryptographic lookup APIs.
- Provides a deterministic fallback mode when external credentials or network connectivity are unavailable.
- Rigorously prevents credential persistence and institutional account scraping.

---

## 5. Objectives
1. **Full-Stack Educational Architecture:** Build a complete, maintainable web application using Flask and Vanilla JavaScript adhering to enterprise-level modular separation.
2. **Clarify Cryptographic Mechanics:** Demonstrate visually and theoretically that hash resolution is a database search operation, not mathematical decryption.
3. **Secure API Integration:** Implement a resilient client for the MD5Decrypt API featuring timeouts, sanitization, rate limiting, and error normalization.
4. **Offline Laboratory Capability:** Provide an offline-ready Demonstration Mode using synthetic test datasets that never make external requests.
5. **Enforce Defensive Engineering:** Apply strict server-side validation, Content Security Policies (CSP), frame protection, and zero credential persistence.

---

## 6. Proposed System
The Student Credentials Provider introduces a multi-tier educational architecture:
- **Presentation Tier:** A responsive, accessible single-page application (SPA) dashboard paired with dedicated educational learning centers, architectural documentation, and project overviews.
- **Application Tier:** A lightweight Flask application providing rate-limiting middleware, request parsing, JSON schema validation, and security header injection.
- **Service Tier:** A modular `HashLookupService` orchestrating input sanitization, algorithm mapping, local demonstration queries, and external API requests.
- **Integration Tier:** An isolated `Md5DecryptClient` managing HTTPS sessions, authentication headers/parameters, timeouts, and exception shielding.

---

## 7. Existing Limitations in Legacy Demonstrations
| Legacy Demonstration Approaches | Student Credentials Provider (SCP) Solution |
| :--- | :--- |
| Often rely on dangerous CLI cracking tools (e.g., John the Ripper, Hashcat) with steep learning curves. | Web-based, intuitive laboratory dashboard designed specifically for academic instruction. |
| Misleadingly label lookup operations as "hash decryption" or "reversal." | Explicitly clarifies database search mechanisms with contextual educational explanations. |
| Hardcode API credentials in client-side code or public source files. | Employs strictly isolated environment variables via `python-dotenv`. |
| Silently fail or crash when external APIs are unreachable or throttled. | Gracefully handles timeouts, rate limits, and server errors with distinct forensic visual states. |
| Persist submitted user hashes and credentials to disks or databases. | Pure in-memory processing with zero storage or disk persistence of submitted strings. |

---

## 8. System Architecture

```text
+-------------------------------------------------------------------------+
|                               USER CLIENT                               |
|          Modern Browser (Chrome, Firefox, Safari, Edge)                 |
+-------------------------------------------------------------------------+
                                    |
                                    | [1] HTTPS POST /api/lookup
                                    |     Content-Type: application/json
                                    v
+-------------------------------------------------------------------------+
|                              FLASK BACKEND                              |
|                                                                         |
|  +---------------------+   +---------------------+   +---------------+  |
|  | In-Memory Rate Limiter|   | Security Headers     |   | Request       |  |
|  | (Sliding Window IP) |   | (CSP, nosniff, DENY) |   | JSON Parser   |  |
|  +---------------------+   +---------------------+   +---------------+  |
+-------------------------------------------------------------------------+
                                    |
                                    | [2] Validated parameters
                                    v
+-------------------------------------------------------------------------+
|                    STUDENT LOOKUP SERVICE (Python)                      |
|                                                                         |
|  - Check Non-empty string & max length (256 chars)                      |
|  - Regex verification (Hex characters [0-9a-fA-F])                      |
|  - Algorithm digest length check (MD5=32, SHA1=40, SHA256=64, etc.)     |
|  - Mode routing check (Config.STUDENT_LOOKUP_MODE)                      |
+-------------------------------------------------------------------------+
                 /                                         \
  [Mode = demo] /                                           \ [Mode = live]
               v                                             v
+-----------------------------+               +---------------------------+
|    SYNTHETIC DEMO DATASET   |               |   MD5DECRYPT API CLIENT   |
|                             |               |                           |
| In-Memory Hash Dictionary   |               | - Target: md5decrypt.net  |
| Deterministic Test Hashes   |               | - HTTPS GET Request       |
| Offline, No Network Calls   |               | - Timeout Shield (10s)    |
+-----------------------------+               | - Sanitized Error Handler |
               \                               +---------------------------+
                \                                            /
                 \                                          /
                  \                                        /
                   +-------------------+------------------+
                                       |
                                       | [3] Normalized Internal Result Dict
                                       v
+-------------------------------------------------------------------------+
|                    NORMALIZED JSON RESPONSE GENERATOR                   |
|                                                                         |
| { "success": true, "found": true, "status": "match_found",              |
|   "hash": "...", "algorithm": "md5", "plaintext": "...",                |
|   "mode": "demo|live", "duration": 0.012, "message": "..." }            |
+-------------------------------------------------------------------------+
                                       |
                                       | [4] HTTP 200 / 400 / 429 JSON
                                       v
+-------------------------------------------------------------------------+
|                       FRONTEND RESULT COMPONENT                         |
|                                                                         |
| - Forensic Status Badge (Found / Not Found / Error / Throttled)         |
| - Operating Mode Pill (LIVE in Cyan vs. DEMO in Violet)                 |
| - Sanitized Monospace Hash Display with 1-Click Clipboard Copy          |
| - Educational Forensic Context Explanation                              |
+-------------------------------------------------------------------------+
```

---

## 9. Software Requirements
- **Operating System:** Windows 10/11, macOS Monterey+, or Linux (Ubuntu 20.04+, Debian 11+, Fedora 36+).
- **Python Engine:** CPython 3.11, 3.12, or 3.13.
- **Python Libraries:**
  - `Flask == 3.1.x`
  - `python-dotenv == 1.1.x`
  - `requests == 2.32.x`
  - `Flask-Cors == 5.0.x`
  - `pytest == 8.3.x` (for automated test suite execution)
- **Web Browser:** Any modern evergreen browser with JavaScript ES6+ enabled.

---

## 10. Hardware Requirements
- **Processor:** 1.0 GHz dual-core x86-64 or ARM processor (e.g., Apple M-series or Intel Core i3+).
- **RAM:** Minimum 512 MB available RAM (1 GB recommended).
- **Disk Storage:** Under 50 MB total space required for codebase and Python dependencies.
- **Network Interface:** Active internet connection required only when operating in Live API Mode; completely optional for Demo Mode.

---

## 11. Technologies Used
| Component | Technology | Rationale |
| :--- | :--- | :--- |
| **Backend Runtime** | Python 3.11+ | Clean, readable syntax suitable for academic walkthroughs and robust standard libraries. |
| **Web Microframework** | Flask 3.1 | Minimalist, unopinionated framework avoiding unnecessary enterprise bloat. |
| **HTTP Client** | Requests 2.32 | Industry standard for secure HTTPS communication, session handling, and configurable timeouts. |
| **Config Management**| python-dotenv | Standard 12-factor configuration pattern isolating credentials from version control. |
| **Frontend Layout** | Semantic HTML5 & CSS3 | Accessible semantic markup, CSS Grid, Flexbox, and CSS Custom Properties without heavy frameworks. |
| **Frontend Scripting**| Vanilla JavaScript (ES6+)| Dependency-free, standard DOM manipulation, Fetch API, and asynchronous state handling. |
| **Testing Engine** | Pytest 8.3 | Elegant, readable test syntax with built-in test fixtures and mock patching. |

---

## 12. Functional Requirements
1. **Hash Lookup Submission:** The user must be able to submit a hash digest and select an algorithm (`md5`, `sha1`, `sha256`, `sha384`, `sha512`, `ntlm`).
2. **Digest Validation:** The application must validate character encoding (hexadecimal) and digest length before dispatching upstream requests.
3. **Dual Operating Modes:**
   - **Demo Mode:** Resolves queries against an internal synthetic dictionary with zero external requests.
   - **Live Mode:** Forwards queries to the external MD5Decrypt API using secure environment credentials.
4. **Forensic State Handling:** The application must render ten distinct operational states (Idle, Validating, Loading, Match Found, No Match, Authentication Error, Rate Limited, Timeout, Service Unavailable, Unexpected Response).
5. **Educational Guidance:** Results must display contextual security notices clarifying that lookup matches do not imply cryptographic reversal or identity verification.
6. **Educational Learning Center:** Dedicated curriculum pages explaining hashing vs. encryption, modern password storage (Argon2id, bcrypt), and ethics.

---

## 13. Non-Functional Requirements
1. **Security & Privacy:** Strictly zero storage, logging, or disk persistence of submitted hashes or returned plaintexts.
2. **Defensive Response:** API keys must never appear in client responses, terminal exceptions, or HTTP headers exposed to users.
3. **Response Time:** Local demo queries must resolve in < 10 milliseconds; external queries must enforce a hard 10-second timeout.
4. **Accessibility (WCAG 2.1 AA):** All interactive elements must include ARIA labels, semantic roles, high-contrast ratios, and screen-reader announcements.
5. **Reduced Motion:** Fully respects user OS preferences for `prefers-reduced-motion`.

---

## 14. Algorithm: Hash Lookup Execution

```text
ALGORITHM: EducationalHashLookupLifecycle
INPUT: hash_string (String), algorithm_choice (String)
OUTPUT: NormalizedResult (JSON Object)

BEGIN
    // Step 1: Configuration Initialization
    Initialize application configuration from environment (.env)
    Verify current operating mode (DEMO or LIVE)

    // Step 2: Client Request Ingestion
    Receive user test hash and algorithm selection via HTTP POST /api/lookup
    Enforce per-client sliding window rate limits

    // Step 3: Server-side Format Validation
    IF hash_string is EMPTY or None THEN
        RETURN HTTP 400 {"success": false, "status": "invalid_input", "error": "Hash is required"}
    END IF

    IF length(hash_string) > 256 THEN
        RETURN HTTP 400 {"success": false, "status": "invalid_input", "error": "Length exceeds maximum"}
    END IF

    Normalize algorithm_choice to lowercase
    IF algorithm_choice is NOT in SUPPORTED_ALGORITHMS THEN
        RETURN HTTP 400 {"success": false, "status": "invalid_input", "error": "Unsupported algorithm"}
    END IF

    IF hash_string does NOT match Regex "^[0-9a-fA-F]+$" THEN
        RETURN HTTP 400 {"success": false, "status": "invalid_input", "error": "Invalid hexadecimal characters"}
    END IF

    expected_len := SUPPORTED_ALGORITHMS[algorithm_choice]
    IF length(hash_string) != expected_len THEN
        RETURN HTTP 400 {"success": false, "status": "invalid_input", "error": "Digest length mismatch"}
    END IF

    // Step 4: Execution Routing
    IF current_mode IS DEMO THEN
        Search in-memory DEMO_DATASET for lowercase(hash_string)
        IF match is found THEN
            RETURN HTTP 200 {
                "success": true,
                "found": true,
                "status": "match_found",
                "plaintext": DEMO_DATASET[hash_string].plaintext,
                "mode": "demo",
                "message": "A matching entry was returned from synthetic dataset."
            }
        ELSE
            RETURN HTTP 200 {
                "success": true,
                "found": false,
                "status": "not_found",
                "plaintext": null,
                "mode": "demo",
                "message": "No matching entry was returned by the lookup service."
            }
        END IF
    ELSE
        // Step 5: Secure External API Integration (Live Mode)
        Read API credentials from secure environment (isolated memory)
        Construct HTTPS GET request to provider endpoint
        Measure elapsed duration timer

        TRY
            Execute HTTPS GET with timeout = REQUEST_TIMEOUT_SECONDS
            IF HTTP Status == 401 OR HTTP Status == 403 THEN
                RETURN HTTP 200 {"success": false, "status": "auth_error", "message": "API Authentication failed"}
            ELSE IF HTTP Status == 429 THEN
                RETURN HTTP 200 {"success": false, "status": "rate_limited", "message": "Provider rate limit reached"}
            ELSE IF HTTP Status >= 500 THEN
                RETURN HTTP 200 {"success": false, "status": "service_unavailable", "message": "Provider unavailable"}
            END IF

            Inspect response payload
            IF payload contains recovered plaintext THEN
                RETURN HTTP 200 {"success": true, "found": true, "status": "match_found", "plaintext": payload}
            ELSE
                RETURN HTTP 200 {"success": true, "found": false, "status": "not_found", "plaintext": null}
            END IF
        CATCH TimeoutException
            RETURN HTTP 200 {"success": false, "status": "timeout", "message": "External API timed out"}
        CATCH ConnectionException
            RETURN HTTP 200 {"success": false, "status": "service_unavailable", "message": "Network connection error"}
        FINALLY
            Purge sensitive variables from execution scope
        END TRY
    END IF
END
```

---

## 15. Pseudocode
```python
def execute_student_lookup(lookup_input: str, algorithm_type: str, client_ip: str) -> tuple[dict, int]:
    # 1. Rate Limiting Check
    if is_rate_limited(client_ip):
        return {"success": False, "status": "rate_limited", "error": "Rate limit exceeded"}, 429
    
    # 2. Input Validation
    is_valid, validation_error = validate_lookup_input(lookup_input, algorithm_type)
    if not is_valid:
        return {"success": False, "status": "invalid_input", "error": validation_error}, 400

    # 3. Clean strings
    clean_input = lookup_input.strip().lower()
    clean_algo = algorithm_type.strip().lower()

    # 4. Mode Branching
    if config.STUDENT_LOOKUP_MODE == "demo":
        record = SYNTHETIC_STUDENT_DATABASE.get(clean_input)
        if record and record["algorithm"] == clean_algo:
            return {
                "success": True,
                "found": True,
                "status": "match_found",
                "lookup_input": clean_input,
                "algorithm": clean_algo,
                "plaintext": record["plaintext"],
                "mode": "demo",
                "message": "A matching student record was returned."
            }, 200
        else:
            return {
                "success": True,
                "found": False,
                "status": "not_found",
                "lookup_input": clean_input,
                "algorithm": clean_algo,
                "plaintext": None,
                "mode": "demo",
                "message": "No matching entry was returned by the lookup service."
            }, 200

    # 5. Live Mode Upstream Dispatch (via provider adapter)
    client = Md5DecryptClient(config.MD5DECRYPT_API_URL, config.MD5DECRYPT_API_KEY, config.STUDENT_LOOKUP_TIMEOUT_SECONDS)
    api_response = client.lookup(lookup_input=clean_input, algorithm_type=clean_algo)
    return api_response, 200
```

---

## 16. API Integration Design
The live integration module connects to `md5decrypt.net`:
- **Endpoint:** `https://md5decrypt.net/en/Api/api.php`
- **HTTP Method:** `GET`
- **Parameters:**
  - `hash`: Hexadecimal digest string.
  - `hash_type`: Algorithm identifier (`md5`, `sha1`, `sha256`, `sha384`, `sha512`, `ntlm`).
  - `email`: Registered account email address.
  - `code`: Secret 16-character alphanumeric API access key.
- **Contract Mapping:**
  - *Match Found:* Response body contains the matched plaintext string.
  - *Not Found:* Response body is empty string or explicit notice.
  - *Authentication Error:* HTTP 401/403 or error text indicating invalid key/email.
  - *Rate Throttling:* HTTP 429 or quota exhaustion notice.
- **Fail-Safe Principle:** The integration client catches all network and connection anomalies and maps them to clean internal statuses (`auth_error`, `rate_limited`, `timeout`, `service_unavailable`) without leaking credentials or internal exception dumps.

---

## 17. Security Considerations
1. **Secret Isolation:** API credentials reside strictly in memory parsed from `.env`. The key is never logged, never returned to the frontend, and explicitly ignored from Git.
2. **Defensive Response Headers:**
   - `Content-Security-Policy: default-src 'self' ...`
   - `X-Frame-Options: DENY` (prevents clickjacking attacks)
   - `X-Content-Type-Options: nosniff` (prevents MIME sniffing)
   - `Referrer-Policy: strict-origin-when-cross-origin`
3. **Strict Server-Side Validation:** Every parameter is strictly verified on the backend. Client-side checks improve UX but are never trusted as a security boundary.
4. **Zero Data Retention:** No databases or persistent logs store submitted hashes. Queries are held in volatile variables and freed by the garbage collector immediately following response transmission.
5. **In-Memory Rate Limiting:** Enforces client request thresholds to prevent automated scraping or denial-of-service in demonstration environments.

---

## 18. Test Plan
The platform is tested using automated `pytest` suites covering three primary domains:

| Test Module | Coverage Domain | Key Assertions Verified |
| :--- | :--- | :--- |
| `tests/test_app.py` | Route availability & HTTP contracts | HTTP 200 on all pages (`/`, `/about`, `/documentation`, `/learn`), HTTP 404 handler, JSON enforcement, HTTP 400 on malformed payloads, security headers verification, zero secret exposure in health check. |
| `tests/test_validation.py` | Input validation & boundary checks | Valid MD5/SHA-1/SHA-256/SHA-512 acceptance, case insensitivity, rejection of empty strings, whitespace, non-hex characters, mismatched lengths, oversized strings (>256 chars). |
| `tests/test_api_client.py` | Upstream API client with mocks | Mocked HTTP 200 found responses, mocked empty not-found responses, connection errors, request timeouts, HTTP 401/403 authorization failures, HTTP 429 rate limits, and secret scrubbing verification. |

---

## 19. Known Limitations
1. **In-Memory Rate Limiter:** The built-in rate limiter is designed for single-process academic demonstration. A clustered production deployment would require Redis or Memcached.
2. **API Quota Constraints:** Free third-party API tiers on MD5Decrypt enforce strict credit and rate quotas.
3. **Single-Hash Queries:** By design, the educational lab accepts one hash per submission to emphasize analysis rather than bulk cracking or credential stuffing.

---

## 20. Future Enhancements
1. **Local Rainbow Table Visualizer:** An interactive graphical view demonstrating how reduction functions and chain links operate in classical rainbow tables.
2. **Digest Entropy Graph:** An educational entropy visualizer showing byte distribution and Avalanche Effect across similar plaintexts.
3. **Bcrypt / Argon2 Work-Factor Demonstrator:** An interactive CPU benchmarking tool demonstrating how modern key-derivation functions slow down offline attacks.

---

## 21. Installation Guide

### Prerequisites
- Python 3.11 or newer installed and available in PATH.
- Git (optional, for cloning).

### Step-by-Step Setup

```bash
# 1. Navigate to the project root directory
cd "student-credentials-provider"

# 2. (Recommended) Create a Python virtual environment
python -m venv .venv

# 3. Activate the virtual environment
# On Windows (PowerShell):
.\.venv\Scripts\Activate.ps1
# On Linux / macOS:
source .venv/bin/activate

# 4. Install dependencies
python -m pip install -r requirements.txt

# 5. Create local environment configuration
cp .env.example .env
```

---

## 22. Execution Guide

### Running in Demonstration Mode (Default)
In Demo Mode, no external API credentials or internet connections are required. The server uses pre-configured synthetic student records.

1. Ensure `STUDENT_LOOKUP_MODE=demo` in your `.env` file.
2. Start the application:
   ```bash
   python app.py
   ```
3. Open your browser at `http://127.0.0.1:5000/`.
4. Test with synthetic student record values:
   - MD5: `5d41402abc4b2a76b9719d911017c592` (plaintext: `hello`)
   - MD5: `098f6bcd4621d373cade4e832627b4f6` (plaintext: `test`)
   - SHA-256: `5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8` (plaintext: `password`)

### Running in Live API Mode
1. Register for an API key at [https://md5decrypt.net/en/Api/](https://md5decrypt.net/en/Api/).
2. Edit `.env`:
   ```ini
   STUDENT_LOOKUP_MODE=live
   MD5DECRYPT_API_KEY=your_registered_email@domain.com:your_api_key_code
   STUDENT_LOOKUP_TIMEOUT_SECONDS=10
   ```
3. Start the application:
   ```bash
   python app.py
   ```
4. The dashboard will display the cyan **LIVE** indicator badge.

### Executing Automated Tests
To run the automated verification suite:
```bash
python -m pytest -v
```

---

## 23. Conclusion
The Student Credentials Provider successfully bridges academic theory and software engineering reality. By combining a cybersecurity dashboard, transparent client-server protocols, resilient API integration, defensive server programming, and clear educational pedagogy, the platform empowers students to understand the mathematical realities of cryptographic hashes and the operational nature of lookup databases.

---
*Developed for Academic Cybersecurity Research and Ethical Education.*
