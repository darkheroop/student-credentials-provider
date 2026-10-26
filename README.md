# Student Credentials Provider (SCP)
### Advanced Educational Hash Analysis & Dynamic Multi-Provider Platform

> **"Understand the Hash. Verify the Data. Learn the Security."**

[![Python Version](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/framework-Flask%203.1-success.svg)](https://palletsprojects.com/p/flask/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests: Pytest](https://img.shields.io/badge/tests-75%20passed-brightgreen.svg)]()

---

## 1. Project Overview

**Student Credentials Provider (SCP)** is a full-stack educational cybersecurity web application and lookup platform designed to demonstrate the real-world mechanics of cryptographic hashes, lookup databases, external API communication, and automated failover architectures.

The platform provides:
1. **Minimal Single-Purpose Lookup Interface**: A restrained, focused public interface for entering and verifying 32-character MD5 hexadecimal hashes without clutter.
2. **Dynamic API Key & Provider Management**: An administrative panel (`/admin`) for adding, editing, enabling, disabling, testing, and managing multiple API keys and upstream providers without editing source code.
3. **Automated API Failover**: Intelligent backend coordinator that rotates through eligible API keys by priority, automatically detects quota exhaustion or HTTP 429 rate limits, temporarily pauses exhausted keys, and fails over to backup keys seamlessly.
4. **Encrypted Storage at Rest**: All stored credentials are encrypted in SQLite using authenticated encryption (HMAC-SHA256 authenticated CTR keystream) with a server-side encryption secret. Full API keys are never exposed in administrative responses, application logs, or browser storage.

---

## 2. Architecture & Request Flow

```
[ User Browser ]
       │
       ▼  (POST /api/student-lookup)
[ Flask Backend ] ─── (VercelPathFixMiddleware / Rate Limiter)
       │
       ▼
[ ApiFailoverCoordinator ]
       │
       ├─► 1. Query Database for Eligible Providers (enabled=1, health_status='active', order by priority ASC)
       │
       ├─► 2. Decrypt Provider Credential via CredentialCrypto (authenticated at rest)
       │
       ├─► 3. Invoke Provider Adapter (e.g. Md5DecryptAdapter)
       │
       ├─► 4. Evaluate Response:
       │        ├── Match Found / Not Found ──► Update Last Success ──► Return to User
       │        ├── Quota Exhausted (402/text) ──► Pause Provider ──► Try Next Eligible Key
       │        ├── Rate Limited (429) ──► Respect Retry-After ──► Try Next Eligible Key
       │        └── Auth / Server Error ──► Flag Unhealthy ──► Try Next Eligible Key
       │
       └─► 5. If All Providers Exhausted ──► Return Graceful Error (Zero Leaks)
```

---

## 3. Installation & Setup Instructions

### Prerequisites
* Python 3.11, 3.12, or 3.13
* Git

### Local Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/darkheroop/student-credentials-provider.git
   cd student-credentials-provider
   ```

2. **Create and activate a virtual environment:**
   ```bash
   # Windows (PowerShell)
   python -m venv venv
   .\venv\Scripts\Activate.ps1

   # Linux / macOS
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install required dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment variables:**
   Copy `.env.example` to `.env`:
   ```bash
   cp .env.example .env
   ```

5. **Run the application:**
   ```bash
   python app.py
   ```
   The application will start on `http://127.0.0.1:5000/`.

---

## 4. Environment Variables Reference

| Variable | Description | Default / Example |
| :--- | :--- | :--- |
| `SECRET_KEY` | Flask session secret key | `dev-secret-change-me` |
| `API_ENCRYPTION_KEY` | Secret key used to encrypt API credentials at rest | `scp-encryption-secret-key-32chars!` |
| `ADMIN_USERNAME` | Administrator username for API Management | `inexpert_trifler` |
| `ADMIN_PASSWORD` | Administrator password for API Management | `om sai 0987654321` |
| `DATABASE_PATH` | Path to the SQLite database file | `scp.db` (or `/tmp/scp.db` on Vercel) |
| `MAX_FAILOVER_ATTEMPTS` | Maximum number of provider attempts per lookup | `5` |
| `DEFAULT_PAUSE_DURATION_MINUTES` | Cooldown period for quota-exhausted keys | `60` |
| `STUDENT_LOOKUP_TIMEOUT_SECONDS` | HTTP timeout per provider call | `10` |
| `MD5DECRYPT_API_KEY` | Initial API key (auto-seeded if DB is empty) | `md5d_live_...` |
| `MD5DECRYPT_API_URL` | Upstream provider URL | `https://api.md5decrypt.net/` |

---

## 5. Database Initialization

The SQLite database initializes automatically upon startup.
* The application runs `init_db()` in `database.py`, creating `api_configurations` and `api_event_history` tables with WAL mode and foreign key constraints enabled.
* **Auto-Seeding**: If the database is empty on first boot, it automatically seeds the initial provider using `MD5DECRYPT_API_KEY` from the environment.

To re-initialize the database manually at any time:
```python
from database import Database
db = Database("scp.db")
db.init_db()
```

---

## 6. Accessing & Using API Management

### Accessing the Admin Panel
1. Click the **Settings gear icon (⚙️)** in the top-right corner of the main lookup page, or navigate directly to:
   ```
   http://127.0.0.1:5000/admin/login
   ```
2. Enter your administrator credentials (default: `inexpert_trifler` / `om sai 0987654321` or your configured `ADMIN_USERNAME` / `ADMIN_PASSWORD`).
3. You will be redirected to the **API Management Dashboard** at `/admin`.

### Adding a New API Key
1. In the **Add API Configuration** card, enter:
   * **Display Name**: Descriptive label (e.g. `MD5Decrypt Primary`, `MD5Decrypt Backup`).
   * **Provider**: Select provider (e.g. `MD5Decrypt`).
   * **Priority**: Integer priority (e.g. `10` for primary, `20` for secondary; lower numbers are tried first).
   * **Endpoint URL**: Provider API endpoint (e.g. `https://api.md5decrypt.net/`).
   * **API Key / Credential**: The provider authentication token.
   * **Notes**: Optional operational notes (e.g. `Account quota: 5,000/day`).
2. Click **Save Configuration**.
3. The credential is immediately encrypted and persisted. The list shows only the masked key (e.g. `********zDqY`).

### Testing an API
Click **Test Connection** on any configured API row. The backend will perform a safe validation check against the provider without consuming unnecessary quota and display the latency and health status.

### Manual Reactivation
If an API key is marked **Quota Exhausted** or **Rate Limited**, an administrator can click the **Reactivate** button at any time to clear the pause status and restore the provider to `Active`.

### Editing an API Key
Click **Edit** on any provider row. You can update its priority, endpoint, name, or notes. If you leave the credential field blank, the existing encrypted credential is automatically preserved.

---

## 7. How Automatic Failover & Quota Detection Works

The `ApiFailoverCoordinator` dynamically chooses and executes providers:

1. **Eligibility Filter**: Selects all enabled configurations whose health status is `active`. If an API has a `paused_until` timestamp that has elapsed, it is automatically transitioned back to `active`.
2. **Priority Ordering**: Sorts eligible providers by `priority ASC, id ASC`.
3. **Response Classification**:
   * **Match Found / Not Found**: Both are considered terminal, valid lookup outcomes. The result is returned immediately to the frontend. The provider is marked successful.
   * **Quota Exhaustion**: Triggered by provider error keywords (`credit`, `quota`, `limit reached`, `out of credit`, legacy code `002`). The key is marked `quota_exhausted`, assigned a `paused_until` window, and the coordinator immediately advances to the next eligible key.
   * **Rate Limiting (HTTP 429)**: The provider's `Retry-After` header is parsed. The key is set to `rate_limited` for that duration, and the coordinator moves to the next key.
   * **Authentication Failure (401/403)**: Marked as `auth_failed` requiring admin attention (not retried repeatedly).
   * **Server Error (5xx) or Timeout**: Given a transient 2-minute cooldown (`unhealthy`) and the request fails over to the next provider.
4. **Bounded Retry**: The coordinator enforces `MAX_FAILOVER_ATTEMPTS` to guarantee deterministic, finite response times.

---

## 8. Adding a New Provider Adapter

The provider architecture is extensible:

1. Create a new adapter class inheriting from `BaseProviderAdapter` in `services/providers/`:
   ```python
   from services.providers.base import BaseProviderAdapter, ProviderLookupResult

   class CustomProviderAdapter(BaseProviderAdapter):
       name = "custom_provider"

       def lookup(self, credential, endpoint, hash_input, algorithm, timeout=10, **kwargs):
           # 1. Format request according to provider specifications
           # 2. Execute HTTP request
           # 3. Classify response and return ProviderLookupResult
           return ProviderLookupResult(
               success=True,
               status="match_found",
               found=True,
               plaintext="recovered_plaintext",
           )

       def test_connection(self, credential, endpoint, timeout=10, **kwargs):
           # Perform non-destructive connection check
           return True, "Provider reachable."
   ```

2. Register your adapter in `services/providers/registry.py`:
   ```python
   from services.providers.registry import register_provider
   register_provider("custom_provider", CustomProviderAdapter)
   ```

3. Add the provider through the API Management frontend!

---

## 9. How Credentials Are Encrypted

Credentials are encrypted before being written to SQLite using an **Encrypt-then-MAC** construction:
* **Keystream**: A 16-byte cryptographically secure random nonce is generated per encryption. Keystream blocks are generated using counter mode with an encryption subkey derived from `API_ENCRYPTION_KEY`.
* **Authentication**: A 32-byte HMAC-SHA256 tag is computed over the nonce and ciphertext using a distinct MAC subkey.
* **Storage Format**: `enc:v1:<base64(16_byte_nonce + 32_byte_tag + ciphertext)>`.
* **Tamper Resistance**: Decryption verifies the MAC tag in constant time using `hmac.compare_digest` before attempting decryption.
* **Masking**: Front-facing APIs only ever return masked strings (e.g. `********1234`). Full credentials are never sent to browsers.

---

## 10. Running the Test Suite

The test suite covers unit validation, cryptography, provider adapters, automatic failover, concurrency, CSRF defense, and SSRF prevention.

```bash
# Run all tests with pytest
python -m pytest tests/ -v
```

Expected output:
```text
============================= 75 passed in 2.86s ==============================
```

---

## 11. Security & Responsible Use

* **Educational Purpose**: SCP is built exclusively for authorized academic demonstration and digital forensics education.
* **Zero Persistence of Sensitive Hashes**: The application does not persist submitted lookup hashes or plaintexts.
* **Administrative Protection**: All `/admin/api/*` endpoints enforce server-side session checks, anti-CSRF token verification, and SSRF hostname filtering.
* **Defensive HTTP Headers**: Responses carry `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `X-XSS-Protection: 1; mode=block`, and strict Content Security Policies.

---

## 12. License
Distributed under the MIT License. See `LICENSE` for details.
