# Testing Documentation — Student Credentials Provider (SCP)

## 1. Test Strategy Overview

The Student Credentials Provider employs a multi-layered testing strategy to ensure
reliability, correctness, and security of all application components. The test suite is
designed so that **no real API key or network connection is required** to run the full
suite — all external dependencies are mocked.

### 1.1 Testing Principles

- **Isolation**: Each test is independent and can be run in any order.
- **Determinism**: No test depends on network availability, time of day, or external state.
- **Security**: Tests verify that secrets are never leaked in responses or error messages.
- **Coverage**: Both happy paths and error paths are tested for every component.

---

## 2. Test Categories

### 2.1 Unit Tests

| Test File               | Module Under Test           | Test Count | Description                            |
|--------------------------|----------------------------|------------|----------------------------------------|
| `test_validation.py`    | `services/hash_lookup.py`  | ~18        | Input validation rules and demo lookup |
| `test_api_client.py`    | `services/api_client.py`   | ~10        | API client with mocked HTTP responses  |

### 2.2 Integration Tests

| Test File               | Module Under Test           | Test Count | Description                            |
|--------------------------|----------------------------|------------|----------------------------------------|
| `test_app.py`           | `app.py` (all routes)       | ~20        | Full route-level tests via Flask test client |

### 2.3 Security Tests

Security assertions are woven into both the unit and integration test suites:

- `TestSecurityHeaders` — Verifies HTTP security headers on every response.
- `test_health_does_not_expose_secrets` — Ensures the health endpoint reveals no secrets.
- `test_no_secrets_in_error` — Ensures error responses contain no stack traces or API keys.
- `test_no_credentials_leaked_in_error` — API client test that injects credentials into
  error messages and verifies they are stripped.

---

## 3. Test Infrastructure

### 3.1 Framework and Tools

| Tool            | Version | Purpose                                          |
|-----------------|---------|--------------------------------------------------|
| pytest          | 7.x+    | Test runner and assertion library                 |
| unittest.mock   | stdlib  | Mocking external dependencies (HTTP calls)       |
| Flask test client | —     | In-process HTTP testing without a running server  |

### 3.2 Fixtures

```python
@pytest.fixture
def client():
    """Flask test client fixture for route-level tests."""
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

@pytest.fixture
def service():
    """HashLookupService fixture in demo mode."""
    config = Config()
    config.HASH_LOOKUP_MODE = 'demo'
    return HashLookupService(config)
```

### 3.3 Mocking Strategy

All tests that would otherwise call external APIs use `unittest.mock.patch` to replace
the `requests.get` function:

```python
@patch('services.api_client.requests.get')
def test_successful_lookup(self, mock_get, client):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = 'hello'
    mock_get.return_value = mock_response
    # ... assertions ...
```

This ensures:
- Tests run offline and instantly.
- No real API quota is consumed.
- Specific error conditions (timeouts, 401, 429, 500) can be simulated.

---

## 4. Running the Tests

### 4.1 Prerequisites

```bash
# Install dependencies (includes pytest)
pip install -r requirements.txt
```

### 4.2 Run All Tests

```bash
# From the project root directory
pytest tests/ -v
```

### 4.3 Run a Specific Test File

```bash
pytest tests/test_app.py -v
pytest tests/test_validation.py -v
pytest tests/test_api_client.py -v
```

### 4.4 Run a Specific Test Class

```bash
pytest tests/test_app.py::TestPageRoutes -v
pytest tests/test_app.py::TestLookupEndpoint -v
pytest tests/test_app.py::TestDemoLookup -v
pytest tests/test_validation.py::TestHashValidation -v
```

### 4.5 Run a Single Test

```bash
pytest tests/test_app.py::TestPageRoutes::test_homepage_returns_200 -v
```

### 4.6 Run with Coverage Report

```bash
pip install pytest-cov
pytest tests/ -v --cov=. --cov-report=term-missing
```

---

## 5. Test Descriptions

### 5.1 `test_app.py` — Route Tests

#### `TestPageRoutes`

| Test Name                          | What It Verifies                                          |
|------------------------------------|-----------------------------------------------------------|
| `test_homepage_returns_200`        | GET / returns 200 and contains "Student Credentials Provider" |
| `test_about_returns_200`           | GET /about returns 200 and contains "About"               |
| `test_documentation_returns_200`   | GET /documentation returns 200                            |
| `test_learn_returns_200`           | GET /learn returns 200                                    |
| `test_health_endpoint`             | GET /api/health returns JSON with status, mode, version   |
| `test_health_does_not_expose_secrets` | Health JSON contains no api_key, secret, or password   |
| `test_404_handler`                 | Non-existent routes return 404                            |

#### `TestLookupEndpoint`

| Test Name                              | What It Verifies                                    |
|----------------------------------------|-----------------------------------------------------|
| `test_lookup_requires_json`            | Non-JSON POST body → 400                            |
| `test_lookup_requires_hash_field`      | Missing "hash" field → 400 with success=false       |
| `test_lookup_requires_algorithm_field` | Missing "algorithm" field → 400                     |
| `test_lookup_rejects_empty_hash`       | Empty hash → 400 with status "invalid_input"        |
| `test_lookup_rejects_unsupported_algorithm` | Invalid algorithm → 400                        |
| `test_lookup_rejects_invalid_hex`      | Non-hex characters → 400                            |
| `test_lookup_rejects_wrong_length`     | Wrong length for algorithm → 400                    |
| `test_lookup_rejects_oversized_input`  | Hash > 256 chars → 400                              |
| `test_lookup_method_not_allowed`       | GET /api/lookup → 405                               |

#### `TestDemoLookup`

| Test Name                          | What It Verifies                                        |
|------------------------------------|---------------------------------------------------------|
| `test_demo_lookup_known_hash`      | Known MD5 hash returns found=true, plaintext="hello"    |
| `test_demo_lookup_unknown_hash`    | Unknown hash returns found=false                        |
| `test_demo_lookup_never_claims_live` | Mode is always "demo", never "live"                   |

#### `TestSecurityHeaders`

| Test Name                          | What It Verifies                                        |
|------------------------------------|---------------------------------------------------------|
| `test_security_headers_on_page`    | X-Content-Type-Options and X-Frame-Options are set      |
| `test_no_secrets_in_error`         | Error responses contain no traceback or api_key         |

### 5.2 `test_validation.py` — Validation Tests

#### `TestHashValidation`

| Test Name                          | What It Verifies                                        |
|------------------------------------|---------------------------------------------------------|
| `test_valid_md5_hash`              | 32-char hex string accepted for md5                     |
| `test_valid_sha1_hash`             | 40-char hex string accepted for sha1                    |
| `test_valid_sha256_hash`           | 64-char hex string accepted for sha256                  |
| `test_valid_uppercase_hash`        | Uppercase hex characters are accepted                   |
| `test_empty_hash_rejected`         | Empty string → invalid, message mentions "empty"        |
| `test_none_hash_rejected`          | None value → invalid                                    |
| `test_whitespace_hash_rejected`    | Whitespace-only string → invalid                        |
| `test_unsupported_algorithm_rejected` | "rot13" algorithm → invalid                          |
| `test_invalid_hex_rejected`        | Non-hex characters → invalid, message mentions "hex"    |
| `test_wrong_length_rejected`       | Wrong length → invalid, message mentions "length"       |
| `test_oversized_input_rejected`    | 300-char input → invalid                                |
| `test_algorithm_case_insensitive`  | "MD5" (uppercase) is accepted                           |
| `test_sha384_length`               | 96-char hex accepted for sha384                         |
| `test_sha512_length`               | 128-char hex accepted for sha512                        |

#### `TestDemoLookup` (in test_validation.py)

| Test Name                          | What It Verifies                                        |
|------------------------------------|---------------------------------------------------------|
| `test_known_md5_found`             | MD5 of "hello" → found=true, plaintext="hello"         |
| `test_known_sha256_found`          | SHA-256 of "password" → found=true                      |
| `test_unknown_hash_not_found`      | Unknown hash → found=false, plaintext=None              |
| `test_demo_mode_label`             | Result always includes mode="demo"                      |

### 5.3 `test_api_client.py` — API Client Tests

#### `TestApiClientSuccess`

| Test Name                          | What It Verifies                                        |
|------------------------------------|---------------------------------------------------------|
| `test_successful_lookup_found`     | 200 + non-empty text → found=true, plaintext set        |
| `test_successful_lookup_not_found` | 200 + empty text → found=false, plaintext=None          |

#### `TestApiClientErrors`

| Test Name                          | What It Verifies                                        |
|------------------------------------|---------------------------------------------------------|
| `test_connection_error`            | ConnectionError → success=false, no credentials leaked  |
| `test_timeout_error`               | Timeout → success=false, error mentions "timeout"       |
| `test_http_401_error`              | 401 Unauthorized → success=false                        |
| `test_http_429_rate_limit`         | 429 Too Many Requests → success=false                   |
| `test_http_500_server_error`       | 500 Internal Error → success=false                      |
| `test_no_credentials_leaked_in_error` | Credentials injected into error are sanitised        |

#### `TestApiClientConfiguration`

| Test Name                          | What It Verifies                                        |
|------------------------------------|---------------------------------------------------------|
| `test_client_creation`             | Client instantiation succeeds                           |
| `test_client_with_no_api_key`      | Null API key → lookup returns success=false             |

---

## 6. Expected Test Results

When all components are implemented correctly, running `pytest tests/ -v` should produce:

```
tests/test_app.py::TestPageRoutes::test_homepage_returns_200 PASSED
tests/test_app.py::TestPageRoutes::test_about_returns_200 PASSED
tests/test_app.py::TestPageRoutes::test_documentation_returns_200 PASSED
tests/test_app.py::TestPageRoutes::test_learn_returns_200 PASSED
tests/test_app.py::TestPageRoutes::test_health_endpoint PASSED
tests/test_app.py::TestPageRoutes::test_health_does_not_expose_secrets PASSED
tests/test_app.py::TestPageRoutes::test_404_handler PASSED
tests/test_app.py::TestLookupEndpoint::test_lookup_requires_json PASSED
tests/test_app.py::TestLookupEndpoint::test_lookup_requires_hash_field PASSED
tests/test_app.py::TestLookupEndpoint::test_lookup_requires_algorithm_field PASSED
tests/test_app.py::TestLookupEndpoint::test_lookup_rejects_empty_hash PASSED
tests/test_app.py::TestLookupEndpoint::test_lookup_rejects_unsupported_algorithm PASSED
tests/test_app.py::TestLookupEndpoint::test_lookup_rejects_invalid_hex PASSED
tests/test_app.py::TestLookupEndpoint::test_lookup_rejects_wrong_length PASSED
tests/test_app.py::TestLookupEndpoint::test_lookup_rejects_oversized_input PASSED
tests/test_app.py::TestLookupEndpoint::test_lookup_method_not_allowed PASSED
tests/test_app.py::TestDemoLookup::test_demo_lookup_known_hash PASSED
tests/test_app.py::TestDemoLookup::test_demo_lookup_unknown_hash PASSED
tests/test_app.py::TestDemoLookup::test_demo_lookup_never_claims_live PASSED
tests/test_app.py::TestSecurityHeaders::test_security_headers_on_page PASSED
tests/test_app.py::TestSecurityHeaders::test_no_secrets_in_error PASSED
tests/test_validation.py::TestHashValidation::test_valid_md5_hash PASSED
tests/test_validation.py::TestHashValidation::test_valid_sha1_hash PASSED
...
tests/test_api_client.py::TestApiClientConfiguration::test_client_with_no_api_key PASSED

========== 48 passed in 1.23s ==========
```

---

## 7. Coverage Targets

| Module                    | Target Coverage | Critical Paths                            |
|---------------------------|-----------------|-------------------------------------------|
| `app.py`                  | ≥ 90%           | All routes, error handlers, middleware     |
| `services/hash_lookup.py` | ≥ 95%          | All validation rules, demo lookup          |
| `services/api_client.py`  | ≥ 90%          | Success path, all error types, sanitisation|
| `config.py`               | ≥ 80%          | Default values, environment variable reads |

### 7.1 Generating a Coverage Report

```bash
pytest tests/ --cov=. --cov-report=html
# Open htmlcov/index.html in a browser to view the detailed report
```

---

## 8. Continuous Integration Considerations

For a CI/CD pipeline (e.g., GitHub Actions), the test job would look like:

```yaml
name: Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install -r requirements.txt
      - run: pytest tests/ -v --tb=short
```

No secrets or environment variables are needed because all external calls are mocked.

---

## 9. Adding New Tests

When adding a new feature, follow this checklist:

1. **Identify the module** — Is this a route, service, or client change?
2. **Add to the appropriate test file** — `test_app.py` for routes, `test_validation.py`
   for validation logic, `test_api_client.py` for HTTP client behaviour.
3. **Write both positive and negative tests** — Test the happy path AND at least one
   failure/edge case.
4. **Mock external dependencies** — Never let a test make a real HTTP request.
5. **Check for security** — If the change touches error handling, verify no secrets leak.
6. **Run the full suite** — `pytest tests/ -v` must pass with zero failures.
