# System Architecture — Student Credentials Provider (SCP)

## 1. High-Level Architecture Overview

The Student Credentials Provider follows a layered architecture pattern that cleanly separates
concerns between the user interface, application logic, service layer, and external integrations.

```
┌─────────────────────────────────────────────────────────────────────┐
│                        CLIENT BROWSER                               │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │  HTML/CSS/JavaScript Frontend (Jinja2-rendered templates)    │   │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────────────────┐ │   │
│  │  │ index.html │  │ about.html │  │ documentation.html     │ │   │
│  │  └────────────┘  └────────────┘  └────────────────────────┘ │   │
│  │  ┌────────────┐  ┌────────────┐                             │   │
│  │  │ learn.html │  │ 404.html   │                             │   │
│  │  └────────────┘  └────────────┘                             │   │
│  │                                                              │   │
│  │  Static Assets:  /static/css/  /static/js/  /static/img/    │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                              │                                      │
│                    AJAX / Fetch API                                  │
│                              │                                      │
└──────────────────────────────┼──────────────────────────────────────┘
                               │  HTTP (JSON)
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     FLASK APPLICATION SERVER                        │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                   Middleware Layer                            │   │
│  │  ┌──────────────────┐  ┌──────────────────┐                  │   │
│  │  │ Security Headers │  │  Rate Limiting   │                  │   │
│  │  │ (after_request)  │  │  (per-endpoint)  │                  │   │
│  │  └──────────────────┘  └──────────────────┘                  │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                    Route Handlers                             │   │
│  │                                                               │   │
│  │  Page Routes:                API Routes:                      │   │
│  │  ┌──────────────────┐       ┌──────────────────────────────┐ │   │
│  │  │ GET /            │       │ GET  /api/health             │ │   │
│  │  │ GET /about       │       │ POST /api/lookup             │ │   │
│  │  │ GET /documentation│      │ POST /api/demo-lookup        │ │   │
│  │  │ GET /learn       │       └──────────────────────────────┘ │   │
│  │  └──────────────────┘                                        │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                              │                                      │
│                              ▼                                      │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                    Service Layer                              │   │
│  │                                                               │   │
│  │  ┌─────────────────────────┐  ┌───────────────────────────┐  │   │
│  │  │   HashLookupService     │  │   Md5DecryptClient        │  │   │
│  │  │                         │  │                           │  │   │
│  │  │  - validate_input()     │  │  - lookup()               │  │   │
│  │  │  - lookup()             │  │  - _build_request_url()   │  │   │
│  │  │  - demo_lookup()        │  │  - _sanitize_error()      │  │   │
│  │  │                         │  │                           │  │   │
│  │  └─────────────────────────┘  └───────────────────────────┘  │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                              │                                      │
│                              ▼                                      │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                  Configuration Layer                          │   │
│  │  ┌──────────────────────────────────────────────────────────┐│   │
│  │  │ config.py — Config class                                 ││   │
│  │  │  - HASH_LOOKUP_MODE (demo | live)                        ││   │
│  │  │  - MD5DECRYPT_API_URL                                    ││   │
│  │  │  - MD5DECRYPT_API_KEY (from environment)                 ││   │
│  │  │  - APP_VERSION                                           ││   │
│  │  │  - SUPPORTED_ALGORITHMS                                  ││   │
│  │  └──────────────────────────────────────────────────────────┘│   │
│  └──────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
                               │
                               │  HTTPS (only in live mode)
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                   EXTERNAL API SERVICE                               │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │  md5decrypt.net REST API                                     │   │
│  │  Endpoint: /en/Api/api.php                                   │   │
│  │  Method: GET with query parameters                           │   │
│  │  Auth: email + code                                          │   │
│  └──────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

## 2. Directory Structure

```
student-credentials-provider/
│
├── app.py                      # Flask application entry point
│                                 Registers routes, middleware, error handlers.
│
├── config.py                   # Centralised configuration
│                                 Reads environment variables, sets defaults,
│                                 defines supported algorithms and hash lengths.
│
├── requirements.txt            # Python package dependencies
│
├── .env.example                # Template for environment variables
│
├── README.md                   # Comprehensive project documentation
│
├── services/                   # Business logic layer
│   ├── __init__.py
│   ├── student_lookup.py       # StudentLookupService — validation + demo/live routing
│   └── api_client.py           # Md5DecryptClient — HTTP adapter for external provider
│
├── templates/                  # Jinja2 HTML templates
│   ├── index.html              # Home page with Student Lookup dashboard
│   ├── about.html              # About / project info page
│   ├── documentation.html      # API & technical documentation
│   └── learn.html              # Educational content on hashing & credentials
│
├── static/                     # Client-side assets
│   ├── css/
│   │   └── style.css           # Application styles
│   └── js/
│       └── app.js              # Frontend logic (Student Lookup, AJAX)
│
├── tests/                      # Automated test suite
│   ├── __init__.py
│   ├── test_app.py             # Route-level integration tests
│   ├── test_validation.py      # Input validation unit tests
│   └── test_api_client.py      # API client unit tests (mocked HTTP)
│
└── docs/                       # Extended documentation
    ├── architecture.md          # This file
    ├── algorithm.md             # Algorithm & pseudocode documentation
    └── testing.md               # Test plan and coverage
```

## 3. Component Responsibilities

### 3.1 Flask Application (`app.py`)

The main application module is responsible for:

- **Application Factory**: Creates and configures the Flask instance.
- **Route Registration**: Defines all GET and POST route handlers.
- **Middleware**: Attaches security headers (`X-Content-Type-Options`, `X-Frame-Options`,
  `X-XSS-Protection`, `Referrer-Policy`) to every response via the `after_request` hook.
- **Error Handling**: Custom 404 handler returns a user-friendly page; JSON error responses
  for API endpoints never leak stack traces or secrets.
- **Service Wiring**: Instantiates the `HashLookupService` and injects it into route closures.

### 3.2 Configuration Module (`config.py`)

All tuneable parameters are consolidated in a single `Config` class:

| Parameter               | Source             | Default                                    |
|--------------------------|--------------------|--------------------------------------------|
| `STUDENT_LOOKUP_MODE`   | `STUDENT_LOOKUP_MODE` env | `demo`                              |
| `MD5DECRYPT_API_URL`    | `MD5DECRYPT_API_URL` env | `https://md5decrypt.net/en/Api/api.php` |
| `MD5DECRYPT_API_KEY`    | `MD5DECRYPT_API_KEY` env | `None`                                 |
| `APP_VERSION`           | hardcoded          | `1.0.0`                                    |
| `SUPPORTED_ALGORITHMS`  | hardcoded          | `{md5, sha1, sha256, sha384, sha512, ntlm}` |
| `REQUEST_TIMEOUT`       | `STUDENT_LOOKUP_TIMEOUT_SECONDS` env | `10` (seconds)              |

### 3.3 Service Layer

#### 3.3.1 `StudentLookupService` (`services/student_lookup.py`)

This is the core domain service. It exposes public methods:

1. **`validate_lookup_input(lookup_input, algorithm_type)`** — Returns `(is_valid: bool, message: str)`.
   Checks for empty input, unsupported algorithms, invalid hex characters, and incorrect
   length for the chosen algorithm.

2. **`student_lookup(lookup_input, algorithm_type)`** — The unified entry point. It validates first, then
   delegates to either `demo_lookup()` or `live_lookup()` depending on the configured mode.

3. **`demo_lookup(hash_value, algorithm)`** — Performs a lookup against a hardcoded
   dictionary of well-known hash-to-plaintext pairs. Returns immediately with no network I/O.
   Always tags the result with `mode: "demo"`.

#### 3.3.2 `Md5DecryptClient` (`services/api_client.py`)

A thin HTTP client wrapper that:

- Constructs the API request URL with query parameters (hash, hash type, email, code).
- Sends the HTTP GET request with a configurable timeout.
- Parses the plain-text response to determine if a plaintext was found.
- Measures request duration and includes it in the result dictionary.
- Catches and sanitises all exceptions so that API keys, email addresses, and internal
  error details are never forwarded to the caller.

### 3.4 Templates Layer

All templates extend `base.html`, which provides:

- HTML5 doctype, viewport meta tag, and charset declaration.
- Shared CSS imports (Bootstrap 5 + custom `style.css`).
- A responsive navigation bar with links to all pages.
- A `{% block content %}` placeholder for page-specific content.
- A shared footer with copyright information.

### 3.5 Static Assets

| Path               | Purpose                                                      |
|---------------------|--------------------------------------------------------------|
| `css/style.css`    | Custom styles: colour scheme, card shadows, form styling     |
| `js/main.js`       | Client-side form validation, AJAX hash lookup, result display|
| `img/`             | Logo, favicons, and any illustrative images                  |

## 4. Data Flow

### 4.1 Demo Lookup Flow

```
  User                   Browser JS              Flask                HashLookupService
   │                        │                       │                        │
   │  Enters hash + algo    │                       │                        │
   │───────────────────────>│                       │                        │
   │                        │  POST /api/demo-lookup│                        │
   │                        │──────────────────────>│                        │
   │                        │                       │  validate_input()      │
   │                        │                       │───────────────────────>│
   │                        │                       │  (valid, msg)          │
   │                        │                       │<───────────────────────│
   │                        │                       │                        │
   │                        │                       │  demo_lookup()         │
   │                        │                       │───────────────────────>│
   │                        │                       │  { found, plaintext }  │
   │                        │                       │<───────────────────────│
   │                        │  JSON response        │                        │
   │                        │<──────────────────────│                        │
   │  Displays result       │                       │                        │
   │<───────────────────────│                       │                        │
```

### 4.2 Live Lookup Flow

```
  User        Browser JS        Flask        HashLookupService    Md5DecryptClient    md5decrypt.net
   │              │                │                │                    │                   │
   │  Submit      │                │                │                    │                   │
   │─────────────>│                │                │                    │                   │
   │              │  POST /api/lookup               │                    │                   │
   │              │───────────────>│                │                    │                   │
   │              │                │ validate_input()                    │                   │
   │              │                │───────────────>│                    │                   │
   │              │                │  (True, "OK")  │                    │                   │
   │              │                │<───────────────│                    │                   │
   │              │                │                │                    │                   │
   │              │                │  lookup()      │                    │                   │
   │              │                │───────────────>│                    │                   │
   │              │                │                │  client.lookup()   │                   │
   │              │                │                │───────────────────>│                   │
   │              │                │                │                    │  GET /Api/api.php │
   │              │                │                │                    │──────────────────>│
   │              │                │                │                    │   plaintext / ""  │
   │              │                │                │                    │<──────────────────│
   │              │                │                │  result dict       │                   │
   │              │                │                │<───────────────────│                   │
   │              │                │  result dict   │                    │                   │
   │              │                │<───────────────│                    │                   │
   │              │  JSON response │                │                    │                   │
   │              │<───────────────│                │                    │                   │
   │  Show result │                │                │                    │                   │
   │<─────────────│                │                │                    │                   │
```

## 5. Security Architecture

### 5.1 Defence in Depth

```
┌────────────────────────────────────────────────────────┐
│  Layer 1: Client-side Validation (JavaScript)          │
│  - Prevents obviously invalid submissions              │
│  - UX feedback only — NEVER trusted server-side        │
├────────────────────────────────────────────────────────┤
│  Layer 2: Server-side Input Validation                 │
│  - HashLookupService.validate_input()                  │
│  - Checks: empty, algorithm, hex chars, length, size   │
├────────────────────────────────────────────────────────┤
│  Layer 3: HTTP Security Headers                        │
│  - X-Content-Type-Options: nosniff                     │
│  - X-Frame-Options: DENY                               │
│  - X-XSS-Protection: 1; mode=block                     │
│  - Referrer-Policy: strict-origin-when-cross-origin    │
├────────────────────────────────────────────────────────┤
│  Layer 4: Error Sanitisation                           │
│  - API keys stripped from error messages                │
│  - Stack traces never sent to client                   │
│  - Generic error messages for unexpected failures      │
├────────────────────────────────────────────────────────┤
│  Layer 5: Configuration Security                       │
│  - API keys read from environment variables only       │
│  - .env excluded from version control (.gitignore)     │
│  - Health endpoint exposes mode + version only          │
└────────────────────────────────────────────────────────┘
```

### 5.2 Credential Management

- API keys are **never** hardcoded in source files.
- The `.env.example` file documents the required variables but contains no real values.
- The `Config` class reads `MD5DECRYPT_API_KEY` from `os.environ`.
- The `Md5DecryptClient._sanitize_error()` method strips any occurrence of the API key
  or email from error messages before they are returned to callers.

## 6. Deployment Options

| Environment | Command                                    | Notes                          |
|-------------|---------------------------------------------|--------------------------------|
| Development | `python app.py`                             | Debug mode, auto-reload        |
| Testing     | `pytest tests/ -v`                          | All mocked, no API key needed  |
| Production  | `gunicorn -w 4 -b 0.0.0.0:5000 app:app`   | Behind reverse proxy (nginx)   |

## 7. Technology Stack Summary

```
┌────────────────────────────────────────────────────┐
│  Frontend        │  HTML5, CSS3, JavaScript (ES6)  │
├──────────────────┼─────────────────────────────────┤
│  CSS Framework   │  Bootstrap 5.3                  │
├──────────────────┼─────────────────────────────────┤
│  Backend         │  Python 3.8+, Flask 3.x         │
├──────────────────┼─────────────────────────────────┤
│  HTTP Client     │  requests 2.x                   │
├──────────────────┼─────────────────────────────────┤
│  Templating      │  Jinja2 (bundled with Flask)    │
├──────────────────┼─────────────────────────────────┤
│  Testing         │  pytest, unittest.mock          │
├──────────────────┼─────────────────────────────────┤
│  External API    │  md5decrypt.net REST API         │
├──────────────────┼─────────────────────────────────┤
│  Config Mgmt     │  python-dotenv, os.environ      │
└──────────────────┴─────────────────────────────────┘
```
