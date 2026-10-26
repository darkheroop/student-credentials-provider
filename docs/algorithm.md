# Algorithm & Pseudocode — Student Credentials Provider (SCP)

## 1. Overview

The Student Credentials Provider uses a deterministic lookup algorithm to resolve
cryptographic hash digests back to their plaintext counterparts. The system supports
two operational modes — **demo** and **live** — each implementing the same interface
but differing in their data source.

This document describes the algorithms, validation logic, and pseudocode for every
significant operation in the system.

---

## 2. Supported Hash Algorithms

| Algorithm | Digest Length (hex chars) | Digest Length (bits) | Example Use Case          |
|-----------|--------------------------|----------------------|---------------------------|
| MD5       | 32                       | 128                  | Legacy password storage   |
| SHA-1     | 40                       | 160                  | Git commits, older certs  |
| SHA-256   | 64                       | 256                  | Modern password hashing   |
| SHA-384   | 96                       | 384                  | TLS certificates          |
| SHA-512   | 128                      | 512                  | High-security storage     |

---

## 3. Input Validation Algorithm

### 3.1 Purpose

Before any lookup is attempted, the user-supplied hash value and algorithm identifier
must be validated. This prevents wasted API calls, injection attacks, and confusing error
messages.

### 3.2 Validation Rules

1. The hash value must not be `null`, empty, or consist solely of whitespace.
2. The algorithm must be one of the supported set: `{md5, sha1, sha256, sha384, sha512}`.
3. The hash value must contain only valid hexadecimal characters: `[0-9a-fA-F]`.
4. The hash value length must not exceed 256 characters (guard against abuse).
5. The hash value length must exactly match the expected digest length for the specified algorithm.

### 3.3 Pseudocode

```
FUNCTION validate_input(hash_value, algorithm):
    // Rule 1: Check for empty or null input
    IF hash_value IS NULL OR hash_value.strip() IS EMPTY:
        RETURN (False, "Please provide a non-empty hash value")
    END IF

    // Normalise inputs
    hash_value ← hash_value.strip().lower()
    algorithm  ← algorithm.strip().lower()

    // Rule 2: Check supported algorithm
    supported ← {"md5", "sha1", "sha256", "sha384", "sha512"}
    IF algorithm NOT IN supported:
        RETURN (False, "Unsupported algorithm. Supported: md5, sha1, sha256, sha384, sha512")
    END IF

    // Rule 3: Check hexadecimal characters
    hex_pattern ← regex("[^0-9a-f]")
    IF hex_pattern.match(hash_value):
        RETURN (False, "Hash contains invalid hex characters. Only 0-9 and a-f are allowed")
    END IF

    // Rule 4: Guard against oversized input
    IF length(hash_value) > 256:
        RETURN (False, "Input exceeds maximum allowed length")
    END IF

    // Rule 5: Check expected length for algorithm
    expected_lengths ← {
        "md5":    32,
        "sha1":   40,
        "sha256": 64,
        "sha384": 96,
        "sha512": 128
    }
    expected ← expected_lengths[algorithm]
    IF length(hash_value) ≠ expected:
        RETURN (False, "Invalid length for {algorithm}: expected {expected} characters, got {length(hash_value)}")
    END IF

    // All checks passed
    RETURN (True, "Valid input")
END FUNCTION
```

---

## 4. Hash Lookup Algorithm — Unified Entry Point

### 4.1 Purpose

The main `lookup()` function acts as a router. It validates input first, then delegates
to the appropriate backend based on the configured mode.

### 4.2 Pseudocode

```
FUNCTION lookup(hash_value, algorithm):
    // Step 1: Validate input
    (is_valid, message) ← validate_input(hash_value, algorithm)
    IF NOT is_valid:
        RETURN {
            success:   False,
            status:    "invalid_input",
            error:     message,
            found:     False,
            plaintext: None,
            mode:      current_mode
        }
    END IF

    // Step 2: Normalise
    hash_value ← hash_value.strip().lower()
    algorithm  ← algorithm.strip().lower()

    // Step 3: Route to appropriate backend
    IF current_mode = "demo":
        RETURN demo_lookup(hash_value, algorithm)
    ELSE IF current_mode = "live":
        RETURN live_lookup(hash_value, algorithm)
    ELSE:
        RETURN {
            success: False,
            error:   "Unknown lookup mode configured",
            found:   False,
            plaintext: None,
            mode:    current_mode
        }
    END IF
END FUNCTION
```

---

## 5. Demo Mode Lookup Algorithm

### 5.1 Purpose

Demo mode provides instant, offline hash lookups using a pre-defined dictionary of
well-known hash-to-plaintext mappings. This is used for demonstrations, testing, and
when no API key is available.

### 5.2 Demo Dictionary

The demo dictionary includes common test values:

| Plaintext  | MD5 Hash                            | SHA-256 Hash (first 16 chars)    |
|------------|-------------------------------------|----------------------------------|
| `hello`    | `5d41402abc4b2a76b9719d911017c592` | `2cf24dba5fb0a30e...`            |
| `password` | `5f4dcc3b5aa765d61d8327deb882cf99` | `5e884898da280471...`            |
| `123456`   | `e10adc3949ba59abbe56e057f20f883e` | `8d969eef6ecad3c2...`            |
| `admin`    | `21232f297a57a5a743894a0e4a801fc3` | `8c6976e5b5410415...`            |
| `test`     | `098f6bcd4621d373cade4e832627b4f6` | `9f86d081884c7d65...`            |
| `qwerty`   | `d8578edf8458ce06fbc5bb76a58c5ca4` | `65e84be33532fb78...`            |

### 5.3 Pseudocode

```
FUNCTION demo_lookup(hash_value, algorithm):
    start_time ← current_timestamp()

    // Build the demo dictionary keyed by hash digest
    demo_db ← load_demo_hashes()   // Returns dict: { hash_digest → plaintext }

    // Lookup
    IF hash_value IN demo_db:
        plaintext ← demo_db[hash_value]
        RETURN {
            success:   True,
            found:     True,
            plaintext: plaintext,
            mode:      "demo",
            algorithm: algorithm,
            hash:      hash_value,
            duration:  current_timestamp() - start_time,
            message:   "Found in demo database"
        }
    ELSE:
        RETURN {
            success:   True,
            found:     False,
            plaintext: None,
            mode:      "demo",
            algorithm: algorithm,
            hash:      hash_value,
            duration:  current_timestamp() - start_time,
            message:   "Hash not found in demo database"
        }
    END IF
END FUNCTION
```

---

## 6. Live Mode Lookup Algorithm

### 6.1 Purpose

Live mode sends the hash to the md5decrypt.net external API, which maintains a large
database of precomputed hash-to-plaintext mappings.

### 6.2 API Contract

- **Endpoint**: `https://md5decrypt.net/en/Api/api.php`
- **Method**: `GET`
- **Parameters**:
  - `hash` — the hash digest to look up
  - `hash_type` — the algorithm name (md5, sha1, sha256, sha384, sha512)
  - `email` — registered email address
  - `code` — API authorization code
- **Response**: Plain text. Non-empty string = found plaintext. Empty string = not found.

### 6.3 Pseudocode

```
FUNCTION live_lookup(hash_value, algorithm):
    // Pre-condition: API key must be configured
    IF api_key IS NULL OR api_key IS EMPTY:
        RETURN {
            success: False,
            error:   "API key not configured. Set MD5DECRYPT_API_KEY environment variable.",
            found:   False,
            plaintext: None,
            mode:    "live"
        }
    END IF

    // Parse credentials
    (email, code) ← split(api_key, ":")

    // Build request URL
    url ← API_BASE_URL
    params ← {
        "hash":      hash_value,
        "hash_type": algorithm,
        "email":     email,
        "code":      code
    }

    start_time ← current_timestamp()

    TRY:
        // Send HTTP GET request
        response ← http_get(url, params, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()

        // Parse response
        result_text ← response.text.strip()
        duration ← current_timestamp() - start_time

        IF result_text IS NOT EMPTY AND result_text does not start with "ERROR":
            RETURN {
                success:   True,
                found:     True,
                plaintext: result_text,
                mode:      "live",
                algorithm: algorithm,
                hash:      hash_value,
                duration:  duration,
                message:   "Found via md5decrypt.net API"
            }
        ELSE:
            RETURN {
                success:   True,
                found:     False,
                plaintext: None,
                mode:      "live",
                algorithm: algorithm,
                hash:      hash_value,
                duration:  duration,
                message:   "Hash not found in API database"
            }
        END IF

    CATCH TimeoutError:
        RETURN {
            success: False,
            error:   "Request timed out. The API server did not respond within the time limit.",
            found:   False,
            plaintext: None,
            mode:    "live"
        }

    CATCH ConnectionError:
        RETURN {
            success: False,
            error:   "Could not connect to the API server. Check your internet connection.",
            found:   False,
            plaintext: None,
            mode:    "live"
        }

    CATCH HTTPError AS e:
        status_code ← e.response.status_code
        IF status_code = 401:
            error_msg ← "Authentication failed. Check your API credentials."
        ELSE IF status_code = 429:
            error_msg ← "Rate limit exceeded. Please wait before retrying."
        ELSE:
            error_msg ← "API returned HTTP error {status_code}."
        END IF
        RETURN {
            success: False,
            error:   sanitize_error(error_msg),
            found:   False,
            plaintext: None,
            mode:    "live"
        }

    CATCH Exception AS e:
        RETURN {
            success: False,
            error:   sanitize_error("An unexpected error occurred during lookup."),
            found:   False,
            plaintext: None,
            mode:    "live"
        }
    END TRY
END FUNCTION
```

---

## 7. Error Sanitisation Algorithm

### 7.1 Purpose

Prevent sensitive information (API keys, email addresses, internal paths) from leaking
through error messages returned to the client.

### 7.2 Pseudocode

```
FUNCTION sanitize_error(error_message):
    sanitized ← error_message

    // Remove API key if present
    IF api_key IS NOT NULL:
        sanitized ← sanitized.replace(api_key, "[REDACTED]")
        // Also remove individual components
        (email, code) ← split(api_key, ":")
        sanitized ← sanitized.replace(email, "[REDACTED_EMAIL]")
        sanitized ← sanitized.replace(code, "[REDACTED_CODE]")
    END IF

    // Remove file paths
    sanitized ← regex_replace(sanitized, pattern="[A-Za-z]:\\\\[^\s]+", replacement="[PATH]")
    sanitized ← regex_replace(sanitized, pattern="/[^\s]*site-packages[^\s]*", replacement="[PATH]")

    RETURN sanitized
END FUNCTION
```

---

## 8. Security Headers Algorithm

### 8.1 Pseudocode

```
FUNCTION add_security_headers(response):
    response.headers["X-Content-Type-Options"] ← "nosniff"
    response.headers["X-Frame-Options"]        ← "DENY"
    response.headers["X-XSS-Protection"]       ← "1; mode=block"
    response.headers["Referrer-Policy"]        ← "strict-origin-when-cross-origin"
    response.headers["Cache-Control"]          ← "no-store, no-cache, must-revalidate"
    response.headers["Pragma"]                 ← "no-cache"

    RETURN response
END FUNCTION
```

---

## 9. Request Processing Pipeline

The complete request lifecycle from receipt to response:

```
PROCEDURE handle_request(http_request):

    1. Flask receives HTTP request
    2. Match route against registered URL rules
       - If no match → return 404 error page
       - If method not allowed → return 405 JSON error

    3. Execute route handler:
       a. For page routes (GET /, /about, /documentation, /learn):
          - Render Jinja2 template
          - Return HTML response

       b. For health endpoint (GET /api/health):
          - Return JSON: { status, mode, version, timestamp }

       c. For lookup endpoints (POST /api/lookup, /api/demo-lookup):
          i.   Parse JSON body
               - If malformed → return 400 with error message
          ii.  Extract 'hash' and 'algorithm' fields
               - If missing → return 400 with field-specific error
          iii. Call service.validate_input(hash, algorithm)
               - If invalid → return 400 with validation error
          iv.  Call service.lookup(hash, algorithm) or service.demo_lookup(hash, algorithm)
          v.   Return JSON result

    4. Execute after_request middleware:
       - add_security_headers(response)

    5. Return response to client
END PROCEDURE
```

---

## 10. Complexity Analysis

| Operation          | Time Complexity | Space Complexity | Notes                          |
|---------------------|-----------------|------------------|--------------------------------|
| Input validation   | O(n)            | O(1)             | n = length of hash string      |
| Demo lookup        | O(1)            | O(k)             | k = size of demo dictionary    |
| Live lookup        | O(1) + network  | O(1)             | Dominated by network latency   |
| Error sanitisation | O(m)            | O(m)             | m = length of error message    |
| Security headers   | O(1)            | O(1)             | Fixed number of headers        |

---

## 11. Flowchart Summary

```
                    ┌──────────────┐
                    │  User Input  │
                    │ (hash, algo) │
                    └──────┬───────┘
                           │
                           ▼
                    ┌──────────────┐
                    │   Validate   │
                    │    Input     │
                    └──────┬───────┘
                           │
                    ┌──────┴──────┐
                    │             │
                  Valid        Invalid
                    │             │
                    ▼             ▼
             ┌─────────┐   ┌──────────┐
             │  Check   │   │  Return  │
             │  Mode    │   │  Error   │
             └────┬─────┘   └──────────┘
                  │
           ┌──────┴──────┐
           │             │
         Demo          Live
           │             │
           ▼             ▼
    ┌────────────┐ ┌────────────┐
    │ Dict Lookup│ │ API Call   │
    └─────┬──────┘ └─────┬──────┘
          │              │
          ▼              ▼
    ┌────────────┐ ┌────────────┐
    │   Return   │ │   Return   │
    │   Result   │ │   Result   │
    └────────────┘ └────────────┘
```
