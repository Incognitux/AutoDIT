# AutoDIT – Architecture & Technical Guide: How It Works

This document provides a comprehensive technical breakdown of **AutoDIT**—its internal architecture, execution pipeline, data contracts, and design rationale—to guide developers in making informed decisions when extending the engine.

---

## 1. High-Level Design & Core Tenets

AutoDIT is a **deterministic, zero-configuration API security auditing engine** built specifically for pre-commit gates and CI/CD pipelines.

```
                   +------------------------+
                   |  OpenAPI 3.x Spec YAML |
                   +-----------+------------+
                               |
                               v
                     +--------------------+
                     |    ingestion/      |  OpenAPI Schema Validation & Parsing
                     |    (parser.py)     |  -> Generates sorted list[Endpoint]
                     +---------+----------+
                               |
                               v
+------------------+ +--------------------+
|  Target Base URL | |     scanner/       |  Deterministic Execution
|  (Localhost/API) | |   (engine.py)      |  - SafeHttpClient (Timeouts, Host checks)
+--------+---------+ +---------+----------+  - BaseCheck Registry:
         |                     |               * AUTH-001 (Multi-role auth)
         +----------+----------+               * DATA-001 (Data fingerprinting)
                    |                          * RATE-001 (Rate-limit probing)
                    v
          +--------------------+
          |    Raw Findings    |  Typed Finding objects with concrete evidence
          +---------+----------+
                    |
                    v
          +--------------------+
          |    reporting/      |  Pure functional compound threat matrix
          |  (prioritizer.py)  |  (Auth missing + Data leak + No rate = CRITICAL)
          +---------+----------+
                    |
                    v
          +--------------------+
          |    renderers.py    |  Structured output:
          |  (Markdown / JSON) |  - Console summary / report.md / report.json
          +--------------------+
```

### Architectural Guarantees
1. **100% Deterministic**: Given identical inputs (spec + target API state), AutoDIT produces the exact same findings every time. There is no randomness, no probabilistic crawling, and no LLM in the detection path.
2. **Zero-Configuration**: `autodit scan openapi.yaml --target http://localhost:5050` works immediately with sensible defaults. No required configuration files.
3. **Concrete Evidence Required**: Every reported `Finding` must contain sanitized HTTP excerpts (request and response). If a vulnerability cannot be proven with concrete evidence, it is not reported.
4. **Safety & Non-Destructive Operation**: Requests default to read-only endpoints on `localhost`/private ranges. External scanning requires `--allow-remote`. Sensitive tokens and passwords are systematically redacted before output.

---

## 2. Directory Layout & Module Responsibilities

The codebase follows a modular Python `src/` layout:

```text
autodit/
├── pyproject.toml              # Build config, dependencies, CLI entrypoint (autodit)
├── HOW_IT_WORKS.md             # This document
├── README.md                   # User-facing overview and quickstart
├── AGENTS.md                   # Strict architectural constraints for AI/devs
├── src/
│   └── autodit/
│       ├── __init__.py         # Package version declaration
│       ├── __main__.py         # python -m autodit entrypoint
│       ├── cli.py              # Click CLI commands and options (strictly zero business logic)
│       ├── models.py           # Typed dataclasses: Endpoint, Finding, Evidence, Severity, ScanConfig
│       ├── ingestion/
│       │   ├── __init__.py
│       │   └── parser.py       # OpenAPI 3.x schema parser & validator
│       ├── scanner/
│       │   ├── __init__.py
│       │   ├── engine.py       # Scan orchestrator
│       │   ├── base_check.py   # BaseCheck ABC & CheckRegistry
│       │   ├── http_client.py  # Safe requests wrapper (timeouts, redaction, host limits)
│       │   ├── roles.py        # Multi-role identities for authorization testing
│       │   ├── fingerprints.py # Pure regex & heuristic secret pattern detectors
│       │   └── checks/         # Independent check plugins
│       │       ├── __init__.py
│       │       ├── auth.py     # AUTH-001 Multi-Role State Simulation
│       │       ├── data.py     # DATA-001 Heuristic Data Fingerprinting
│       │       └── rate.py     # RATE-001 Rate-Limit Probing
│       └── reporting/
│           ├── __init__.py
│           ├── prioritizer.py  # Algorithmic compound threat matrix (pure function)
│           └── renderers.py    # Markdown and JSON report renderers
├── vuln_api/                   # Isolated test target (never packaged into distribution)
│   ├── __init__.py
│   ├── __main__.py             # python -m vuln_api (launches uvicorn on :5050)
│   ├── app.py                  # FastAPI app with vulnerable AND hardened routes
│   └── openapi.yaml            # Spec accurately mapping vuln_api routes
└── tests/                      # Flat test suite (pytest)
    ├── __init__.py
    ├── conftest.py             # Fixtures and test utilities
    ├── test_models.py          # Data contract tests
    ├── test_parser.py          # Spec parsing tests
    ├── test_fingerprints.py    # Positive and negative pattern matches
    ├── test_prioritizer.py     # Table-driven compound severity tests
    ├── test_roles.py           # Identity simulation tests
    ├── test_scan_vulnerable.py # Asserts exact expected findings on vulnerable routes
    └── test_scan_hardened.py   # Asserts ZERO findings on hardened routes
```

---

## 3. Core Data Contracts (`src/autodit/models.py`)

All modules communicate strictly via typed dataclasses—never untyped dictionaries or global state:

| Model | Purpose | Key Attributes |
|---|---|---|
| `Severity` | Enum for threat levels | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `Endpoint` | Attack surface representation extracted from OpenAPI | `method` (`GET`, `POST`), `path`, `summary`, `parameters`, `auth_required`, `response_schemas` |
| `Evidence` | Verifiable proof for a finding | `request_method`, `request_url`, `request_headers`, `response_status`, `response_body_excerpt` |
| `Finding` | An identified, verified security vulnerability | `check_id` (`AUTH-001`), `endpoint`, `severity`, `title`, `description`, `evidence`, `remediation` |
| `ScanConfig` | Runtime settings passed into scanner | `target_url`, `spec_path`, `allow_remote`, `timeout` |

---

## 4. Execution Lifecycle: Step-by-Step

### Phase 1: Ingestion (`src/autodit/ingestion/parser.py`)
1. Ingests an OpenAPI 3.x YAML/JSON specification file.
2. Validates schema correctness using `openapi-spec-validator` (if present) and `PyYAML`.
3. Iterates over `paths` and standard HTTP operations (`GET`, `POST`, `PUT`, `DELETE`, etc.).
4. Checks whether endpoints declare security requirements (e.g. `security` block at route or root level).
5. Produces a `list[Endpoint]` deterministically sorted by `(path, method)`.

### Phase 2: Scanning (`src/autodit/scanner/`)
1. **Orchestrator (`engine.py`)**:
   - Queries `CheckRegistry.get_all()` to retrieve active checks in sorted order.
   - For each sorted `Endpoint`, runs each check plugin.
2. **Safe HTTP Transport (`http_client.py`)**:
   - Validates that the target hostname is local (`localhost`, `127.0.0.1`, `::1`, RFC 1918 private ranges). If an external IP/domain is targeted, it rejects execution unless `--allow-remote` is passed.
   - Enforces explicit timeouts on every request.
   - Sanitizes and redacts tokens and sensitive headers (`Authorization`, `x-api-key`) before embedding them in evidence.
3. **Current Checks (`checks/`)**:
   - **`AUTH-001` (Multi-Role State Simulation)**: Replays endpoints that claim to require authentication without tokens. If the server responds with `200 OK`, it flags broken authentication with response proof.
   - **`DATA-001` (Heuristic Data Fingerprinting)**: Queries endpoints and passes the response payload to `fingerprints.py`. Tests for leaked bcrypt hashes, SSNs, and internal identifiers (`usr_sec_*`).
   - **`RATE-001` (Rate-Limit Probing)**: Sends a strictly bounded burst (capped at 50 requests) to test whether high-frequency hits trigger an HTTP `429 Too Many Requests` response.

### Phase 3: Threat Prioritization (`src/autodit/reporting/prioritizer.py`)
Static severity ratings lead to alert fatigue. AutoDIT correlates findings across each endpoint using an algorithmic compound severity matrix:

```
+------------------------------------------------------------------------+
|                          Compound Severity Matrix                      |
+------------------------------------------------------------------------+
|  Missing Auth  +  Sensitive Data Exposure  +  No Rate Limit  => CRITICAL|
|  Missing Auth  +  Standard Endpoint                          => HIGH    |
|  Authenticated +  Sensitive Data Exposure                    => MEDIUM  |
|  Authenticated +  No Rate Limit (Non-sensitive)              => LOW     |
+------------------------------------------------------------------------+
```

The prioritizer groups findings by endpoint, upgrades individual severity where compounding risks exist, and outputs a deterministically sorted list:
`Severity (CRITICAL -> HIGH -> MEDIUM -> LOW) -> Endpoint -> Check ID`.

### Phase 4: Rendering (`src/autodit/reporting/renderers.py`)
- **JSON Renderer (`render_json`)**: Emits structured JSON suitable for pre-commit hooks, CI pipelines, and SIEM ingestion.
- **Markdown Renderer (`render_markdown`)**: Emits human-readable reports featuring severity tags, endpoint details, sanitized evidence blocks, and actionable developer remediation advice.

---

## 5. Test Target (`vuln_api/`)

The repository includes a deliberately isolated test bench:
- **`vuln_api/app.py`**: A FastAPI service implementing both:
  - **Vulnerable routes**: Demonstrating excessive data exposure, missing rate limits, and broken auth.
  - **Hardened routes** (`/api/v1/hardened/*`): Providing identical functionality with proper authorization and sanitized models.
- **`vuln_api/openapi.yaml`**: The corresponding OpenAPI spec.
- **Regression testing contract**:
  - `tests/test_scan_vulnerable.py` asserts the **exact expected finding set** against vulnerable routes.
  - `tests/test_scan_hardened.py` asserts **zero findings** against hardened routes.

---

## 6. How to Develop & Extend AutoDIT

### Adding a New Check Plugin
To add a new check (e.g. `INPUT-001` for dangerous parameters or `CORS-001` for permissive headers):

1. **Create the check file**: Add `src/autodit/scanner/checks/<name>.py`.
2. **Inherit from `BaseCheck` and use `@CheckRegistry.register`**:
   ```python
   from typing import ClassVar
   from autodit.models import Endpoint, Evidence, Finding, ScanConfig, Severity
   from autodit.scanner.base_check import BaseCheck, CheckRegistry
   from autodit.scanner.http_client import SafeHttpClient

   @CheckRegistry.register
   class CorsCheck(BaseCheck):
       check_id: ClassVar[str] = "CORS-001"
       name: ClassVar[str] = "Permissive CORS Policy"
       description: ClassVar[str] = "Checks for wildcard Access-Control-Allow-Origin headers."
       remediation: ClassVar[str] = "Restrict allowed origins to trusted domains."

       def run(self, endpoint: Endpoint, config: ScanConfig) -> list[Finding]:
           findings: list[Finding] = []
           # Implementation using SafeHttpClient
           return findings
   ```
3. **Register in `src/autodit/scanner/checks/__init__.py`**:
   Import your check class and add it to `__all__`.
4. **Write unit and integration tests**:
   - Add unit tests with positive and negative mocks in `tests/`.
   - Update `prioritizer.py` if the new check influences compound severity calculations.
5. **Run validation commands**:
   ```bash
   ruff check . && ruff format --check .
   pytest
   ```

### Code Organization Rules
- **Split a file** when it crosses ~300 lines.
- **Add a subdirectory** when it holds 4+ related files.
- **Keep detection deterministic**: No random seeds, no probabilistic heuristics, and no LLMs in the detection path.
