# AutoDIT – Budget-Optimized API Vulnerability Detection for Zero-Configuration Developer Workflows

[![Python](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](#license)
[![Security](https://img.shields.io/badge/OWASP-API%20Security%20Top%2010-orange.svg)](https://api-security.owasp.org/editions/2023/en/0x11-t10/)
[![Design](https://img.shields.io/badge/Detection-Deterministic%20%26%20Zero--Config-brightgreen.svg)](#core-principles)

**AutoDIT** is a deterministic, zero-configuration API security auditing engine built for developers and engineering teams. Designed to integrate natively into pre-commit hooks and CI/CD pipelines, AutoDIT verifies API endpoints against real-world vulnerabilities—producing reproducible, evidence-backed security reports without requiring complex enterprise configuration or costly manual penetration tests.

---

## Table of Contents

- [Core Principles](#core-principles)
- [Key Features & Detection Capabilities](#key-features--detection-capabilities)
- [Detection Architecture & Terminology](#detection-architecture--terminology)
- [Quickstart: Running the Working Prototype](#quickstart-running-the-working-prototype)
- [Target Architecture & Modular Roadmap](#target-architecture--modular-roadmap)
- [Algorithmic Threat Prioritization](#algorithmic-threat-prioritization)
- [Safety, Ethics & Security Guardrails](#safety-ethics--security-guardrails)
- [Project Structure](#project-structure)
- [License](#license)

---

## Core Principles

Traditional API scanners frequently suffer from slow crawl cycles, high costs, and alert fatigue caused by false positives. AutoDIT operates under four strict engineering tenets:

1. **100% Deterministic Detection**: Given the same target, schema, and parameters, AutoDIT always outputs the identical findings. No probabilistic crawlers, no non-deterministic fuzzing heuristics, and no LLMs in the detection path.
2. **Zero-Configuration by Default**: Commands run out-of-the-box with sensible defaults (`autodit scan openapi.yaml --target http://localhost:8000`). Configuration files are completely optional.
3. **Evidence-Based Reporting (Zero Alert Fatigue)**: Every reported vulnerability includes concrete proof (sanitized request/response excerpts). If a flaw cannot be proven definitively, it is not reported.
4. **Lightweight & Shift-Left**: Engineered to be fast and lightweight enough to execute on every developer commit and pull request gate.

---

## Key Features & Detection Capabilities

AutoDIT maps detected vulnerabilities directly to the [OWASP API Security Top 10 (2023)](https://api-security.owasp.org/editions/2023/en/0x11-t10/) standard ([GitHub repository](https://github.com/OWASP/API-Security)):

| Check Category | OWASP Mapping | Detection Mechanism |
|---|---|---|
| **Multi-Role State Simulation** | API1:2023 (BOLA) & API2:2023 (Broken Authentication) | Automatically replays endpoints with varying credential states (unauthenticated, low-privilege, cross-tenant) to identify broken access controls and privilege escalation. |
| **Heuristic Data Fingerprinting** | API3:2023 (Broken Object Property Level Authorization / Excessive Data Exposure) | Inspects JSON payloads for sensitive keys, high-entropy tokens, password hashes, PII (SSN, emails), and internal database identifiers leaking beyond declared schemas. |
| **Rate-Limit Probing** | API4:2023 (Unrestricted Resource Consumption) | Sends tightly bounded bursts to detect missing rate limits (`429 Too Many Requests`, `Retry-After`, and `X-RateLimit-*` headers) without causing denial of service. |

---

## Detection Architecture & Terminology

- **Deterministic API Security Auditing Engine**: Evaluates vulnerabilities using exact, predefined rules and structural maps (OpenAPI schemas) to produce repeatable, predictable results.
- **Automated Multi-Role State Simulation**: Programmatically sequences HTTP requests across distinct authentication contexts (e.g., swapping User A's token for User B's token) to detect BOLA/IDOR flaws.
- **Heuristic Data Fingerprinting**: Algorithmic inspection of response payloads for unintended structural data exposure (e.g., cryptographic hashes, database internal keys, PII).
- **Algorithmic Threat Prioritization Matrix**: Evaluates compounded API flaws on an endpoint (e.g., missing authentication combined with unthrottled access and sensitive data exposure elevates severity to **High**).
- **Pre-Commit CI/CD Testing Gate**: Blocks code from being merged if structural API vulnerabilities are introduced, shifting security to the earliest point in development.

---

## Quickstart: Running the Working Prototype

The repository currently includes a working prototype demonstration consisting of an intentionally vulnerable mock service (`testApp.py`) and the core auditing engine (`scanner.py`).

### 1. Prerequisites

- Python 3.11+
- Virtual environment (`venv`)

### 2. Setup

```bash
# Clone the repository
git clone https://github.com/your-org/Autodit.git
cd Autodit

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Run the Vulnerable Mock API

In a dedicated terminal window, start the local vulnerable Flask test server:

```bash
python testApp.py
```
*The server will initialize on `http://127.0.0.1:5050`.*

### 4. Run the Security Scanner

In another terminal window, launch the AutoDIT scanner:

```bash
python scanner.py
```

### Prototype Configuration (`config.json`)

```json
{
  "target_url": "http://127.0.0.1:5050",
  "baseline_token": "mock-jwt-token-12345",
  "test_user_id": 1
}
```

### Sample Output

```text
--- AutoDIT Local Auditing Engine ---

[*] Running State Simulation Broken Authentication (api/v1/admin/dashboard)
     [!] HIGH SEVERITY: Broken Authentication detected. Endpoint accessible without token.

[*] Running Load Simulation: Missing Rate Limiting (api/v1/login)
     [!] HIGH SEVERITY: Missing Rate Limiting. Server accepted 50 rapid requests without 429 status.

[*] Running Heuristic Fingerprinting: Excessive Data Exposure (/api/v1/users/1)
    [!] HIGH SEVERITY: Excessive Data Exposure. Sensitive keys (ssn, hash) found in JSON payload.

--- Scan Complete ---
```

---

## Target Architecture & Modular Roadmap

AutoDIT is evolving from standalone prototype scripts into a fully modular CLI package designed for zero-configuration pre-commit and CI usage:

```
autodit/
  cli.py             # Entrypoint: parses arguments, coordinates scan pipeline
  models.py          # Typed models: Endpoint, Finding, Evidence, Severity
  ingestion/         # Parses OpenAPI 3.x specifications into Endpoint models
  scanner/           # Test execution pipeline
    roles.py         # Multi-role identity/token handling
    fingerprints.py  # Sensitive pattern matching & heuristic detectors
    checks/          # Self-contained check plugins (AUTH-001, DATA-001, RATE-001)
  reporting/         # Threat prioritization matrix, JSON/Markdown/HTML renderers
vuln_api/            # Standalone, isolated vulnerable target for automated regression tests
tests/               # Unit, integration, and hardened zero-finding regression tests
```

### Planned CLI Workflow

```bash
# Standard zero-configuration scan against an OpenAPI specification
autodit scan openapi.yaml --target http://localhost:8000

# Export structured report for CI/CD gates
autodit scan openapi.yaml --target http://localhost:8000 --output report.json --format json

# Fail pipeline on findings above a severity threshold
autodit scan openapi.yaml --target http://localhost:8000 --fail-on medium
```

---

## Algorithmic Threat Prioritization

Rather than assigning static severity ratings, AutoDIT correlates findings per endpoint using a compound risk matrix:

```
+------------------------------------------------------------------------+
|                          Compound Severity Matrix                      |
+------------------------------------------------------------------------+
|  Missing Auth  +  Sensitive Data Exposure  +  No Rate Limit  =>  CRITICAL|
|  Missing Auth  +  Standard Endpoint                          =>  HIGH    |
|  Authenticated +  Sensitive Data Exposure                    =>  MEDIUM  |
|  Authenticated +  No Rate Limit (Non-sensitive)              =>  LOW     |
+------------------------------------------------------------------------+
```

Every finding is output with:
- **Check ID**: Stable identifier (e.g. `AUTH-001`, `DATA-001`, `RATE-001`)
- **Endpoint**: HTTP Method and Path
- **Severity**: Calculated rating based on compounded impact
- **Evidence**: Concrete request/response excerpts with secrets redacted
- **Remediation**: Actionable guidance for developers to fix the flaw immediately

---

## Safety, Ethics & Security Guardrails

AutoDIT is strictly a **vulnerability detection tool**, not an offensive exploitation framework:

- **Localhost Default**: Scans default to `localhost` and private RFC 1918 IP ranges. Scanning external endpoints requires an explicit opt-in flag (`--allow-remote`).
- **Non-Destructive Execution**: AutoDIT prioritizes safe, read-only requests. State-changing methods (`POST`, `PUT`, `DELETE`) require explicit flags and never execute destructive payloads.
- **Bounded Rate Testing**: Rate-limit probing operates under strict burst limits (capped at 50 requests) to prevent inadvertent denial of service (DoS).
- **Automated Secret Redaction**: Tokens, authorization headers, passwords, and detected keys are automatically sanitized prior to rendering reports or writing logs.
- **Vulnerable API Isolation**: The bundled `testApp.py` / `vuln_api` is strictly intended for local regression testing and must never be bound to public interfaces.

---

## Project Structure

```text
Autodit/
├── AGENTS.md            # Agent instructions and architectural specifications
├── README.md            # Project documentation and usage guide
├── config.json          # Prototype scanner configuration
├── lingoBingo.txt       # Domain terminology and security concepts
├── requirements.txt     # Python package dependencies
├── scanner.py           # Prototype security scanner implementation
└── testApp.py           # Intentionally vulnerable test API server
```

---

## License

This project is licensed under the MIT License.
