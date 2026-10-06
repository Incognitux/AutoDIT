# AGENTS.md

Guidance for AI coding agents working on **AutoDIT**: a deterministic, zero-configuration API security auditing engine for small dev teams. It ingests OpenAPI specs, runs stateful security checks, and emits a prioritized report. It is designed to run as a pre-commit / CI gate.

> Assumptions marked **(assumed)** were not in the project synopsis. Edit them to match the real repo.

## Project goals (do not drift from these)

1. **Deterministic**: same spec + same target + same config = same findings. No randomness, no LLM calls, no probabilistic crawling in the detection path.
2. **Zero-configuration**: `autodit scan openapi.yaml --target http://localhost:8000` must work with sensible defaults. Config is optional, never required.
3. **Low false positives**: every finding must carry concrete evidence. If we can't prove it, we don't report it (or we downgrade it).
4. **Lightweight**: minimal dependencies, fast enough for a pre-commit hook.

## Architecture

Three modules plus a test target. Keep boundaries clean; modules communicate through typed data structures, not shared state.

| Module | Responsibility |
|---|---|
| `ingestion/` | Parse and validate OpenAPI (3.x) into an internal `Endpoint` model (method, path, params, auth requirements, response schemas). Builds the attack surface map. |
| `scanner/` | Executes state-aware HTTP requests and runs the checks below. Produces raw `Finding` objects with evidence. |
| `reporting/` | Applies the threat prioritization matrix, ranks findings, renders the report (JSON + human-readable, e.g. Markdown/HTML). |
| `vuln_api/` | Deliberately vulnerable dummy API used for tests and demos. **Never** deploy or expose it. |

### Scanner checks

- **Multi-Role State Simulation** (broken authentication / authorization): replay each endpoint under multiple identities (no token, low-privilege token, high-privilege token, another user's token) and compare responses. Flag unauthenticated access, privilege escalation, and BOLA/IDOR-style access.
- **Heuristic Data Fingerprinting** (excessive data exposure): inspect JSON responses for sensitive fields and patterns (password hashes, tokens, API keys, emails, phone numbers, SSN-like and card-like patterns, internal IDs). Compare against what the OpenAPI response schema declares.
- **Rate-limit probing** (unthrottled consumption): send a bounded burst and look for `429`, `Retry-After`, or `X-RateLimit-*` behavior.
- **Threat Prioritization matrix**: combines findings per endpoint (e.g. missing auth + sensitive data exposure + no rate limit compounds to High). Output severities: **High / Medium / Low**.

GraphQL is **foundation-only** for now: scaffolding and interfaces are fine, full checks are out of scope.

## Suggested layout (assumed)

```
autodit/
  cli.py
  ingestion/
  scanner/
    checks/          # one file per check, each implements BaseCheck
    roles.py         # identity/token handling for multi-role simulation
    fingerprints.py  # sensitive-data patterns
  reporting/
    prioritizer.py   # severity matrix
    renderers/
  models.py          # Endpoint, Finding, Evidence, Severity
vuln_api/            # intentionally insecure test target
tests/
docs/
```

## Tech stack and commands (assumed)

- Python 3.11+, HTTP via `requests`, spec parsing via `PyYAML` / an OpenAPI parser, tests via `pytest`.
- Vulnerable test API: FastAPI or Flask.

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

pytest                      # run all tests
pytest tests/scanner -q     # one area
ruff check . && ruff format .   # lint / format (assumed)
python -m vuln_api          # start dummy vulnerable API on localhost
autodit scan openapi.yaml --target http://localhost:8000
```

Run `pytest` and the linter before declaring any task done.

## Coding conventions

- Type hints everywhere; `Finding`, `Endpoint`, `Evidence` are dataclasses/pydantic models, not dicts.
- Each check is a self-contained class with a stable ID (e.g. `AUTH-001`, `DATA-001`, `RATE-001`), a description, and a remediation string.
- Every `Finding` must include: check ID, endpoint (method + path), severity inputs, **evidence** (request/response excerpts with secrets redacted), and **remediation** text.
- Sort all collections (endpoints, findings) deterministically before output.
- Set explicit timeouts on every HTTP call. Never retry silently in a way that changes results.
- Prefer small pure functions for the prioritizer and fingerprinting so they are easy to unit test.
- Keep dependencies minimal; justify any new one in the PR/commit message.

## Testing expectations

- Unit-test fingerprint patterns with positive **and** negative samples (false positives matter as much as misses).
- Unit-test the prioritization matrix with a table of finding combinations to expected severity.
- Integration tests run the scanner against `vuln_api/` and assert the **exact expected set** of findings. The dummy API should also have a hardened variant or route set that must produce **zero** findings.
- Use recorded/mocked responses for tests that don't need a live server.
- Any bug fix needs a regression test.

## Safety and ethics rules (strict)

- Scanning must be **opt-in per target**. Default to `localhost` / private ranges; require an explicit flag (e.g. `--allow-remote`) for anything else. Never add behavior that scans hosts discovered by crawling.
- This is a detection tool, not an exploitation tool. Do not add payloads that modify or destroy data, exfiltrate data, or exploit beyond proving a flaw. Prefer read-only requests; require an explicit flag for state-changing methods (POST/PUT/PATCH/DELETE) and keep them non-destructive.
- Rate-limit probing must use a small, bounded burst with a hard cap. No load-testing or DoS behavior.
- Redact tokens, passwords, and detected secrets in logs and reports. Never commit real credentials; use fixtures with fake data.
- Do not weaken the `vuln_api` isolation: it binds to localhost only.

## Things to avoid

- Don't introduce ML/LLM/probabilistic logic into detection or severity scoring.
- Don't add mandatory config files or setup steps to the default workflow.
- Don't expand into full GraphQL checks, a web dashboard, or a SaaS backend unless asked.
- Don't report a finding without evidence, even if it "probably" exists.
- Don't rename check IDs or change severity semantics without updating tests and docs.

## Definition of done

- Tests pass and lint is clean.
- New/changed checks have evidence + remediation text and tests (positive and negative).
- Output stays deterministic across repeated runs.
- Docs/README updated if CLI flags, check IDs, or severity rules changed.

## Context

Academic mini project (BMSIT&M, CSE, 2026-27), aligned with SDG 9 and SDG 16. Primary references: OWASP API Security Top 10, OpenAPI Specification, RFC 9110. When in doubt about a vulnerability category, map it to the relevant OWASP API Security risk and cite it in the check's description.
