# CLAUDE.md — API Security Scanner

## Project Overview

API Security Scanner — a static-analysis tool for discovering, auditing, and reporting API security vulnerabilities and misconfigurations across REST, GraphQL, gRPC, and API gateway configurations.

- **Language**: Python 3.10+ (no external dependencies — pure stdlib)
- **Scanner file**: `api_security_scanner.py` (single self-contained file)
- **Version**: 1.0.0
- **License**: MIT

## Architecture

1. **Module-level rule dicts** — categorised lists of `{id, category, name, severity, pattern, description, cwe, recommendation, compliance}`.
2. **`Finding` dataclass** — `rule_id, name, category, severity, file_path, line_num, line_content, description, recommendation, cwe, cve, compliance`.
3. **`APISecurityScanner` class** — with `SKIP_DIRS`, `SEVERITY_ORDER`, `SEVERITY_COLOR`, ANSI constants, and API inventory tracking.
4. **Methods**: `scan_path` → `_scan_directory` → `_dispatch_file` → type-specific scanners → `_sast_scan` regex engine.
5. **CLI**: `argparse` with `target`, `--json`, `--html`, `--severity`, `--verbose`, `--version`.
6. **Exit code**: `1` if CRITICAL or HIGH findings, `0` otherwise.

## Rule Categories (100+ rules across 20 categories)

| Category | Prefix | Count |
|----------|--------|-------|
| BOLA (API1) | API1-* | 6 |
| Broken Authentication (API2) | API2-* | 10 |
| Property Level Auth (API3) | API3-* | 5 |
| Resource Consumption (API4) | API4-* | 6 |
| BFLA (API5) | API5-* | 4 |
| Business Flow (API6) | API6-* | 3 |
| SSRF (API7) | API7-* | 4 |
| Misconfiguration (API8) | API8-* | 10 |
| Inventory Management (API9) | API9-* | 4 |
| Unsafe Consumption (API10) | API10-* | 4 |
| Input Validation / Injection | API-INJ-* | 7 |
| Secrets / Credentials | API-SEC-* | 6 |
| Transport / TLS Security | API-TLS-* | 4 |
| Logging & Monitoring | API-LOG-* | 3 |
| GraphQL Security | API-GQL-* | 5 |
| gRPC Security | API-GRPC-* | 4 |
| API Gateway | API-GW-* | 5 |
| Environment Secrets | API-ENV-* | 6 |
| Container Security | API-DOCKER-* | 4 |
| K8s API Security | API-K8S-* | 5 |
| OpenAPI Spec | API-SPEC-* | 5 |
| Protobuf | API-PROTO-* | 2 |

## Compliance Frameworks

- **OWASP API Top 10 (2023)** — API1 through API10
- **PCI-DSS v4.0**
- **GDPR**
- **HIPAA**
- **DORA**

## File Types Scanned

`.py`, `.pyw`, `.js`, `.jsx`, `.ts`, `.tsx`, `.mjs`, `.cjs`, `.go`, `.java`, `.rb`, `.php`, `.proto`, `.graphql`, `.gql`, `.env`, `.yaml`, `.yml`, `.toml`, `.conf`, `Dockerfile`, `nginx.conf`

## Development Guidelines

### Adding New Rules

1. Add the rule dict to the appropriate `*_RULES` list at module level.
2. Follow the ID pattern: `API{N}-{NNN}` (OWASP) or `API-{CATEGORY}-{NNN}`.
3. Every rule must include: `id`, `category`, `severity`, `name`, `pattern` (regex), `description`, `cwe`, `recommendation`, `compliance`.
4. Severity levels: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`.
5. Compliance codes must reference keys in `COMPLIANCE_MAP`.

### Testing

```bash
python api_security_scanner.py tests/samples/ --verbose
python api_security_scanner.py tests/samples/ --json report.json --html report.html
```

### Test Sample Files

- `tests/samples/vulnerable_api.py` — insecure Flask API
- `tests/samples/vulnerable_api.js` — insecure Express.js API
- `tests/samples/vulnerable_openapi.yaml` — insecure OpenAPI spec
- `tests/samples/vulnerable_api.proto` — insecure gRPC protobuf
- `tests/samples/vulnerable_api.graphql` — insecure GraphQL schema
- `tests/samples/.env.api` — exposed API secrets
- `tests/samples/Dockerfile.api` — insecure API container
- `tests/samples/nginx_api.conf` — insecure Nginx API proxy
- `tests/samples/k8s_api_deploy.yaml` — insecure K8s API deployment

## Conventions

- Single-file scanner — all rules, engine, and reports in `api_security_scanner.py`.
- No external dependencies — only Python stdlib.
- HTML reports use dark theme with blue-indigo gradient (`#0ea5e9` → `#6366f1` → `#8b5cf6`).
- Keep rule descriptions actionable — always include a concrete `recommendation`.
- Use British English in descriptions (sanitise, unauthorised, etc.) for consistency.
