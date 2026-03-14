#!/usr/bin/env python3
"""
API Security Scanner — Discovery, Vulnerability & Misconfiguration Management
Version : 1.0.0
License : MIT
Requires: Python 3.10+ (no external dependencies)

Scans source code, OpenAPI/Swagger specs, API gateway configs, GraphQL schemas,
gRPC protobuf definitions, environment files, Dockerfiles, and K8s manifests for
API security issues mapped to OWASP API Top 10 (2023).
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import re
import sys
import textwrap
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

__version__ = "1.0.0"

# ════════════════════════════════════════════════════════════════════════════════
#  COMPLIANCE MAP
# ════════════════════════════════════════════════════════════════════════════════
COMPLIANCE_MAP: dict[str, str] = {
    "OWASP-API1": "OWASP API Top 10:API1 Broken Object Level Authorization",
    "OWASP-API2": "OWASP API Top 10:API2 Broken Authentication",
    "OWASP-API3": "OWASP API Top 10:API3 Broken Object Property Level Authorization",
    "OWASP-API4": "OWASP API Top 10:API4 Unrestricted Resource Consumption",
    "OWASP-API5": "OWASP API Top 10:API5 Broken Function Level Authorization",
    "OWASP-API6": "OWASP API Top 10:API6 Unrestricted Access to Sensitive Business Flows",
    "OWASP-API7": "OWASP API Top 10:API7 Server-Side Request Forgery",
    "OWASP-API8": "OWASP API Top 10:API8 Security Misconfiguration",
    "OWASP-API9": "OWASP API Top 10:API9 Improper Inventory Management",
    "OWASP-API10": "OWASP API Top 10:API10 Unsafe Consumption of APIs",
    "PCI-DSS": "PCI-DSS v4.0",
    "GDPR": "GDPR",
    "HIPAA": "HIPAA",
    "DORA": "DORA",
}

# ════════════════════════════════════════════════════════════════════════════════
#  FINDING DATACLASS
# ════════════════════════════════════════════════════════════════════════════════
@dataclass
class Finding:
    rule_id: str
    name: str
    category: str
    severity: str
    file_path: str
    line_num: int
    line_content: str
    description: str
    recommendation: str
    cwe: str = ""
    cve: str = ""
    compliance: list[str] = field(default_factory=list)

# ════════════════════════════════════════════════════════════════════════════════
#  RULE DEFINITIONS
# ════════════════════════════════════════════════════════════════════════════════

# ── OWASP API1: Broken Object Level Authorisation (BOLA) ──────────────────────
BOLA_RULES: list[dict] = [
    {"id": "API1-001", "category": "BOLA", "name": "Direct object reference without authorisation check",
     "severity": "CRITICAL", "pattern": r"(?:request\.(?:args|params|query)|req\.(?:params|query))\s*(?:\[|\.get\s*\().*(?:id|_id|Id|ID)\b",
     "description": "API endpoint accesses object by user-supplied ID without authorisation check — classic BOLA.",
     "cwe": "CWE-639", "recommendation": "Validate that the authenticated user owns or has access to the requested object before returning it.",
     "compliance": ["OWASP-API1", "PCI-DSS"]},
    {"id": "API1-002", "category": "BOLA", "name": "Path parameter ID without ownership validation",
     "severity": "HIGH", "pattern": r"@app\.(?:get|put|patch|delete|route)\s*\(\s*['\"].*<(?:int:)?(?:id|user_id|account_id|order_id)",
     "description": "Flask route with path parameter ID — ensure ownership validation is performed.",
     "cwe": "CWE-639", "recommendation": "Add ownership validation middleware or check that current_user owns the resource.",
     "compliance": ["OWASP-API1"]},
    {"id": "API1-003", "category": "BOLA", "name": "Express route with ID param lacking auth middleware",
     "severity": "HIGH", "pattern": r"router\.(?:get|put|patch|delete)\s*\(\s*['\"]/:(?:id|userId|accountId|orderId)",
     "description": "Express route with ID parameter — ensure authorisation middleware is applied.",
     "cwe": "CWE-639", "recommendation": "Add authorisation middleware to verify the caller has access to the resource.",
     "compliance": ["OWASP-API1"]},
    {"id": "API1-004", "category": "BOLA", "name": "Django URL pattern with pk without permission class",
     "severity": "HIGH", "pattern": r"path\s*\(\s*['\"].*<(?:int|str):pk>",
     "description": "Django URL with pk parameter — verify permission_classes are set on the view.",
     "cwe": "CWE-639", "recommendation": "Use IsOwner or custom permission class on the DRF view.",
     "compliance": ["OWASP-API1"]},
    {"id": "API1-005", "category": "BOLA", "name": "Spring @PathVariable without @PreAuthorize",
     "severity": "HIGH", "pattern": r"@(?:Get|Put|Patch|Delete)Mapping.*\{(?:id|userId|accountId)\}",
     "description": "Spring controller uses path variable ID — ensure @PreAuthorize or security check.",
     "cwe": "CWE-639", "recommendation": "Add @PreAuthorize annotation or SecurityContext check.",
     "compliance": ["OWASP-API1"]},
    {"id": "API1-006", "category": "BOLA", "name": "Sequential/predictable ID pattern",
     "severity": "MEDIUM", "pattern": r"(?:auto_increment|SERIAL|IDENTITY|autoIncrement)\b",
     "description": "Sequential IDs make BOLA enumeration trivial.",
     "cwe": "CWE-330", "recommendation": "Use UUIDs or non-sequential identifiers for external-facing resources.",
     "compliance": ["OWASP-API1"]},
]

# ── OWASP API2: Broken Authentication ────────────────────────────────────────
AUTH_RULES: list[dict] = [
    {"id": "API2-001", "category": "Broken Authentication", "name": "API endpoint without authentication decorator",
     "severity": "CRITICAL", "pattern": r"@app\.route\s*\(.*methods\s*=.*(?:POST|PUT|DELETE|PATCH)",
     "description": "Flask route accepting write methods — verify authentication is enforced.",
     "cwe": "CWE-306", "recommendation": "Add @login_required or authentication middleware to all non-public endpoints.",
     "compliance": ["OWASP-API2", "PCI-DSS"]},
    {"id": "API2-002", "category": "Broken Authentication", "name": "JWT secret hardcoded",
     "severity": "CRITICAL", "pattern": r"(?:jwt_secret|JWT_SECRET|jwt\.encode|jwt\.decode)\s*(?:=|,|\().*['\"][A-Za-z0-9+/=]{8,}['\"]",
     "description": "JWT secret is hardcoded in source code.",
     "cwe": "CWE-798", "recommendation": "Store JWT secrets in environment variables or a secrets manager.",
     "compliance": ["OWASP-API2", "PCI-DSS"]},
    {"id": "API2-003", "category": "Broken Authentication", "name": "JWT algorithm none or weak",
     "severity": "CRITICAL", "pattern": r"(?:algorithm|algorithms)\s*(?:=|:)\s*(?:\[?\s*['\"](?:none|HS256)['\"])",
     "description": "JWT using 'none' or weak HS256 algorithm.",
     "cwe": "CWE-327", "recommendation": "Use RS256 or ES256 for JWT signing. Never allow 'none' algorithm.",
     "compliance": ["OWASP-API2"]},
    {"id": "API2-004", "category": "Broken Authentication", "name": "JWT verify disabled",
     "severity": "CRITICAL", "pattern": r"(?:verify|verify_signature|verify_exp)\s*(?:=|:)\s*(?:False|false)",
     "description": "JWT signature or expiry verification is disabled.",
     "cwe": "CWE-345", "recommendation": "Always verify JWT signature and expiration claims.",
     "compliance": ["OWASP-API2"]},
    {"id": "API2-005", "category": "Broken Authentication", "name": "API key in query string",
     "severity": "HIGH", "pattern": r"(?:api[_-]?key|apikey|token|access_token)\s*=\s*(?:request\.(?:args|query|params)|req\.(?:query|params))",
     "description": "API key passed in URL query string — exposed in logs and browser history.",
     "cwe": "CWE-598", "recommendation": "Pass API keys in Authorization header, not in URL query parameters.",
     "compliance": ["OWASP-API2", "PCI-DSS"]},
    {"id": "API2-006", "category": "Broken Authentication", "name": "No password hashing",
     "severity": "CRITICAL", "pattern": r"(?:password|passwd)\s*==\s*(?:request|req)\.",
     "description": "Password compared directly without hashing.",
     "cwe": "CWE-256", "recommendation": "Use bcrypt, argon2, or scrypt for password hashing and comparison.",
     "compliance": ["OWASP-API2", "PCI-DSS"]},
    {"id": "API2-007", "category": "Broken Authentication", "name": "Basic auth over HTTP",
     "severity": "HIGH", "pattern": r"(?:BasicAuth|HTTPBasicAuth|basic_auth|Authorization.*Basic)\b",
     "description": "Basic authentication detected — ensure HTTPS is enforced.",
     "cwe": "CWE-523", "recommendation": "Only use Basic Auth over HTTPS/TLS. Prefer token-based auth.",
     "compliance": ["OWASP-API2"]},
    {"id": "API2-008", "category": "Broken Authentication", "name": "Missing CSRF protection on state-changing endpoint",
     "severity": "HIGH", "pattern": r"(?:csrf_exempt|@csrf_exempt|CSRFProtect.*False|csrf\s*=\s*False)",
     "description": "CSRF protection explicitly disabled on endpoint.",
     "cwe": "CWE-352", "recommendation": "Enable CSRF protection on all state-changing API endpoints.",
     "compliance": ["OWASP-API2"]},
    {"id": "API2-009", "category": "Broken Authentication", "name": "Session fixation risk — no session regeneration",
     "severity": "MEDIUM", "pattern": r"session\[.*(user|login|auth).*\]\s*=",
     "description": "Session data set without regenerating session ID after authentication.",
     "cwe": "CWE-384", "recommendation": "Regenerate session ID after successful authentication.",
     "compliance": ["OWASP-API2"]},
    {"id": "API2-010", "category": "Broken Authentication", "name": "OAuth2 implicit flow",
     "severity": "HIGH", "pattern": r"(?:response_type\s*(?:=|:)\s*['\"]token['\"]|implicit\s*(?:grant|flow))",
     "description": "OAuth2 implicit flow is deprecated and insecure.",
     "cwe": "CWE-287", "recommendation": "Use Authorization Code flow with PKCE instead of implicit flow.",
     "compliance": ["OWASP-API2"]},
]

# ── OWASP API3: Broken Object Property Level Authorisation ───────────────────
PROPERTY_AUTH_RULES: list[dict] = [
    {"id": "API3-001", "category": "Property Level Auth", "name": "Mass assignment — request body to model directly",
     "severity": "CRITICAL", "pattern": r"(?:\*\*request\.(?:json|data|body|form)|\.update\s*\(\s*request\.(?:json|data|body)|Object\.assign\s*\(.*req\.body)",
     "description": "Request body unpacked directly into model — mass assignment vulnerability.",
     "cwe": "CWE-915", "recommendation": "Use explicit field allowlists. Never pass raw request body to model updates.",
     "compliance": ["OWASP-API3"]},
    {"id": "API3-002", "category": "Property Level Auth", "name": "Excessive data exposure — full model serialisation",
     "severity": "HIGH", "pattern": r"(?:\.to_dict\s*\(\s*\)|\.to_json\s*\(\s*\)|serialize\s*\(\s*\)|\.values\s*\(\s*\)|JSON\.stringify\s*\(\s*(?:user|account|order|record))",
     "description": "Full model serialised to response — may expose internal/sensitive fields.",
     "cwe": "CWE-213", "recommendation": "Use response serialisers with explicit field allowlists.",
     "compliance": ["OWASP-API3", "GDPR"]},
    {"id": "API3-003", "category": "Property Level Auth", "name": "Internal fields exposed in API response",
     "severity": "HIGH", "pattern": r"(?:password|secret|token|hash|salt|ssn|credit_card|internal_id|_password|password_hash)\s*(?:=|:)",
     "description": "Sensitive or internal field may be included in API response.",
     "cwe": "CWE-213", "recommendation": "Exclude sensitive fields from API responses using serialiser allowlists.",
     "compliance": ["OWASP-API3", "GDPR", "PCI-DSS"]},
    {"id": "API3-004", "category": "Property Level Auth", "name": "Django model __all__ fields exposed",
     "severity": "HIGH", "pattern": r"fields\s*=\s*['\"]__all__['\"]",
     "description": "Django serialiser exposes all model fields including sensitive ones.",
     "cwe": "CWE-213", "recommendation": "Explicitly list allowed fields instead of using '__all__'.",
     "compliance": ["OWASP-API3"]},
    {"id": "API3-005", "category": "Property Level Auth", "name": "GraphQL type exposes sensitive fields",
     "severity": "HIGH", "pattern": r"type\s+(?:User|Account|Customer|Patient)\s*\{[^}]*(?:password|ssn|secret|token|creditCard)",
     "description": "GraphQL type definition exposes sensitive fields.",
     "cwe": "CWE-213", "recommendation": "Remove sensitive fields from GraphQL types or use field-level authorisation.",
     "compliance": ["OWASP-API3", "GDPR"]},
]

# ── OWASP API4: Unrestricted Resource Consumption ────────────────────────────
RESOURCE_RULES: list[dict] = [
    {"id": "API4-001", "category": "Resource Consumption", "name": "No rate limiting on API endpoint",
     "severity": "HIGH", "pattern": r"@app\.(?:route|get|post|put|delete|patch)\s*\(",
     "description": "API endpoint without rate limiting — vulnerable to abuse and DoS.",
     "cwe": "CWE-770", "recommendation": "Apply rate limiting (e.g. flask-limiter, express-rate-limit, @RateLimiter).",
     "compliance": ["OWASP-API4", "DORA"]},
    {"id": "API4-002", "category": "Resource Consumption", "name": "No pagination on list endpoint",
     "severity": "MEDIUM", "pattern": r"\.(?:find|all|filter|select|query)\s*\(\s*\)\s*$",
     "description": "Query returns all records without pagination — resource exhaustion risk.",
     "cwe": "CWE-770", "recommendation": "Implement pagination with limit/offset or cursor-based pagination.",
     "compliance": ["OWASP-API4"]},
    {"id": "API4-003", "category": "Resource Consumption", "name": "Unbounded file upload size",
     "severity": "HIGH", "pattern": r"(?:MAX_CONTENT_LENGTH|upload_max|maxFileSize|fileSizeLimit)\s*(?:=|:)\s*(?:None|null|0|-1|Infinity)",
     "description": "File upload size limit disabled or set to unlimited.",
     "cwe": "CWE-400", "recommendation": "Set reasonable file upload size limits (e.g. 10MB for documents).",
     "compliance": ["OWASP-API4"]},
    {"id": "API4-004", "category": "Resource Consumption", "name": "No request timeout configured",
     "severity": "MEDIUM", "pattern": r"(?:timeout\s*(?:=|:)\s*(?:None|null|0|-1|Infinity|false)|no.?timeout)",
     "description": "Request timeout disabled — allows slow-loris and resource exhaustion attacks.",
     "cwe": "CWE-400", "recommendation": "Set appropriate request timeouts (e.g. 30 seconds for API calls).",
     "compliance": ["OWASP-API4"]},
    {"id": "API4-005", "category": "Resource Consumption", "name": "Unbounded batch/bulk operation",
     "severity": "HIGH", "pattern": r"(?:batch|bulk|mass|multi)\s*(?:=|:|\()\s*.*(?:request|req)\.",
     "description": "Batch operation with no limit on number of items.",
     "cwe": "CWE-770", "recommendation": "Limit batch operations to a reasonable maximum (e.g. 100 items per request).",
     "compliance": ["OWASP-API4"]},
    {"id": "API4-006", "category": "Resource Consumption", "name": "GraphQL query without depth or complexity limit",
     "severity": "HIGH", "pattern": r"(?:graphql|GraphQL|ApolloServer|makeExecutableSchema|graphene)\s*\(",
     "description": "GraphQL endpoint without depth/complexity limiting — vulnerable to query abuse.",
     "cwe": "CWE-400", "recommendation": "Add query depth limiting and complexity analysis middleware.",
     "compliance": ["OWASP-API4"]},
]

# ── OWASP API5: Broken Function Level Authorisation (BFLA) ──────────────────
BFLA_RULES: list[dict] = [
    {"id": "API5-001", "category": "BFLA", "name": "Admin endpoint without role/permission check",
     "severity": "CRITICAL", "pattern": r"(?:@app\.route|router\.(?:get|post|put|delete))\s*\(\s*['\"].*(?:/admin|/manage|/internal|/config|/settings|/users/create|/roles)",
     "description": "Administrative endpoint — ensure proper role-based access control.",
     "cwe": "CWE-285", "recommendation": "Add role-based authorisation (e.g. @roles_required('admin'), isAdmin middleware).",
     "compliance": ["OWASP-API5", "PCI-DSS"]},
    {"id": "API5-002", "category": "BFLA", "name": "Privilege escalation — user can modify roles",
     "severity": "CRITICAL", "pattern": r"(?:role|permission|is_admin|is_staff|is_superuser)\s*=\s*(?:request|req)\.",
     "description": "User-supplied input controls role/permission assignment.",
     "cwe": "CWE-269", "recommendation": "Never accept role/permission changes from user input. Use server-side authorisation.",
     "compliance": ["OWASP-API5"]},
    {"id": "API5-003", "category": "BFLA", "name": "HTTP method override allowed",
     "severity": "MEDIUM", "pattern": r"(?:X-HTTP-Method-Override|X-Method-Override|_method|methodOverride)",
     "description": "HTTP method override enabled — may bypass method-based access controls.",
     "cwe": "CWE-285", "recommendation": "Disable HTTP method override or restrict to safe methods.",
     "compliance": ["OWASP-API5"]},
    {"id": "API5-004", "category": "BFLA", "name": "Missing permission check on DELETE endpoint",
     "severity": "HIGH", "pattern": r"(?:@app\.delete|router\.delete|@DeleteMapping|app\.delete)\s*\(",
     "description": "DELETE endpoint — ensure proper authorisation before resource deletion.",
     "cwe": "CWE-285", "recommendation": "Add authorisation check verifying the caller has delete permissions.",
     "compliance": ["OWASP-API5"]},
]

# ── OWASP API6: Unrestricted Access to Sensitive Business Flows ──────────────
BUSINESS_FLOW_RULES: list[dict] = [
    {"id": "API6-001", "category": "Business Flow", "name": "No CAPTCHA on authentication endpoint",
     "severity": "MEDIUM", "pattern": r"(?:@app\.route|router\.post)\s*\(\s*['\"].*(?:/login|/signin|/authenticate|/register|/signup)['\"]",
     "description": "Authentication endpoint without CAPTCHA — vulnerable to credential stuffing.",
     "cwe": "CWE-307", "recommendation": "Add CAPTCHA or progressive delays after failed attempts.",
     "compliance": ["OWASP-API6", "DORA"]},
    {"id": "API6-002", "category": "Business Flow", "name": "No anti-automation on payment/checkout flow",
     "severity": "HIGH", "pattern": r"(?:@app\.route|router\.post)\s*\(\s*['\"].*(?:/pay|/checkout|/purchase|/transfer|/withdraw)['\"]",
     "description": "Financial transaction endpoint without anti-automation controls.",
     "cwe": "CWE-799", "recommendation": "Add CAPTCHA, velocity checks, and transaction verification on financial endpoints.",
     "compliance": ["OWASP-API6", "PCI-DSS", "DORA"]},
    {"id": "API6-003", "category": "Business Flow", "name": "Password reset without rate limiting",
     "severity": "HIGH", "pattern": r"(?:@app\.route|router\.post)\s*\(\s*['\"].*(?:/reset.?password|/forgot.?password|/password.?reset)['\"]",
     "description": "Password reset endpoint — ensure rate limiting and token expiry.",
     "cwe": "CWE-640", "recommendation": "Rate-limit password reset requests and use short-lived tokens.",
     "compliance": ["OWASP-API6"]},
]

# ── OWASP API7: Server-Side Request Forgery (SSRF) ──────────────────────────
SSRF_RULES: list[dict] = [
    {"id": "API7-001", "category": "SSRF", "name": "User-controlled URL in server-side request",
     "severity": "CRITICAL", "pattern": r"(?:requests\.(?:get|post|put|delete|head|patch)|urllib\.request\.urlopen|fetch|axios|http\.request)\s*\(\s*(?:request|req)\.",
     "description": "Server makes HTTP request using user-supplied URL — SSRF vulnerability.",
     "cwe": "CWE-918", "recommendation": "Validate and restrict URLs to an allowlist of domains. Block internal IPs (10.x, 172.16-31.x, 192.168.x, 127.x, 169.254.x).",
     "compliance": ["OWASP-API7"]},
    {"id": "API7-002", "category": "SSRF", "name": "URL parameter used for redirect",
     "severity": "HIGH", "pattern": r"(?:redirect|redirect_to|return_url|next|callback_url|forward)\s*=\s*(?:request|req)\.",
     "description": "Open redirect via user-supplied URL — can be chained with SSRF.",
     "cwe": "CWE-601", "recommendation": "Validate redirect URLs against an allowlist. Never redirect to arbitrary user input.",
     "compliance": ["OWASP-API7"]},
    {"id": "API7-003", "category": "SSRF", "name": "Webhook URL from user input",
     "severity": "HIGH", "pattern": r"(?:webhook|callback|hook|notify).*(?:url|endpoint|uri)\s*(?:=|:)\s*(?:request|req|body|data)\.",
     "description": "Webhook URL taken from user input — SSRF via webhook registration.",
     "cwe": "CWE-918", "recommendation": "Validate webhook URLs and restrict to HTTPS with domain allowlist.",
     "compliance": ["OWASP-API7"]},
    {"id": "API7-004", "category": "SSRF", "name": "File download/import from user URL",
     "severity": "HIGH", "pattern": r"(?:download|import|fetch|load|read).*(?:from|url|uri|href|src)\s*(?:=|:)\s*(?:request|req|body)",
     "description": "File download/import using user-provided URL.",
     "cwe": "CWE-918", "recommendation": "Use URL allowlist and validate resolved IP is not internal before fetching.",
     "compliance": ["OWASP-API7"]},
]

# ── OWASP API8: Security Misconfiguration ────────────────────────────────────
MISCONFIG_RULES: list[dict] = [
    {"id": "API8-001", "category": "Misconfiguration", "name": "CORS wildcard origin",
     "severity": "HIGH", "pattern": r"(?:Access-Control-Allow-Origin|cors.*origin|allow_origin|allowedOrigins)\s*(?:=|:)\s*['\"]?\*['\"]?",
     "description": "CORS allows all origins — any website can make API requests.",
     "cwe": "CWE-942", "recommendation": "Restrict CORS origins to specific trusted domains.",
     "compliance": ["OWASP-API8"]},
    {"id": "API8-002", "category": "Misconfiguration", "name": "Debug mode enabled",
     "severity": "HIGH", "pattern": r"(?:DEBUG|debug)\s*(?:=|:)\s*(?:True|true|1|['\"]true['\"])",
     "description": "Debug mode enabled — exposes stack traces, internal paths, and sensitive info.",
     "cwe": "CWE-215", "recommendation": "Disable debug mode in production environments.",
     "compliance": ["OWASP-API8"]},
    {"id": "API8-003", "category": "Misconfiguration", "name": "Verbose error messages exposed",
     "severity": "MEDIUM", "pattern": r"(?:traceback\.format_exc|stackTrace|stack_trace|e\.message|err\.stack|\.printStackTrace)",
     "description": "Stack traces or verbose error details exposed in API responses.",
     "cwe": "CWE-209", "recommendation": "Return generic error messages. Log details server-side only.",
     "compliance": ["OWASP-API8"]},
    {"id": "API8-004", "category": "Misconfiguration", "name": "Missing security headers",
     "severity": "MEDIUM", "pattern": r"(?:X-Content-Type-Options|X-Frame-Options|Strict-Transport-Security|Content-Security-Policy)\s*(?:=|:)\s*(?:None|null|false|['\"]['\"])",
     "description": "Security headers disabled or set to empty value.",
     "cwe": "CWE-693", "recommendation": "Set X-Content-Type-Options: nosniff, X-Frame-Options: DENY, HSTS, and CSP headers.",
     "compliance": ["OWASP-API8"]},
    {"id": "API8-005", "category": "Misconfiguration", "name": "API serves over HTTP (not HTTPS)",
     "severity": "HIGH", "pattern": r"(?:http://(?:0\.0\.0\.0|localhost|\*)|app\.run\s*\(.*ssl_context\s*=\s*None|https?\s*(?:=|:)\s*(?:false|False))",
     "description": "API configured to serve over unencrypted HTTP.",
     "cwe": "CWE-319", "recommendation": "Enforce HTTPS/TLS for all API endpoints.",
     "compliance": ["OWASP-API8", "PCI-DSS"]},
    {"id": "API8-006", "category": "Misconfiguration", "name": "Server version/technology exposed",
     "severity": "LOW", "pattern": r"(?:X-Powered-By|Server)\s*(?:=|:)\s*['\"](?:Express|Flask|Django|Kestrel|Apache|nginx)",
     "description": "Server technology disclosed in response headers.",
     "cwe": "CWE-200", "recommendation": "Remove or obfuscate X-Powered-By and Server headers.",
     "compliance": ["OWASP-API8"]},
    {"id": "API8-007", "category": "Misconfiguration", "name": "Bind to 0.0.0.0",
     "severity": "MEDIUM", "pattern": r"(?:host|bind|listen)\s*(?:=|:)\s*['\"]0\.0\.0\.0['\"]",
     "description": "API binds to all network interfaces including public.",
     "cwe": "CWE-668", "recommendation": "Bind to 127.0.0.1 or use a reverse proxy for external access.",
     "compliance": ["OWASP-API8"]},
    {"id": "API8-008", "category": "Misconfiguration", "name": "TLS certificate verification disabled",
     "severity": "CRITICAL", "pattern": r"(?:verify\s*=\s*False|rejectUnauthorized\s*(?:=|:)\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0|InsecureSkipVerify\s*(?:=|:)\s*true|CURLOPT_SSL_VERIFYPEER\s*(?:=|,)\s*(?:false|0))",
     "description": "TLS certificate verification disabled — vulnerable to MITM attacks.",
     "cwe": "CWE-295", "recommendation": "Always verify TLS certificates in production.",
     "compliance": ["OWASP-API8", "PCI-DSS"]},
    {"id": "API8-009", "category": "Misconfiguration", "name": "CORS credentials with wildcard origin",
     "severity": "CRITICAL", "pattern": r"(?:Access-Control-Allow-Credentials|supports_credentials|allowCredentials)\s*(?:=|:)\s*(?:True|true|1)",
     "description": "CORS credentials enabled — if combined with wildcard origin, cookies leak to any site.",
     "cwe": "CWE-942", "recommendation": "When credentials are enabled, restrict origins to specific trusted domains.",
     "compliance": ["OWASP-API8"]},
    {"id": "API8-010", "category": "Misconfiguration", "name": "Permissive CORS methods",
     "severity": "MEDIUM", "pattern": r"(?:Access-Control-Allow-Methods|allow_methods|allowedMethods)\s*(?:=|:)\s*['\"]?\*",
     "description": "CORS allows all HTTP methods.",
     "cwe": "CWE-942", "recommendation": "Restrict CORS methods to only those required by the API.",
     "compliance": ["OWASP-API8"]},
]

# ── OWASP API9: Improper Inventory Management ────────────────────────────────
INVENTORY_RULES: list[dict] = [
    {"id": "API9-001", "category": "Inventory Management", "name": "API version in URL without deprecation",
     "severity": "MEDIUM", "pattern": r"(?:/v[0-9]+/|/api/v[0-9]+/|version\s*(?:=|:)\s*['\"]v?[0-9]+)",
     "description": "Multiple API versions detected — ensure old versions are deprecated and retired.",
     "cwe": "CWE-1059", "recommendation": "Maintain API version inventory. Deprecate and retire old versions with clear timelines.",
     "compliance": ["OWASP-API9"]},
    {"id": "API9-002", "category": "Inventory Management", "name": "Swagger/OpenAPI endpoint publicly exposed",
     "severity": "MEDIUM", "pattern": r"(?:/swagger|/api-docs|/openapi|/docs|/redoc|/graphiql|/playground)\s*(?:['\"]|$)",
     "description": "API documentation endpoint publicly accessible — exposes API surface.",
     "cwe": "CWE-200", "recommendation": "Restrict API documentation access in production. Use authentication or IP allowlist.",
     "compliance": ["OWASP-API9"]},
    {"id": "API9-003", "category": "Inventory Management", "name": "Deprecated API endpoint still active",
     "severity": "MEDIUM", "pattern": r"(?:deprecated|DEPRECATED|@deprecated|\.deprecated|obsolete|legacy)\b",
     "description": "Deprecated API code still present — may lack security updates.",
     "cwe": "CWE-1059", "recommendation": "Remove deprecated endpoints or apply identical security controls as current versions.",
     "compliance": ["OWASP-API9"]},
    {"id": "API9-004", "category": "Inventory Management", "name": "Internal/debug endpoint exposed",
     "severity": "HIGH", "pattern": r"(?:@app\.route|router\.(?:get|post))\s*\(\s*['\"].*(?:/debug|/test|/internal|/health/detailed|/metrics|/status/full|/_)",
     "description": "Internal or debug endpoint exposed — may leak sensitive operational data.",
     "cwe": "CWE-200", "recommendation": "Remove debug/test endpoints from production. Restrict internal endpoints to internal networks.",
     "compliance": ["OWASP-API9"]},
]

# ── OWASP API10: Unsafe Consumption of APIs ──────────────────────────────────
UNSAFE_CONSUMPTION_RULES: list[dict] = [
    {"id": "API10-001", "category": "Unsafe Consumption", "name": "Third-party API response used without validation",
     "severity": "HIGH", "pattern": r"(?:response|resp|res)\.(?:json|data|body|text)\s*(?:\[|\.)",
     "description": "Third-party API response data accessed directly without validation.",
     "cwe": "CWE-20", "recommendation": "Validate and sanitise all data received from third-party APIs before use.",
     "compliance": ["OWASP-API10"]},
    {"id": "API10-002", "category": "Unsafe Consumption", "name": "External API call without timeout",
     "severity": "MEDIUM", "pattern": r"(?:requests\.(?:get|post|put|delete)|axios|fetch|http\.request)\s*\([^)]*\)\s*(?!.*timeout)",
     "description": "External API call without timeout — may hang indefinitely.",
     "cwe": "CWE-400", "recommendation": "Set explicit timeouts on all external API calls (e.g. timeout=30).",
     "compliance": ["OWASP-API10"]},
    {"id": "API10-003", "category": "Unsafe Consumption", "name": "No circuit breaker on external API",
     "severity": "LOW", "pattern": r"(?:requests\.(?:get|post)|axios\.(?:get|post)|fetch\s*\()\s*\(\s*['\"]https?://(?!localhost|127\.0\.0\.1)",
     "description": "External API call without circuit breaker pattern.",
     "cwe": "CWE-400", "recommendation": "Implement circuit breaker pattern for external API dependencies.",
     "compliance": ["OWASP-API10"]},
    {"id": "API10-004", "category": "Unsafe Consumption", "name": "Blindly following redirects from external API",
     "severity": "MEDIUM", "pattern": r"(?:allow_redirects\s*=\s*True|followRedirects?\s*(?:=|:)\s*true|maxRedirects\s*(?:=|:)\s*(?:[5-9]|[1-9]\d))",
     "description": "Following redirects from external APIs without limit — SSRF escalation risk.",
     "cwe": "CWE-601", "recommendation": "Disable or limit redirects when calling external APIs.",
     "compliance": ["OWASP-API10"]},
]

# ── Input Validation / Injection ─────────────────────────────────────────────
INJECTION_RULES: list[dict] = [
    {"id": "API-INJ-001", "category": "Input Validation", "name": "SQL injection via string formatting",
     "severity": "CRITICAL", "pattern": r"(?:execute|cursor\.execute|query|raw|rawQuery|sequelize\.query)\s*\(\s*(?:f['\"]|['\"].*%s|['\"].*\+\s*(?:request|req|body|params))",
     "description": "SQL query constructed with string formatting — SQL injection vulnerability.",
     "cwe": "CWE-89", "recommendation": "Use parameterised queries or ORM methods. Never concatenate user input into SQL.",
     "compliance": ["OWASP-API8", "PCI-DSS"]},
    {"id": "API-INJ-002", "category": "Input Validation", "name": "NoSQL injection",
     "severity": "CRITICAL", "pattern": r"(?:\.find|\.findOne|\.aggregate|\.updateOne|\.deleteOne)\s*\(\s*(?:request|req)\.",
     "description": "MongoDB/NoSQL query with direct user input — NoSQL injection.",
     "cwe": "CWE-943", "recommendation": "Validate and sanitise input. Use schema validation before database queries.",
     "compliance": ["OWASP-API8"]},
    {"id": "API-INJ-003", "category": "Input Validation", "name": "Command injection via user input",
     "severity": "CRITICAL", "pattern": r"(?:subprocess\.(?:run|call|Popen|check_output)|os\.(?:system|popen)|exec\s*\(|child_process\.exec)\s*\(.*(?:request|req)\.",
     "description": "OS command executed with user-supplied input — command injection.",
     "cwe": "CWE-78", "recommendation": "Never pass user input to shell commands. Use parameterised subprocess calls.",
     "compliance": ["OWASP-API8"]},
    {"id": "API-INJ-004", "category": "Input Validation", "name": "XSS via unsanitised output",
     "severity": "HIGH", "pattern": r"(?:innerHTML|outerHTML|document\.write|\.html\s*\()\s*(?:=\s*)?(?:request|req|body|params|data)\.",
     "description": "User input rendered as HTML without sanitisation — XSS vulnerability.",
     "cwe": "CWE-79", "recommendation": "Sanitise all output. Use context-appropriate encoding.",
     "compliance": ["OWASP-API8"]},
    {"id": "API-INJ-005", "category": "Input Validation", "name": "LDAP injection",
     "severity": "HIGH", "pattern": r"(?:ldap\.search|ldap_search|searchFilter)\s*(?:=|:|\().*(?:request|req)\.",
     "description": "LDAP query with user input — LDAP injection vulnerability.",
     "cwe": "CWE-90", "recommendation": "Sanitise and escape special LDAP characters in user input.",
     "compliance": ["OWASP-API8"]},
    {"id": "API-INJ-006", "category": "Input Validation", "name": "XML External Entity (XXE) processing",
     "severity": "CRITICAL", "pattern": r"(?:xml\.etree\.ElementTree\.parse|lxml\.etree\.parse|XMLParser|DOMParser|SAXParser|xml2js|parseString)\s*\(",
     "description": "XML parsing without disabling external entities — XXE vulnerability.",
     "cwe": "CWE-611", "recommendation": "Disable external entity processing. Use defusedxml in Python.",
     "compliance": ["OWASP-API8"]},
    {"id": "API-INJ-007", "category": "Input Validation", "name": "Path traversal via user input",
     "severity": "CRITICAL", "pattern": r"(?:open|read|write|send_file|sendFile|readFile|createReadStream)\s*\(.*(?:request|req)\.",
     "description": "File path constructed from user input — path traversal vulnerability.",
     "cwe": "CWE-22", "recommendation": "Validate and sanitise file paths. Use os.path.basename and restrict to allowed directories.",
     "compliance": ["OWASP-API8"]},
]

# ── Secrets / Credentials ────────────────────────────────────────────────────
SECRET_RULES: list[dict] = [
    {"id": "API-SEC-001", "category": "Secrets", "name": "Hardcoded API key",
     "severity": "CRITICAL", "pattern": r"(?:api[_-]?key|apikey|api[_-]?secret)\s*(?:=|:)\s*['\"][A-Za-z0-9_\-]{16,}['\"]",
     "description": "API key hardcoded in source code.",
     "cwe": "CWE-798", "recommendation": "Store API keys in environment variables or a secrets manager.",
     "compliance": ["OWASP-API2", "PCI-DSS"]},
    {"id": "API-SEC-002", "category": "Secrets", "name": "Hardcoded password/secret",
     "severity": "CRITICAL", "pattern": r"(?:password|passwd|secret|db_pass|database_password|auth_token)\s*(?:=|:)\s*['\"][^'\"]{6,}['\"]",
     "description": "Password or secret hardcoded in source code.",
     "cwe": "CWE-798", "recommendation": "Use environment variables or secrets manager for credentials.",
     "compliance": ["OWASP-API2", "PCI-DSS"]},
    {"id": "API-SEC-003", "category": "Secrets", "name": "Private key in source code",
     "severity": "CRITICAL", "pattern": r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----",
     "description": "Private key embedded in source code.",
     "cwe": "CWE-321", "recommendation": "Store private keys in a secrets manager. Never commit keys to source control.",
     "compliance": ["OWASP-API2", "PCI-DSS"]},
    {"id": "API-SEC-004", "category": "Secrets", "name": "AWS credentials hardcoded",
     "severity": "CRITICAL", "pattern": r"(?:AKIA[0-9A-Z]{16}|aws_secret_access_key\s*(?:=|:)\s*['\"][A-Za-z0-9/+=]{40}['\"])",
     "description": "AWS access key or secret key hardcoded.",
     "cwe": "CWE-798", "recommendation": "Use IAM roles, instance profiles, or AWS Secrets Manager.",
     "compliance": ["OWASP-API2", "PCI-DSS"]},
    {"id": "API-SEC-005", "category": "Secrets", "name": "Database connection string with credentials",
     "severity": "CRITICAL", "pattern": r"(?:mongodb|mysql|postgres|postgresql|redis|amqp|mssql)://[^:]+:[^@]+@",
     "description": "Database connection string with embedded credentials.",
     "cwe": "CWE-798", "recommendation": "Use environment variables for database connection strings.",
     "compliance": ["OWASP-API2", "PCI-DSS"]},
    {"id": "API-SEC-006", "category": "Secrets", "name": "Bearer/OAuth token hardcoded",
     "severity": "CRITICAL", "pattern": r"(?:Bearer|bearer)\s+[A-Za-z0-9\-._~+/]+=*",
     "description": "Bearer token hardcoded in source code.",
     "cwe": "CWE-798", "recommendation": "Retrieve tokens dynamically from auth server or secrets manager.",
     "compliance": ["OWASP-API2"]},
]

# ── Transport/TLS Security ───────────────────────────────────────────────────
TLS_RULES: list[dict] = [
    {"id": "API-TLS-001", "category": "Transport Security", "name": "HTTP endpoint (not HTTPS)",
     "severity": "HIGH", "pattern": r"['\"]http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[^'\"]+['\"]",
     "description": "Non-HTTPS endpoint used — data transmitted in cleartext.",
     "cwe": "CWE-319", "recommendation": "Use HTTPS for all API endpoints.",
     "compliance": ["OWASP-API8", "PCI-DSS"]},
    {"id": "API-TLS-002", "category": "Transport Security", "name": "Weak TLS version allowed",
     "severity": "HIGH", "pattern": r"(?:TLSv1(?:\.0)?|SSLv[23]|ssl\.PROTOCOL_TLSv1(?:_1)?|TLS_1_0|TLS_1_1|minVersion.*TLSv1(?:\.[01])?)",
     "description": "Weak TLS version (< 1.2) configured — vulnerable to downgrade attacks.",
     "cwe": "CWE-326", "recommendation": "Enforce TLS 1.2 or higher. Disable TLS 1.0 and 1.1.",
     "compliance": ["OWASP-API8", "PCI-DSS"]},
    {"id": "API-TLS-003", "category": "Transport Security", "name": "Weak cipher suite",
     "severity": "HIGH", "pattern": r"(?:DES|RC4|MD5|NULL|EXPORT|anon|3DES|RC2)\b",
     "description": "Weak cipher suite configured.",
     "cwe": "CWE-327", "recommendation": "Use only strong cipher suites (AES-256-GCM, CHACHA20-POLY1305).",
     "compliance": ["OWASP-API8", "PCI-DSS"]},
    {"id": "API-TLS-004", "category": "Transport Security", "name": "Missing HSTS header",
     "severity": "MEDIUM", "pattern": r"(?:Strict-Transport-Security)\s*(?:=|:)\s*(?:None|null|false|''|\"\")",
     "description": "HSTS header disabled or missing.",
     "cwe": "CWE-319", "recommendation": "Set Strict-Transport-Security: max-age=31536000; includeSubDomains.",
     "compliance": ["OWASP-API8"]},
]

# ── Logging & Monitoring ─────────────────────────────────────────────────────
LOGGING_RULES: list[dict] = [
    {"id": "API-LOG-001", "category": "Logging & Monitoring", "name": "Sensitive data in logs",
     "severity": "HIGH", "pattern": r"(?:log(?:ger)?\.(?:info|debug|warn|error)|console\.log|print)\s*\(.*(?:password|token|secret|api_key|credit_card|ssn|authorization)",
     "description": "Sensitive data written to logs.",
     "cwe": "CWE-532", "recommendation": "Mask or redact sensitive data before logging.",
     "compliance": ["OWASP-API8", "GDPR", "PCI-DSS"]},
    {"id": "API-LOG-002", "category": "Logging & Monitoring", "name": "No request logging configured",
     "severity": "LOW", "pattern": r"(?:logging\.disable|logger\.disabled\s*=\s*True|LOG_LEVEL\s*(?:=|:)\s*['\"](?:NONE|OFF)['\"])",
     "description": "Request logging disabled — hampers incident response.",
     "cwe": "CWE-778", "recommendation": "Enable structured request logging with timestamps, IPs, and endpoints.",
     "compliance": ["OWASP-API8", "DORA"]},
    {"id": "API-LOG-003", "category": "Logging & Monitoring", "name": "Full request body logged",
     "severity": "MEDIUM", "pattern": r"(?:log|print|console\.log)\s*\(.*(?:request\.(?:body|data|json)|req\.body)",
     "description": "Full request body logged — may contain sensitive user data.",
     "cwe": "CWE-532", "recommendation": "Log request metadata only. Redact body or log sanitised summaries.",
     "compliance": ["OWASP-API8", "GDPR"]},
]

# ── GraphQL-Specific Rules ───────────────────────────────────────────────────
GRAPHQL_RULES: list[dict] = [
    {"id": "API-GQL-001", "category": "GraphQL", "name": "GraphQL introspection enabled in production",
     "severity": "HIGH", "pattern": r"(?:introspection\s*(?:=|:)\s*(?:True|true|1)|__schema|__type|IntrospectionQuery)",
     "description": "GraphQL introspection enabled — exposes entire API schema to attackers.",
     "cwe": "CWE-200", "recommendation": "Disable introspection in production. Enable only in development.",
     "compliance": ["OWASP-API9"]},
    {"id": "API-GQL-002", "category": "GraphQL", "name": "No query depth limit",
     "severity": "HIGH", "pattern": r"(?:depthLimit|maxDepth|queryDepth)\s*(?:=|:)\s*(?:None|null|0|-1|Infinity|false)",
     "description": "GraphQL query depth limit disabled — vulnerable to nested query attacks.",
     "cwe": "CWE-400", "recommendation": "Set query depth limit (e.g. depthLimit(10)).",
     "compliance": ["OWASP-API4"]},
    {"id": "API-GQL-003", "category": "GraphQL", "name": "GraphQL batching without limit",
     "severity": "MEDIUM", "pattern": r"(?:batch|batching|allowBatchedHttpRequests)\s*(?:=|:)\s*(?:True|true|1)",
     "description": "GraphQL batching enabled without limit — amplification attack vector.",
     "cwe": "CWE-400", "recommendation": "Limit batch size or disable batching in production.",
     "compliance": ["OWASP-API4"]},
    {"id": "API-GQL-004", "category": "GraphQL", "name": "GraphQL mutation without authentication",
     "severity": "CRITICAL", "pattern": r"(?:type\s+Mutation\s*\{|\.mutation\s*\(|Mutation\s*=\s*)",
     "description": "GraphQL mutations detected — ensure authentication is required.",
     "cwe": "CWE-306", "recommendation": "Add authentication middleware to all GraphQL mutations.",
     "compliance": ["OWASP-API2"]},
    {"id": "API-GQL-005", "category": "GraphQL", "name": "GraphQL field-level authorisation missing",
     "severity": "HIGH", "pattern": r"(?:resolve|resolver)\s*(?:=|:)\s*(?:lambda|function|\()",
     "description": "GraphQL resolver without field-level authorisation check.",
     "cwe": "CWE-285", "recommendation": "Add field-level authorisation in resolvers for sensitive data.",
     "compliance": ["OWASP-API1", "OWASP-API5"]},
]

# ── gRPC-Specific Rules ─────────────────────────────────────────────────────
GRPC_RULES: list[dict] = [
    {"id": "API-GRPC-001", "category": "gRPC", "name": "gRPC insecure channel",
     "severity": "CRITICAL", "pattern": r"(?:grpc\.insecure_channel|ManagedChannelBuilder\.forAddress|\.usePlaintext\s*\(\s*\)|grpc\.Dial\s*\([^)]*grpc\.WithInsecure)",
     "description": "gRPC using plaintext (insecure) channel — data transmitted unencrypted.",
     "cwe": "CWE-319", "recommendation": "Use grpc.secure_channel with TLS credentials.",
     "compliance": ["OWASP-API8", "PCI-DSS"]},
    {"id": "API-GRPC-002", "category": "gRPC", "name": "gRPC reflection enabled",
     "severity": "MEDIUM", "pattern": r"(?:reflection\.enable|ServerReflection|grpc_reflection|add_reflection)",
     "description": "gRPC server reflection enabled — exposes service definitions.",
     "cwe": "CWE-200", "recommendation": "Disable gRPC reflection in production environments.",
     "compliance": ["OWASP-API9"]},
    {"id": "API-GRPC-003", "category": "gRPC", "name": "gRPC without authentication interceptor",
     "severity": "HIGH", "pattern": r"(?:grpc\.server|grpc\.NewServer|new\s+Server)\s*\([^)]*\)\s*(?!.*(?:interceptor|auth|credential))",
     "description": "gRPC server created without authentication interceptor.",
     "cwe": "CWE-306", "recommendation": "Add authentication interceptor (e.g. JWT, mTLS) to gRPC server.",
     "compliance": ["OWASP-API2"]},
    {"id": "API-GRPC-004", "category": "gRPC", "name": "gRPC message size unlimited",
     "severity": "MEDIUM", "pattern": r"(?:max_receive_message_length|maxInboundMessageSize|MaxRecvMsgSize)\s*(?:=|:|\()\s*(?:-1|None|null|0|Infinity)",
     "description": "gRPC message size limit disabled — resource exhaustion risk.",
     "cwe": "CWE-400", "recommendation": "Set reasonable max message size (e.g. 4MB).",
     "compliance": ["OWASP-API4"]},
]

# ── API Gateway / Proxy Misconfiguration ─────────────────────────────────────
GATEWAY_RULES: list[dict] = [
    {"id": "API-GW-001", "category": "API Gateway", "name": "Nginx proxy_pass without rate limiting",
     "severity": "HIGH", "pattern": r"proxy_pass\s+https?://",
     "description": "Nginx proxy_pass without rate limiting configuration.",
     "cwe": "CWE-770", "recommendation": "Add limit_req_zone and limit_req directives for rate limiting.",
     "compliance": ["OWASP-API4"]},
    {"id": "API-GW-002", "category": "API Gateway", "name": "Nginx upstream without health check",
     "severity": "LOW", "pattern": r"upstream\s+\w+\s*\{(?!.*(?:health_check|check))",
     "description": "Nginx upstream block without health check configuration.",
     "cwe": "CWE-400", "recommendation": "Add health_check directive to upstream blocks.",
     "compliance": ["OWASP-API10"]},
    {"id": "API-GW-003", "category": "API Gateway", "name": "API Gateway without authentication",
     "severity": "HIGH", "pattern": r"(?:x-amazon-apigateway-auth|authorizationType)\s*(?:=|:)\s*['\"](?:NONE|none|open)['\"]",
     "description": "API Gateway endpoint without authentication.",
     "cwe": "CWE-306", "recommendation": "Configure API Gateway authoriser (Lambda, Cognito, IAM).",
     "compliance": ["OWASP-API2"]},
    {"id": "API-GW-004", "category": "API Gateway", "name": "Kong plugin rate limiting not configured",
     "severity": "MEDIUM", "pattern": r"(?:plugins\s*(?:=|:)\s*\[|KongPlugin)\s*(?!.*rate)",
     "description": "Kong API gateway without rate-limiting plugin.",
     "cwe": "CWE-770", "recommendation": "Enable the rate-limiting plugin on Kong routes.",
     "compliance": ["OWASP-API4"]},
    {"id": "API-GW-005", "category": "API Gateway", "name": "Envoy filter chain without auth",
     "severity": "HIGH", "pattern": r"(?:filter_chains|http_filters)\s*(?:=|:)(?!.*(?:jwt_authn|ext_authz|rbac))",
     "description": "Envoy proxy filter chain without authentication filter.",
     "cwe": "CWE-306", "recommendation": "Add jwt_authn or ext_authz filter to Envoy configuration.",
     "compliance": ["OWASP-API2"]},
]

# ── .env File Rules ──────────────────────────────────────────────────────────
ENV_RULES: list[dict] = [
    {"id": "API-ENV-001", "category": "Environment Secrets", "name": "API key in .env file",
     "severity": "HIGH", "pattern": r"(?:API_KEY|API_SECRET|SECRET_KEY|AUTH_TOKEN|ACCESS_TOKEN)\s*=\s*[A-Za-z0-9_\-./+=]{8,}",
     "description": "API key or secret stored in .env file — ensure not committed to source control.",
     "cwe": "CWE-798", "recommendation": "Add .env to .gitignore. Use a secrets manager in production.",
     "compliance": ["OWASP-API2", "PCI-DSS"]},
    {"id": "API-ENV-002", "category": "Environment Secrets", "name": "Database credentials in .env",
     "severity": "HIGH", "pattern": r"(?:DB_PASSWORD|DATABASE_PASSWORD|MYSQL_PASSWORD|POSTGRES_PASSWORD|MONGO_PASSWORD|REDIS_PASSWORD)\s*=\s*\S+",
     "description": "Database password stored in .env file.",
     "cwe": "CWE-798", "recommendation": "Use a secrets manager for database credentials in production.",
     "compliance": ["OWASP-API2", "PCI-DSS"]},
    {"id": "API-ENV-003", "category": "Environment Secrets", "name": "JWT secret in .env",
     "severity": "HIGH", "pattern": r"(?:JWT_SECRET|JWT_KEY|TOKEN_SECRET|AUTH_SECRET)\s*=\s*\S+",
     "description": "JWT signing secret in .env — ensure strong, random value and not committed.",
     "cwe": "CWE-798", "recommendation": "Use a cryptographically random JWT secret. Rotate regularly.",
     "compliance": ["OWASP-API2"]},
    {"id": "API-ENV-004", "category": "Environment Secrets", "name": "Debug mode enabled in .env",
     "severity": "MEDIUM", "pattern": r"(?:DEBUG|NODE_ENV|FLASK_DEBUG|DJANGO_DEBUG)\s*=\s*(?:true|True|1|development)",
     "description": "Debug mode enabled via environment variable.",
     "cwe": "CWE-215", "recommendation": "Disable debug mode in production environments.",
     "compliance": ["OWASP-API8"]},
    {"id": "API-ENV-005", "category": "Environment Secrets", "name": "OAuth client secret in .env",
     "severity": "HIGH", "pattern": r"(?:OAUTH_CLIENT_SECRET|CLIENT_SECRET|GOOGLE_CLIENT_SECRET|GITHUB_CLIENT_SECRET|AUTH0_CLIENT_SECRET)\s*=\s*\S+",
     "description": "OAuth client secret in .env file.",
     "cwe": "CWE-798", "recommendation": "Use a secrets manager for OAuth credentials in production.",
     "compliance": ["OWASP-API2"]},
    {"id": "API-ENV-006", "category": "Environment Secrets", "name": "Webhook secret in .env",
     "severity": "MEDIUM", "pattern": r"(?:WEBHOOK_SECRET|STRIPE_WEBHOOK_SECRET|SIGNING_SECRET)\s*=\s*\S+",
     "description": "Webhook signing secret in .env.",
     "cwe": "CWE-798", "recommendation": "Ensure webhook secrets are strong and rotated regularly.",
     "compliance": ["OWASP-API2"]},
]

# ── Docker / Container Rules ─────────────────────────────────────────────────
DOCKER_RULES: list[dict] = [
    {"id": "API-DOCKER-001", "category": "Container Security", "name": "API container runs as root",
     "severity": "HIGH", "pattern": r"(?:USER\s+root|user\s*(?:=|:)\s*['\"]?root)",
     "description": "API container runs as root user.",
     "cwe": "CWE-250", "recommendation": "Use a non-root user (e.g. USER appuser) in Dockerfile.",
     "compliance": ["OWASP-API8"]},
    {"id": "API-DOCKER-002", "category": "Container Security", "name": "Secret in Dockerfile",
     "severity": "CRITICAL", "pattern": r"(?:ENV|ARG)\s+(?:API_KEY|SECRET|PASSWORD|TOKEN|PRIVATE_KEY)\s*=?\s*\S+",
     "description": "Secret value hardcoded in Dockerfile.",
     "cwe": "CWE-798", "recommendation": "Use Docker secrets or runtime environment variables instead.",
     "compliance": ["OWASP-API2", "PCI-DSS"]},
    {"id": "API-DOCKER-003", "category": "Container Security", "name": "Unversioned base image",
     "severity": "MEDIUM", "pattern": r"FROM\s+\S+:latest",
     "description": "Docker image uses :latest tag — unpredictable and unreproducible builds.",
     "cwe": "CWE-1104", "recommendation": "Pin base image to a specific version tag or digest.",
     "compliance": ["OWASP-API8"]},
    {"id": "API-DOCKER-004", "category": "Container Security", "name": "API port exposed without TLS",
     "severity": "MEDIUM", "pattern": r"EXPOSE\s+(?:80|8080|3000|5000|8000|9090)\b",
     "description": "Common HTTP port exposed — ensure TLS termination at load balancer or proxy.",
     "cwe": "CWE-319", "recommendation": "Use HTTPS or ensure TLS termination is handled upstream.",
     "compliance": ["OWASP-API8"]},
]

# ── K8s Ingress / Service Rules ──────────────────────────────────────────────
K8S_API_RULES: list[dict] = [
    {"id": "API-K8S-001", "category": "K8s API Security", "name": "Ingress without TLS",
     "severity": "HIGH", "pattern": r"kind:\s*Ingress(?!.*tls:)",
     "description": "Kubernetes Ingress without TLS configuration.",
     "cwe": "CWE-319", "recommendation": "Add TLS section with certificate secret to Ingress.",
     "compliance": ["OWASP-API8", "PCI-DSS"]},
    {"id": "API-K8S-002", "category": "K8s API Security", "name": "Service type LoadBalancer without restriction",
     "severity": "MEDIUM", "pattern": r"type:\s*LoadBalancer(?!.*loadBalancerSourceRanges)",
     "description": "LoadBalancer service without source IP restrictions.",
     "cwe": "CWE-668", "recommendation": "Add loadBalancerSourceRanges to restrict access.",
     "compliance": ["OWASP-API8"]},
    {"id": "API-K8S-003", "category": "K8s API Security", "name": "Missing NetworkPolicy for API pods",
     "severity": "MEDIUM", "pattern": r"kind:\s*Deployment(?!.*NetworkPolicy)",
     "description": "API deployment without associated NetworkPolicy.",
     "cwe": "CWE-668", "recommendation": "Create NetworkPolicy to restrict ingress/egress traffic.",
     "compliance": ["OWASP-API8"]},
    {"id": "API-K8S-004", "category": "K8s API Security", "name": "API container without resource limits",
     "severity": "MEDIUM", "pattern": r"containers:(?!.*(?:limits:|resources:))",
     "description": "Container without resource limits — vulnerable to resource exhaustion.",
     "cwe": "CWE-770", "recommendation": "Set CPU and memory limits on all API containers.",
     "compliance": ["OWASP-API4"]},
    {"id": "API-K8S-005", "category": "K8s API Security", "name": "Secret mounted as environment variable",
     "severity": "MEDIUM", "pattern": r"secretKeyRef:",
     "description": "K8s secret mounted as environment variable — visible in process listing.",
     "cwe": "CWE-214", "recommendation": "Mount secrets as files instead of environment variables.",
     "compliance": ["OWASP-API2"]},
]

# ── OpenAPI / Swagger Spec Rules ─────────────────────────────────────────────
OPENAPI_RULES: list[dict] = [
    {"id": "API-SPEC-001", "category": "OpenAPI Spec", "name": "Endpoint without security scheme",
     "severity": "HIGH", "pattern": r"(?:paths:.*(?:get|post|put|delete|patch):)(?!.*security:)",
     "description": "OpenAPI path operation without security requirement.",
     "cwe": "CWE-306", "recommendation": "Add security requirement to all non-public endpoints in OpenAPI spec.",
     "compliance": ["OWASP-API2"]},
    {"id": "API-SPEC-002", "category": "OpenAPI Spec", "name": "No global security scheme defined",
     "severity": "HIGH", "pattern": r"openapi:\s*['\"]?3\.",
     "description": "OpenAPI 3.x spec detected — verify global security schemes are defined.",
     "cwe": "CWE-306", "recommendation": "Define securitySchemes in components and apply globally or per-operation.",
     "compliance": ["OWASP-API2"]},
    {"id": "API-SPEC-003", "category": "OpenAPI Spec", "name": "API key auth in query parameter",
     "severity": "MEDIUM", "pattern": r"in:\s*(?:query|cookie)\s*\n\s*name:\s*(?:api[_-]?key|token|access_token)",
     "description": "API key passed in query parameter per OpenAPI spec.",
     "cwe": "CWE-598", "recommendation": "Use header-based API key or OAuth2 authentication.",
     "compliance": ["OWASP-API2"]},
    {"id": "API-SPEC-004", "category": "OpenAPI Spec", "name": "Missing response schema definition",
     "severity": "LOW", "pattern": r"responses:\s*\n\s*['\"]?(?:200|201|2\d\d)['\"]?:\s*\n\s*description:",
     "description": "API response without schema definition — may lead to undocumented data exposure.",
     "cwe": "CWE-213", "recommendation": "Define response schemas for all API endpoints.",
     "compliance": ["OWASP-API3", "OWASP-API9"]},
    {"id": "API-SPEC-005", "category": "OpenAPI Spec", "name": "Server URL uses HTTP",
     "severity": "HIGH", "pattern": r"servers:\s*\n\s*-\s*url:\s*['\"]?http://",
     "description": "OpenAPI spec defines HTTP (not HTTPS) server URL.",
     "cwe": "CWE-319", "recommendation": "Use HTTPS URLs in OpenAPI server definitions.",
     "compliance": ["OWASP-API8"]},
]

# ── Protobuf Rules ───────────────────────────────────────────────────────────
PROTO_RULES: list[dict] = [
    {"id": "API-PROTO-001", "category": "Protobuf", "name": "Sensitive field without field_behavior annotation",
     "severity": "MEDIUM", "pattern": r"(?:string|bytes)\s+(?:password|secret|token|api_key|ssn|credit_card)\s*=\s*\d+",
     "description": "Protobuf message contains sensitive field without OUTPUT_ONLY annotation.",
     "cwe": "CWE-213", "recommendation": "Add google.api.field_behavior = OUTPUT_ONLY or remove from response messages.",
     "compliance": ["OWASP-API3"]},
    {"id": "API-PROTO-002", "category": "Protobuf", "name": "RPC without authentication metadata",
     "severity": "HIGH", "pattern": r"rpc\s+\w+\s*\(",
     "description": "gRPC RPC method defined — ensure authentication interceptor is configured.",
     "cwe": "CWE-306", "recommendation": "Implement per-RPC authentication using metadata interceptors.",
     "compliance": ["OWASP-API2"]},
]

# ════════════════════════════════════════════════════════════════════════════════
#  SCANNER CLASS
# ════════════════════════════════════════════════════════════════════════════════
class APISecurityScanner:
    """Static-analysis scanner for API security misconfigurations and vulnerabilities."""

    SKIP_DIRS: set[str] = {
        "node_modules", "__pycache__", ".git", ".svn", ".hg", "venv", ".venv",
        "env", ".env", "dist", "build", ".tox", ".mypy_cache", ".pytest_cache",
        ".idea", ".vs", ".vscode", "vendor", "target", "bin", "obj",
        "coverage", ".next", ".nuxt", ".output",
    }
    SEVERITY_ORDER: dict[str, int] = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    SEVERITY_COLOR: dict[str, str] = {
        "CRITICAL": "\033[91m", "HIGH": "\033[31m", "MEDIUM": "\033[33m",
        "LOW": "\033[36m", "INFO": "\033[37m",
    }
    RESET = "\033[0m"
    BOLD = "\033[1m"

    PY_EXTENSIONS: set[str] = {".py", ".pyw"}
    JS_EXTENSIONS: set[str] = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
    CONFIG_EXTENSIONS: set[str] = {".yaml", ".yml", ".toml", ".conf"}
    ENV_NAMES: set[str] = {".env"}
    PROTO_EXTENSIONS: set[str] = {".proto"}
    GRAPHQL_EXTENSIONS: set[str] = {".graphql", ".gql"}
    DOCKER_NAMES: set[str] = {"Dockerfile", "dockerfile", "Containerfile"}
    NGINX_NAMES: set[str] = {"nginx.conf", "default.conf", "api.conf"}
    OPENAPI_KEYWORDS: set[str] = {"openapi", "swagger", "paths:", "servers:"}

    def __init__(self, verbose: bool = False) -> None:
        self.findings: list[Finding] = []
        self.files_scanned: int = 0
        self.verbose = verbose
        self.api_inventory: dict[str, set[str]] = {
            "frameworks": set(), "protocols": set(), "auth_methods": set(),
            "api_gateways": set(), "databases": set(),
        }

    # ── inventory detection keywords ──
    _FRAMEWORK_KW: dict[str, str] = {
        "flask": "Flask", "fastapi": "FastAPI", "django": "Django",
        "express": "Express", "nestjs": "NestJS", "koa": "Koa",
        "hapi": "Hapi", "spring": "Spring Boot", "gin": "Gin",
        "echo": "Echo", "fiber": "Fiber", "actix": "Actix",
        "rails": "Rails", "laravel": "Laravel", "phoenix": "Phoenix",
        "graphene": "Graphene", "strawberry": "Strawberry",
        "apollo": "Apollo", "ariadne": "Ariadne", "nexus": "Nexus",
    }
    _PROTOCOL_KW: dict[str, str] = {
        "rest": "REST", "graphql": "GraphQL", "grpc": "gRPC",
        "soap": "SOAP", "websocket": "WebSocket", "sse": "SSE",
        "protobuf": "Protobuf", "openapi": "OpenAPI", "swagger": "Swagger",
    }
    _AUTH_KW: dict[str, str] = {
        "jwt": "JWT", "oauth": "OAuth2", "basic_auth": "Basic Auth",
        "api_key": "API Key", "bearer": "Bearer Token", "saml": "SAML",
        "mtls": "mTLS", "oidc": "OpenID Connect", "passport": "Passport.js",
        "auth0": "Auth0", "cognito": "Cognito", "keycloak": "Keycloak",
    }
    _GATEWAY_KW: dict[str, str] = {
        "nginx": "Nginx", "kong": "Kong", "envoy": "Envoy",
        "traefik": "Traefik", "apigee": "Apigee", "aws_api_gateway": "AWS API Gateway",
        "azure_api_management": "Azure APIM", "istio": "Istio",
    }
    _DB_KW: dict[str, str] = {
        "postgres": "PostgreSQL", "mysql": "MySQL", "mongodb": "MongoDB",
        "redis": "Redis", "elasticsearch": "Elasticsearch", "dynamodb": "DynamoDB",
        "sqlite": "SQLite", "cassandra": "Cassandra", "neo4j": "Neo4j",
    }

    # ── public API ──
    def scan_path(self, target: str) -> list[Finding]:
        p = Path(target).resolve()
        if p.is_file():
            self._dispatch_file(str(p))
        elif p.is_dir():
            self._scan_directory(str(p))
        else:
            self._warn(f"Target not found: {target}")
        return self.findings

    # ── directory walk ──
    def _scan_directory(self, root: str) -> None:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in self.SKIP_DIRS]
            for fname in filenames:
                fpath = os.path.join(dirpath, fname)
                self._dispatch_file(fpath)

    # ── file dispatch ──
    def _dispatch_file(self, fpath: str) -> None:
        fname = os.path.basename(fpath)
        ext = os.path.splitext(fname)[1].lower()
        try:
            if ext in self.PY_EXTENSIONS:
                self._scan_source(fpath, "python")
            elif ext in self.JS_EXTENSIONS:
                self._scan_source(fpath, "javascript")
            elif ext in self.PROTO_EXTENSIONS:
                self._scan_proto(fpath)
            elif ext in self.GRAPHQL_EXTENSIONS:
                self._scan_graphql(fpath)
            elif fname in self.DOCKER_NAMES or fname.endswith(".dockerfile"):
                self._scan_docker(fpath)
            elif fname in self.NGINX_NAMES or "nginx" in fname.lower():
                self._scan_gateway(fpath)
            elif fname.startswith(".env"):
                self._scan_env(fpath)
            elif ext in self.CONFIG_EXTENSIONS:
                self._scan_config(fpath)
            elif ext == ".json" and fname in ("package.json",):
                pass  # future: npm dep scanning
            elif ext in (".json", ".yaml", ".yml"):
                self._scan_config(fpath)
            elif ext == ".go" or ext == ".java" or ext == ".rb" or ext == ".php":
                self._scan_source(fpath, "generic")
            else:
                return
            self.files_scanned += 1
            self._detect_inventory(fpath)
            self._vprint(f"  Scanned: {fpath}")
        except (OSError, UnicodeDecodeError):
            pass

    # ── inventory detection ──
    def _detect_inventory(self, fpath: str) -> None:
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read().lower()
        except OSError:
            return
        for kw, label in self._FRAMEWORK_KW.items():
            if kw in content:
                self.api_inventory["frameworks"].add(label)
        for kw, label in self._PROTOCOL_KW.items():
            if kw in content:
                self.api_inventory["protocols"].add(label)
        for kw, label in self._AUTH_KW.items():
            if kw in content:
                self.api_inventory["auth_methods"].add(label)
        for kw, label in self._GATEWAY_KW.items():
            if kw in content:
                self.api_inventory["api_gateways"].add(label)
        for kw, label in self._DB_KW.items():
            if kw in content:
                self.api_inventory["databases"].add(label)

    # ── SAST engine ──
    def _sast_scan(self, fpath: str, lines: list[str], rules: list[dict]) -> None:
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("//"):
                continue
            for rule in rules:
                if re.search(rule["pattern"], line, re.IGNORECASE):
                    self._add(rule, fpath, i, stripped)

    def _add(self, rule: dict, fpath: str, line_num: int, line_content: str) -> None:
        self.findings.append(Finding(
            rule_id=rule["id"], name=rule["name"], category=rule["category"],
            severity=rule["severity"], file_path=fpath, line_num=line_num,
            line_content=line_content[:200], description=rule["description"],
            recommendation=rule["recommendation"], cwe=rule.get("cwe", ""),
            cve=rule.get("cve", ""), compliance=rule.get("compliance", []),
        ))

    # ── source code scanning (Python / JS / Java / Go / generic) ──
    def _scan_source(self, fpath: str, lang: str) -> None:
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except OSError:
            return
        all_rules = (
            BOLA_RULES + AUTH_RULES + PROPERTY_AUTH_RULES + RESOURCE_RULES +
            BFLA_RULES + BUSINESS_FLOW_RULES + SSRF_RULES + MISCONFIG_RULES +
            INVENTORY_RULES + UNSAFE_CONSUMPTION_RULES + INJECTION_RULES +
            SECRET_RULES + TLS_RULES + LOGGING_RULES + GRAPHQL_RULES +
            GRPC_RULES
        )
        self._sast_scan(fpath, lines, all_rules)

    # ── protobuf scanning ──
    def _scan_proto(self, fpath: str) -> None:
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except OSError:
            return
        self._sast_scan(fpath, lines, PROTO_RULES + GRPC_RULES)

    # ── GraphQL schema scanning ──
    def _scan_graphql(self, fpath: str) -> None:
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except OSError:
            return
        gql_source_rules = [r for r in GRAPHQL_RULES if "GQL" in r["id"]]
        property_gql = [r for r in PROPERTY_AUTH_RULES if "GraphQL" in r.get("name", "")]
        self._sast_scan(fpath, lines, gql_source_rules + property_gql + BOLA_RULES)

    # ── Docker scanning ──
    def _scan_docker(self, fpath: str) -> None:
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except OSError:
            return
        self._sast_scan(fpath, lines, DOCKER_RULES + SECRET_RULES + TLS_RULES)

    # ── Nginx/Gateway config scanning ──
    def _scan_gateway(self, fpath: str) -> None:
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except OSError:
            return
        self._sast_scan(fpath, lines, GATEWAY_RULES + MISCONFIG_RULES + TLS_RULES)

    # ── .env scanning ──
    def _scan_env(self, fpath: str) -> None:
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except OSError:
            return
        self._sast_scan(fpath, lines, ENV_RULES)

    # ── YAML/TOML config scanning (OpenAPI, K8s, generic) ──
    def _scan_config(self, fpath: str) -> None:
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                lines = content.splitlines(keepends=True)
        except OSError:
            return
        content_lower = content.lower()
        rules: list[dict] = MISCONFIG_RULES + K8S_API_RULES + TLS_RULES + SECRET_RULES
        if any(kw in content_lower for kw in self.OPENAPI_KEYWORDS):
            rules += OPENAPI_RULES
        if "kind:" in content_lower and ("ingress" in content_lower or "service" in content_lower or "deployment" in content_lower):
            rules += K8S_API_RULES
        if "kong" in content_lower or "envoy" in content_lower:
            rules += GATEWAY_RULES
        self._sast_scan(fpath, lines, rules)

    # ── helpers ──
    def _vprint(self, msg: str) -> None:
        if self.verbose:
            print(msg)

    def _warn(self, msg: str) -> None:
        print(f"\033[33m[WARN]\033[0m {msg}", file=sys.stderr)

    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def filter_severity(self, min_sev: str) -> None:
        cutoff = self.SEVERITY_ORDER.get(min_sev, 4)
        self.findings = [f for f in self.findings if self.SEVERITY_ORDER.get(f.severity, 4) <= cutoff]

    # ════════════════════════════════════════════════════════════════════════
    #  CONSOLE REPORT
    # ════════════════════════════════════════════════════════════════════════
    def print_report(self) -> None:
        self.findings.sort(key=lambda f: self.SEVERITY_ORDER.get(f.severity, 4))
        s = self.summary()
        inv = {k: sorted(v) for k, v in self.api_inventory.items() if v}
        hdr = (
            f"\n{'=' * 80}\n"
            f"  API Security Scanner — Scan Report\n"
            f"  Scanner Version : {__version__}\n"
            f"  Scan Date       : {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
            f"  Files Scanned   : {self.files_scanned}\n"
            f"  Findings        : {len(self.findings)}\n"
            f"{'=' * 80}\n"
        )
        print(hdr)
        if inv:
            print("  API Inventory Discovered:")
            for cat, items in inv.items():
                print(f"  {cat.replace('_', ' ').title()}: {', '.join(items)}")
            print()
        for idx, f in enumerate(self.findings, 1):
            clr = self.SEVERITY_COLOR.get(f.severity, self.RESET)
            comp = ", ".join(COMPLIANCE_MAP.get(c, c) for c in f.compliance) if f.compliance else ""
            print(f"  {self.BOLD}[{idx}]{self.RESET} {f.rule_id} — {clr}{f.severity}{self.RESET}")
            print(f"      {f.name}")
            print(f"      File: {f.file_path}:{f.line_num}")
            print(f"      Code: {f.line_content}")
            if f.cwe:
                print(f"      CWE:  {f.cwe}")
            if f.cve:
                print(f"      CVE:  {f.cve}")
            if comp:
                print(f"      Compliance: {comp}")
            print(f"      Recommendation: {f.recommendation}")
            print()
        bar = "  ".join(f"{k}: {v}" for k, v in s.items())
        print(f"{'=' * 80}")
        print(f"  Summary:  {bar}")
        print(f"{'=' * 80}\n")

    # ════════════════════════════════════════════════════════════════════════
    #  JSON REPORT
    # ════════════════════════════════════════════════════════════════════════
    def save_json(self, path: str) -> None:
        data = {
            "scanner": "API Security Scanner",
            "version": __version__,
            "scan_date": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "files_scanned": self.files_scanned,
            "api_inventory": {k: sorted(v) for k, v in self.api_inventory.items() if v},
            "summary": self.summary(),
            "findings": [asdict(f) for f in self.findings],
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, default=str)
        print(f"JSON report saved to {path}")

    # ════════════════════════════════════════════════════════════════════════
    #  HTML REPORT
    # ════════════════════════════════════════════════════════════════════════
    def save_html(self, path: str) -> None:
        s = self.summary()
        inv = {k: sorted(v) for k, v in self.api_inventory.items() if v}
        now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        sev_colors = {"CRITICAL": "#ff4757", "HIGH": "#ff6b81", "MEDIUM": "#ffa502", "LOW": "#1e90ff", "INFO": "#a4b0be"}

        findings_html = ""
        for idx, f in enumerate(self.findings, 1):
            comp_tags = "".join(f'<span class="comp-tag">{COMPLIANCE_MAP.get(c, c)}</span>' for c in f.compliance)
            cve_link = f'<a href="https://nvd.nist.gov/vuln/detail/{f.cve}" target="_blank">{f.cve}</a>' if f.cve else ""
            findings_html += f"""
            <tr class="sev-{f.severity}">
              <td>{idx}</td><td>{f.rule_id}</td>
              <td><span class="sev" style="background:{sev_colors.get(f.severity,'#a4b0be')}">{f.severity}</span></td>
              <td>{f.name}</td><td>{f.category}</td>
              <td><code>{f.file_path}:{f.line_num}</code></td>
              <td><code>{f.line_content[:120]}</code></td>
              <td>{f.cwe}</td><td>{cve_link}</td>
              <td>{comp_tags}</td>
              <td>{f.recommendation}</td>
            </tr>"""

        inv_html = ""
        if inv:
            for cat, items in inv.items():
                inv_html += f"<p><strong>{cat.replace('_', ' ').title()}:</strong> {', '.join(items)}</p>"

        cards_html = "".join(
            f'<div class="card" style="border-top:3px solid {sev_colors[sev]}">'
            f'<div class="card-count">{cnt}</div><div class="card-label">{sev}</div></div>'
            for sev, cnt in s.items()
        )

        html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>API Security Scan Report</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0f0f23;color:#e0e0e0}}
.header{{background:linear-gradient(135deg,#0ea5e9,#6366f1,#8b5cf6);padding:32px;text-align:center}}
.header h1{{font-size:28px;font-weight:700;color:#fff}}.header p{{color:#e0e0ff;margin-top:6px}}
.meta{{display:flex;justify-content:center;gap:32px;margin-top:12px;color:#c8d6e5;font-size:13px}}
.cards{{display:flex;justify-content:center;gap:16px;padding:24px;flex-wrap:wrap}}
.card{{background:#1a1a3e;border-radius:8px;padding:20px 32px;text-align:center;min-width:120px}}
.card-count{{font-size:32px;font-weight:700;color:#fff}}.card-label{{font-size:13px;color:#a4b0be;margin-top:4px}}
.inv{{background:#1a1a3e;margin:0 24px 16px;padding:16px 24px;border-radius:8px;border-left:3px solid #6366f1}}
.inv p{{margin:4px 0;font-size:14px}}
.container{{padding:0 24px 24px}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
th{{background:#1a1a3e;padding:10px 8px;text-align:left;position:sticky;top:0;cursor:pointer}}
td{{padding:8px;border-bottom:1px solid #2a2a4e;vertical-align:top}}
tr:hover{{background:#1e1e3f}}
.sev{{padding:2px 8px;border-radius:4px;color:#fff;font-weight:600;font-size:11px}}
.comp-tag{{display:inline-block;background:#2a2a5e;padding:1px 6px;border-radius:3px;font-size:10px;margin:1px}}
code{{background:#1a1a3e;padding:2px 5px;border-radius:3px;font-size:12px;word-break:break-all}}
a{{color:#6366f1;text-decoration:none}}a:hover{{text-decoration:underline}}
.filters{{padding:8px 24px;display:flex;gap:12px;flex-wrap:wrap;align-items:center}}
.filters label{{font-size:13px;cursor:pointer;display:flex;align-items:center;gap:4px}}
</style></head><body>
<div class="header"><h1>API Security Scanner — Scan Report</h1>
<p>Discovery, Vulnerability &amp; Misconfiguration Management</p>
<div class="meta"><span>Version {__version__}</span><span>{now}</span>
<span>Files: {self.files_scanned}</span><span>Findings: {len(self.findings)}</span></div></div>
<div class="cards">{cards_html}</div>
{"<div class='inv'><strong>API Inventory</strong>" + inv_html + "</div>" if inv_html else ""}
<div class="filters"><strong>Filter:</strong>
{"".join(f'<label><input type="checkbox" checked onchange="filterSev()" class="sev-chk" value="{sv}"> {sv}</label>' for sv in s)}</div>
<div class="container"><table><thead><tr>
<th>#</th><th>Rule</th><th>Severity</th><th>Name</th><th>Category</th>
<th>Location</th><th>Code</th><th>CWE</th><th>CVE</th><th>Compliance</th><th>Recommendation</th>
</tr></thead><tbody>{findings_html}</tbody></table></div>
<script>
function filterSev(){{
  const chk=document.querySelectorAll('.sev-chk');
  const on=new Set();chk.forEach(c=>{{if(c.checked)on.add(c.value)}});
  document.querySelectorAll('tbody tr').forEach(r=>{{
    const s=r.className.replace('sev-','');r.style.display=on.has(s)?'':'none';
  }});
}}
</script></body></html>"""
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(html)
        print(f"HTML report saved to {path}")


# ════════════════════════════════════════════════════════════════════════════════
#  CLI
# ════════════════════════════════════════════════════════════════════════════════
def main() -> None:
    parser = argparse.ArgumentParser(
        prog="api_security_scanner.py",
        description="API Security Scanner — Discovery, Vulnerability & Misconfiguration Management",
    )
    parser.add_argument("target", help="File or directory to scan")
    parser.add_argument("--json", metavar="FILE", dest="json_file", help="Save JSON report")
    parser.add_argument("--html", metavar="FILE", dest="html_file", help="Save HTML report")
    parser.add_argument("--severity", metavar="SEV", default="LOW",
                        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                        help="Minimum severity to report")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--version", action="version", version=f"API Security Scanner v{__version__}")
    args = parser.parse_args()

    scanner = APISecurityScanner(verbose=args.verbose)
    scanner.scan_path(args.target)
    scanner.filter_severity(args.severity)
    scanner.print_report()
    if args.json_file:
        scanner.save_json(args.json_file)
    if args.html_file:
        scanner.save_html(args.html_file)

    s = scanner.summary()
    sys.exit(1 if s.get("CRITICAL", 0) + s.get("HIGH", 0) > 0 else 0)


if __name__ == "__main__":
    main()
