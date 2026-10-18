# Project Requirements

## 1. Functional Requirements

### FR1: HTTP Request Handling
The server shall accept HTTP requests on its configured listening address
and port, parse requests, and return HTTP responses.

### FR2: Request Normalization
The system shall normalize request data before security decisions so that
security components can inspect a consistent representation of paths,
queries, parameters, and bodies.

### FR3: Token Bucket Rate Limiting
The system shall implement a Token Bucket rate limiter that tracks request
allowance and rejects requests when the configured rate limit is exceeded.
Rejected requests shall receive HTTP 429.

### FR4: Signature-Based WAF
The system shall inspect normalized requests using configured security
signatures. Requests matching blocking rules shall receive HTTP 403.
The system shall record the matching rule and relevant request location
where available.

### FR5: Configurable Pipeline Order
The system shall support both pipeline orders:
- rate_limit_first: rate limiter followed by WAF
- waf_first: WAF followed by rate limiter

Request normalization precedes these security stages.

### FR6: Logging and Metrics
The server shall record relevant request outcomes, including successful
responses, WAF blocks, rate-limit rejections, errors, latency, and
pipeline configuration.

### FR7: Testing
Security components and pipeline behavior shall be tested using automated
tests and repeatable HTTP requests.

## 2. Non-Functional Requirements

- Reliability: malformed or unsupported requests should be handled safely.
- Maintainability: security components should remain modular.
- Observability: logs and metrics should help explain request decisions.
- Reproducibility: experiments should record the active configuration and
  relevant workload conditions.
- Usability: setup, test, and server-start instructions should be documented.

## 3. Acceptance Checks

- A normal test request receives HTTP 200 when allowed.
- A request matching a configured WAF rule is blocked with HTTP 403.
- A request exceeding the rate limit is rejected with HTTP 429.
- Both pipeline orders can be selected through configuration.
- Automated tests pass.
- Metrics identify the pipeline order and relevant security outcomes.

Exact rate-limiter defaults and environment-variable names should be verified
against the current implementation before publication.
