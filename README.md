# ACN-WAF-RateLimiter

## Project Overview

This project implements a lightweight HTTP server with request normalization,
a Token Bucket rate limiter, a signature-based Web Application Firewall (WAF),
configurable security pipeline ordering, and server-side metrics.

The project compares two security pipeline configurations:

- Mode A: Request normalization -> Rate Limiter -> WAF -> Application
- Mode B: Request normalization -> WAF -> Rate Limiter -> Application

## Requirements

- Python 3
- Git
- curl for manual HTTP testing
- pytest for automated tests

## Setup

Clone the repository and enter the project directory:

    git clone https://github.com/prarthuhs97-stack/ACN-WAF-RateLimiter.git
    cd ACN-WAF-RateLimiter

Run the automated tests from the project root:

    python3 -m pytest -q

## Running the Server

Start Mode A (rate limiter first):

    cd server
    PIPELINE_ORDER=rate_limit_first python3 server.py

Start Mode B (WAF first):

    cd server
    PIPELINE_ORDER=waf_first python3 server.py

The server listens on port 8080. Stop it with Ctrl+C.
Only one server process can listen on the configured port at a time.

## Manual Tests

Run these commands from another terminal while the server is running.

Normal request:

    curl -i http://127.0.0.1:8080/index.html

SQL-injection-style test request:

    curl -i --path-as-is 'http://127.0.0.1:8080/?id=1%27%20OR%20%271%27=%271'

Expected basic behavior:
- Normal request: HTTP 200 OK
- Matching malicious request: HTTP 403 Forbidden
- Request rejected by the rate limiter: HTTP 429 Too Many Requests

Actual results depend on the active configuration, rate-limit state, and WAF rules.

## Metrics and Logs

The server records request counts, response status counts, rate-limit
rejections, WAF blocks, latency statistics, throughput, and WAF rule matches.
On shutdown, it prints a [METRICS] JSON summary.

The WAF log identifies the client, attack category, matched rule,
location of the match, and active pipeline order.

## Project Structure

- server/: HTTP server and security components
- tests/: automated tests
- docs/: requirements, problem statement, and research gap
- experiments/, traffic/, results/, reports/: experiment-related artifacts
- gns3/, wireshark/: network experiment materials

## Experiment Notes

Basic functional tests are not performance benchmarks. A fair comparison of
the two pipeline orders requires repeatable traffic workloads, equivalent
conditions, and recorded measurements. Consult the experiment results and
report artifacts for the scope and limitations of completed experiments.
