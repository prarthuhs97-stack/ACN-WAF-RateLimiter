# Problem Statement

## Background

HTTP services can be exposed to excessive request rates and malicious input.
Rate limiting and a Web Application Firewall (WAF) address different aspects
of this problem: rate limiting constrains request volume, while a WAF
inspects requests for patterns associated with attacks.

The order in which these controls execute can affect which component handles
a request first, which security event is recorded, and how requests consume
rate-limit capacity.

## Problem

The project needs a small, testable HTTP server that combines request
normalization, Token Bucket rate limiting, and signature-based WAF inspection.
It must support two configurable security pipeline orders so their behavior
can be examined under consistent conditions.

## Objectives

1. Implement an HTTP server with request parsing and normalization.
2. Implement a Token Bucket rate limiter.
3. Implement signature-based WAF detection and blocking.
4. Support rate-limiter-first and WAF-first pipeline configurations.
5. Record security decisions and request-processing metrics.
6. Validate basic behavior through automated and manual tests.
7. Provide a foundation for repeatable traffic experiments.

## Scope

The implementation covers HTTP request handling and the specified security
controls. Comparative performance claims require separate controlled
experiments and should not be inferred from a small number of manual requests.

## Expected Outcome

The project should provide a reproducible test environment for observing
how two security pipeline orders handle benign requests, malicious requests,
and rate-limited traffic.
