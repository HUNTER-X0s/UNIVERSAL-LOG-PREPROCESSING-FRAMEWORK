# Phase 7 Rate Limiting & DoS Defense

## RateLimitMiddleware
- Per-IP sliding window rate limiting.
- Health check endpoint bypassed to avoid false downtime alerts.
- Returns HTTP 429 Too Many Requests on breach.
