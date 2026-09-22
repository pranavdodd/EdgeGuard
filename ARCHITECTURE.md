# Architecture

## Current milestone: M7

The Worker supports a lightweight reverse proxy through the `ORIGIN_URL`
environment binding. `/health` remains local, while other requests are
forwarded to the configured origin when present.

M2 adds normalized request context and a keyed pseudonymous client ID. M3 adds
deterministic risk decisions, M4 adds Durable Object rate limiting, and M5
maps outcomes into privacy-safe `SecurityEvent` records. M6 adds queue-backed
asynchronous event persistence. M7 adds authenticated read-only analytics
routes backed by parameterized D1 queries.

D1 is historical storage only; it does not participate in real-time decisions
or rate limiting. There are no write-capable administrative endpoints.
