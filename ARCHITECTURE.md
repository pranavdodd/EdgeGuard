# Architecture

## Current milestone: M6

The Worker now supports a lightweight reverse proxy capability via the
`ORIGIN_URL` environment binding. Requests to `/health` still return the
bootstrap health JSON, while all other requests are forwarded to the configured
origin server if `ORIGIN_URL` is set.

If no origin binding is configured, requests without a matching bootstrap route
still return `404`. This milestone establishes the origin-forwarding layer but
M2 adds normalized request context and a keyed pseudonymous client ID. M3 adds
deterministic risk decisions, and M4 adds Durable Object rate limiting. M5
maps those normalized outcomes into privacy-safe `SecurityEvent` records and
persists them to D1 on a best-effort basis. D1 is historical storage only; it
does not participate in real-time decisions or rate limiting. There are still
no queues, dashboards, or administrative endpoints.
