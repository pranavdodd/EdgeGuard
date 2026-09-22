# Architecture

## Current milestone: M1

The Worker now supports a lightweight reverse proxy capability via the
`ORIGIN_URL` environment binding. Requests to `/health` still return the
bootstrap health JSON, while all other requests are forwarded to the configured
origin server if `ORIGIN_URL` is set.

If no origin binding is configured, requests without a matching bootstrap route
still return `404`. This milestone establishes the origin-forwarding layer but
does not yet include security decisions, storage, queues, or administrative
endpoints.
