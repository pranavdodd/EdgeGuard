# EdgeGuard

EdgeGuard is a Cloudflare Workers API security gateway. The repository is being
built milestone by milestone from the accompanying build specification.

## M0: Bootstrap

M0 provides a typed Cloudflare Worker, local Wrangler development server, test
runner, linting, formatting, and a health endpoint.

## M1: Reverse Proxy

M1 adds a simple reverse-proxy layer. When the worker is configured with an
`ORIGIN_URL` binding, it forwards incoming requests to that origin and returns
the origin response. `/health` remains a local bootstrap endpoint and bypasses
proxying.

Later milestones add security decisions and gateway policies.

## M5: Security Event Persistence

M5 adds a privacy-safe, best-effort security-event history in Cloudflare D1.
Events record normalized request context, risk outcomes, proxy status, and rate
limit metadata without storing raw IPs, credentials, cookies, bodies, secrets,
or query strings. D1 is not part of the real-time enforcement path; Durable
Objects continue to own rate limiting.

See [SECURITY.md](SECURITY.md) for storage exclusions and retention assumptions.

## M6: Asynchronous Security Event Processing

M6 sends privacy-safe security events to the `SECURITY_EVENTS_QUEUE` Cloudflare
Queue from the request path. The queue consumer persists events to D1 in the
background, acknowledges successful writes, and retries failed messages.
Security-event inserts are idempotent, so at-least-once queue delivery does not
duplicate records.

## M7: Read-Only Security Analytics

M7 adds authenticated, read-only analytics endpoints. Use a bearer token or
`x-api-key` matching `ANALYTICS_API_KEY` with `/api/analytics/events` or
`/api/analytics/summary`. Event reads support bounded action, client, and limit
filters; summaries provide a bounded time window, action counts, average risk
score, and top paths. Responses are not cached.

## M8: Workers AI Threat Analyst

M8 asynchronously analyzes queued security events with the `AI` Workers AI
binding and stores validated advisory analyses separately in D1. Analysis is
available at `/api/analytics/analysis?eventId=...` and is explicitly labeled
AI-generated. It never decides request enforcement or activates proposed rules;
AI failures preserve the base event and do not affect request handling.

## Requirements

- Node.js 20 or newer
- npm

## Commands

```sh
npm install
npm test
npm run typecheck
npm run lint
npm run format:check
npm run dev
```

With the development server running, request `http://localhost:8787/health`.
It returns JSON with HTTP status `200`.
