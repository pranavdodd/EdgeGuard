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
