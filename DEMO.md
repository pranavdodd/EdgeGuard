# EdgeGuard Demo

## Local flow

1. Install dependencies with `npm ci`.
2. Start the Worker with `npm run dev`.
3. Check `GET /health`.
4. Request a normal path and observe the configured origin response.
5. Request `/.env` and verify the deterministic `403` response.
6. Configure `ANALYTICS_API_KEY`, then query the protected analytics endpoints.
7. Run the benchmark with `npm run benchmark -- http://127.0.0.1:8787`.

Production deployments must use a fixed, reviewed `ORIGIN_URL`; do not expose a
user-controlled proxy target. Analytics credentials and fingerprint material
must be supplied through Cloudflare secrets or environment bindings.
