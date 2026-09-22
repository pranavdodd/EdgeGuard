# Security Event Privacy

M5 stores security outcomes in Cloudflare D1 for operational history. Events
contain pseudonymous `clientId` values, request IDs, pathname-only request
locations, coarse edge metadata, risk outcomes, and applicable proxy or rate
limit metadata.

The event schema deliberately excludes raw IP addresses, authorization and
cookie values, request and response bodies, all incoming headers, fingerprint
material, HMAC secrets, Durable Object internals, and raw query strings.

D1 persistence is asynchronous and best effort. Queue submission or consumer
failures are logged internally without exposing infrastructure details to
clients and do not change proxy, block, or rate-limit behavior. Queue delivery
is at least once; event IDs make D1 inserts idempotent. Durable Objects remain
the source of truth for real-time rate limiting; D1 is only the historical
event store.

Retention is intentionally a future configurable policy, not an indefinite
retention promise. The `created_at` index supports a later time-based cleanup
job without changing the event contract.
