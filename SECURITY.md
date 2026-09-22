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

M8 sends only minimized, privacy-safe security-event fields to Workers AI. It
does not send raw IP addresses, credentials, cookies, bodies, HMAC material,
or fingerprint inputs. AI output is validated before separate persistence and
cannot change deterministic enforcement or deploy proposed rules.

## Threat Model and Failure Policies

EdgeGuard is designed to protect an operator-controlled origin from basic
request probes, deterministic risk signals, and rate abuse. It is not a full
WAF and does not claim production-grade detection parity.

- Invalid origin configuration fails closed with a sanitized `500` response.
- Origin network failures return a sanitized `502`; enforcement remains
  deterministic and the event is queued when available.
- Durable Object failures fail open so an infrastructure outage does not turn
  into an unexpected outage; the failure is logged without request secrets.
- Queue submission and D1 consumer failures preserve request outcomes; queue
  messages retry only when base-event persistence fails.
- Workers AI failures, timeouts, malformed output, and absent bindings preserve
  the base event. AI analysis is advisory and separately stored.
- Analytics requires `ANALYTICS_API_KEY`, validates bounded filters, and is
  read-only. Query failures return a sanitized `503`.

Known limitations include heuristic rules, no IP reputation feed, no automatic
rule approval workflow, local-only benchmark results, and retention requiring
an explicit operator policy.

Retention is intentionally a future configurable policy, not an indefinite
retention promise. The `created_at` index supports a later time-based cleanup
job without changing the event contract.
