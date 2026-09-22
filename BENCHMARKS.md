# Benchmarks

## Method

Run the local Worker with `npm run dev`, then execute:

```sh
BENCHMARK_REQUESTS=100 BENCHMARK_CONCURRENCY=10 npm run benchmark -- http://127.0.0.1:8787
```

The script measures `GET` requests for `/health` (allowed), `/.env` (blocked),
and `/benchmark-missing` (unmatched). It records actual p50, p95, and p99
latencies, expected-status errors, request count, concurrency, URL, and date.
It does not fabricate rate-limit measurements; those require a configured
Durable Object deployment and should be run separately against that deployment.

## Results

Measured run on 2026-09-22:

| Case      | Requests | Concurrency | Errors |       p50 |       p95 |       p99 |
| --------- | -------: | ----------: | -----: | --------: | --------: | --------: |
| allowed   |      100 |          10 |      0 | 30.716 ms | 70.883 ms | 73.010 ms |
| blocked   |      100 |          10 |      0 | 31.952 ms | 67.766 ms | 77.022 ms |
| unmatched |      100 |          10 |      0 | 32.032 ms | 72.452 ms | 76.871 ms |

Environment: Node fetch against a local Wrangler Worker at
`http://127.0.0.1:8787`, with the default local bindings. The run used
`BENCHMARK_REQUESTS=100 BENCHMARK_CONCURRENCY=10 npm run benchmark --
http://127.0.0.1:8787`.

Latency includes local network and server overhead. It is not a claim of
production performance or WAF parity. Rate-limited traffic and deployed
production latency were not measured in this run.
