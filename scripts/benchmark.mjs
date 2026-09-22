#!/usr/bin/env node
/* global URL, console, fetch, performance, process */

const baseUrl = process.argv[2] ?? "http://127.0.0.1:8787";
const count = Number(process.env.BENCHMARK_REQUESTS ?? 100);
const concurrency = Number(process.env.BENCHMARK_CONCURRENCY ?? 10);

if (!Number.isInteger(count) || count < 1 || count > 10_000) {
  throw new Error("BENCHMARK_REQUESTS must be an integer from 1 to 10000");
}
if (!Number.isInteger(concurrency) || concurrency < 1 || concurrency > count) {
  throw new Error(
    "BENCHMARK_CONCURRENCY must be an integer within request count",
  );
}

const cases = [
  { name: "allowed", path: "/health", expected: 200 },
  { name: "blocked", path: "/.env", expected: 403 },
  { name: "unmatched", path: "/benchmark-missing", expected: 404 },
];

const percentile = (values, fraction) => {
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[
    Math.min(sorted.length - 1, Math.ceil(sorted.length * fraction) - 1)
  ];
};

const measure = async (testCase) => {
  const durations = [];
  let errors = 0;
  let next = 0;
  const worker = async () => {
    while (next < count) {
      const index = next++;
      const started = performance.now();
      try {
        const response = await fetch(new URL(testCase.path, baseUrl));
        if (response.status !== testCase.expected) errors++;
        await response.arrayBuffer();
      } catch {
        errors++;
      }
      durations[index] = performance.now() - started;
    }
  };
  await Promise.all(Array.from({ length: concurrency }, worker));
  return {
    case: testCase.name,
    requests: count,
    concurrency,
    errors,
    p50Ms: Number(percentile(durations, 0.5).toFixed(3)),
    p95Ms: Number(percentile(durations, 0.95).toFixed(3)),
    p99Ms: Number(percentile(durations, 0.99).toFixed(3)),
  };
};

console.log(
  JSON.stringify(
    {
      environment: "Node fetch against configured EdgeGuard URL",
      date: new Date().toISOString(),
      origin: baseUrl,
      requestCount: count,
      concurrency,
      results: await Promise.all(cases.map(measure)),
      interpretation:
        "Latency includes network and local server overhead; run against a deployed or local Worker for meaningful EdgeGuard measurements.",
    },
    null,
    2,
  ),
);
