# Architecture

## Current milestone: M0

The project currently contains a single Cloudflare Worker entrypoint. It owns
only bootstrap routing: `GET /health` returns a JSON status response and all
other routes return `404`.

No origin forwarding, security decisions, storage, queues, or administrative
endpoints are included until their respective milestones are reached.
