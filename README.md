# EdgeGuard

EdgeGuard is a Cloudflare Workers API security gateway. The repository is being
built milestone by milestone from the accompanying build specification.

## M0: Bootstrap

M0 provides a typed Cloudflare Worker, local Wrangler development server, test
runner, linting, formatting, and a health endpoint. Later milestones add proxy
forwarding and security behavior.

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
