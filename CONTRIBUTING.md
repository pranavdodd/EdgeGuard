# Contributing

Install Node.js 20 or newer, then run:

```sh
npm ci
npm test
npm run typecheck
npm run lint
npm run format:check
npm run build
```

Do not commit `.env`, `.dev.vars`, Cloudflare credentials, database IDs, or
benchmark claims that were not produced by `npm run benchmark`.
