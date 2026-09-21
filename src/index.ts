export interface Env {
  ORIGIN_URL?: string;
}

const healthResponse = (): Response =>
  Response.json({
    status: "ok",
    service: "edgeguard",
  });

const proxyRequest = (request: Request, env?: Env): Response | null => {
  if (!env?.ORIGIN_URL) {
    return null;
  }

  const origin = new URL(env.ORIGIN_URL);
  const target = new URL(request.url);

  target.protocol = origin.protocol;
  target.username = origin.username;
  target.password = origin.password;
  target.host = origin.host;

  const proxiedRequest = new Request(target.toString(), request);
  const headers = new Headers(proxiedRequest.headers);
  headers.set("host", origin.host);

  return fetch(new Request(proxiedRequest, { headers }));
};

export default {
  fetch(request: Request, env: Env): Response {
    const url = new URL(request.url);

    if (request.method === "GET" && url.pathname === "/health") {
      return healthResponse();
    }

    const proxiedResponse = proxyRequest(request, env);
    if (proxiedResponse) {
      return proxiedResponse;
    }

    return Response.json({ error: "not_found" }, { status: 404 });
  },
} satisfies ExportedHandler<Env>;
