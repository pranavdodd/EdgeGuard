export interface Env {
  // Bindings are added by later milestones.
}

const healthResponse = (): Response =>
  Response.json({
    status: "ok",
    service: "edgeguard",
  });

export default {
  fetch(request: Request): Response {
    const url = new URL(request.url);

    if (request.method === "GET" && url.pathname === "/health") {
      return healthResponse();
    }

    return Response.json({ error: "not_found" }, { status: 404 });
  },
} satisfies ExportedHandler<Env>;
