import http from "node:http";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import worker from "../src/index";

describe("GET /health", () => {
  it("returns a JSON health response", async () => {
    const response = await worker.fetch(new Request("http://localhost/health"));

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("application/json");
    await expect(response.json()).resolves.toEqual({
      status: "ok",
      service: "edgeguard",
    });
  });
});

describe("bootstrap routing", () => {
  it("returns 404 for routes outside M0", async () => {
    const response = await worker.fetch(new Request("http://localhost/"));

    expect(response.status).toBe(404);
  });
});

describe("M1 proxy forwarding", () => {
  let server: http.Server;
  let port: number;

  beforeAll(async () => {
    server = http.createServer((req, res) => {
      let body = "";

      req.on("data", (chunk) => {
        body += chunk.toString();
      });

      req.on("end", () => {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(
          JSON.stringify({
            method: req.method,
            url: req.url,
            header: req.headers["x-test"],
            body,
          }),
        );
      });
    });

    await new Promise<void>((resolve) => {
      server.listen(0, "127.0.0.1", () => resolve());
    });

    port = (server.address() as { port: number }).port;
  });

  afterAll(async () => {
    await new Promise<void>((resolve, reject) => {
      server.close((error) => {
        if (error) {
          reject(error);
          return;
        }

        resolve();
      });
    });
  });

  it("forwards the request and response to the configured origin", async () => {
    const response = await worker.fetch(
      new Request("http://localhost/api/v1/users?active=true", {
        method: "POST",
        headers: {
          "x-test": "edgeguard",
        },
        body: JSON.stringify({ ok: true }),
      }),
      {
        ORIGIN_URL: `http://127.0.0.1:${port}`,
      },
    );

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({
      method: "POST",
      url: "/api/v1/users?active=true",
      header: "edgeguard",
      body: '{"ok":true}',
    });
  });
});
