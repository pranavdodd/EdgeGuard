import { describe, expect, it } from "vitest";
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
