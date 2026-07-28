import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { requestZapBaseline } from "../../lib/worker-client";

const ORIGINAL_ENV = { ...process.env };

describe("requestZapBaseline — structured reason codes (never just 'Not Tested')", () => {
  beforeEach(() => {
    process.env.SCANNER_WORKER_URL = "http://worker.test";
    process.env.SCANNER_WORKER_SECRET = "test-secret";
  });

  afterEach(() => {
    process.env = { ...ORIGINAL_ENV };
    vi.unstubAllGlobals();
  });

  it("reports ZAP_WORKER_NOT_CONFIGURED when env vars are missing, without ever attempting a request", async () => {
    delete process.env.SCANNER_WORKER_URL;
    delete process.env.SCANNER_WORKER_SECRET;
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);

    const result = await requestZapBaseline("https://example.com");
    expect(result.execution.status).toBe("NOT_TESTED");
    expect(result.execution.reasonCode).toBe("ZAP_WORKER_NOT_CONFIGURED");
    expect(result.execution.reasonMessage.length).toBeGreaterThan(0);
    expect(result.report).toBeNull();
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("reports ZAP_WORKER_UNREACHABLE on a network error (not AbortError)", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockRejectedValue(new Error("connect ECONNREFUSED 127.0.0.1:8080")),
    );

    const result = await requestZapBaseline("https://example.com");
    expect(result.execution.status).toBe("FAILED");
    expect(result.execution.reasonCode).toBe("ZAP_WORKER_UNREACHABLE");
    expect(result.execution.startedAt).not.toBeNull();
    expect(result.execution.completedAt).not.toBeNull();
    expect(result.execution.durationMs).not.toBeNull();
  });

  it("reports ZAP_TIMEOUT when the request is aborted", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation(() => {
        const err = new Error("The operation was aborted");
        err.name = "AbortError";
        return Promise.reject(err);
      }),
    );

    const result = await requestZapBaseline("https://example.com", 50);
    expect(result.execution.status).toBe("TIMED_OUT");
    expect(result.execution.reasonCode).toBe("ZAP_TIMEOUT");
  });

  it("reports ZAP_START_FAILED when the worker responds with a non-2xx status", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(new Response(JSON.stringify({ error: "boom" }), { status: 500 })),
    );

    const result = await requestZapBaseline("https://example.com");
    expect(result.execution.status).toBe("FAILED");
    expect(result.execution.reasonCode).toBe("ZAP_START_FAILED");
    expect(result.execution.reasonMessage).toContain("500");
  });

  it("reports ZAP_INVALID_RESPONSE when the worker's body isn't valid JSON", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(new Response("not json", { status: 200 })),
    );

    const result = await requestZapBaseline("https://example.com");
    expect(result.execution.status).toBe("FAILED");
    expect(result.execution.reasonCode).toBe("ZAP_INVALID_RESPONSE");
  });

  it("reports ZAP_REPORT_MISSING when the worker returns ok without a report field", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(new Response(JSON.stringify({}), { status: 200 })),
    );

    const result = await requestZapBaseline("https://example.com");
    expect(result.execution.status).toBe("FAILED");
    expect(result.execution.reasonCode).toBe("ZAP_REPORT_MISSING");
  });

  it("reports COMPLETED with the real report and null reasonCode on success", async () => {
    const fakeReport = { site: [{ "@name": "https://example.com", alerts: [] }] };
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(new Response(JSON.stringify({ report: fakeReport }), { status: 200 })),
    );

    const result = await requestZapBaseline("https://example.com");
    expect(result.execution.status).toBe("COMPLETED");
    expect(result.execution.reasonCode).toBeNull();
    expect(result.report).toEqual(fakeReport);
  });
});
