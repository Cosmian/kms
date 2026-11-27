import { afterEach, expect, test, vi } from "vitest";

import { fetchClusterStatus, fetchHealth, healthMarker } from "../../src/utils/health";

const SERVER = "https://kms.example.test";

const stubFetch = (response: Response) => vi.stubGlobal("fetch", vi.fn().mockResolvedValue(response));

const body = (extra: Record<string, unknown> = {}) => ({
    status: "UP",
    latency_ms: 1,
    dependencies: { database: { name: "sqlite", status: "UP", latency_ms: 1 } },
    ...extra,
});

afterEach(() => {
    vi.unstubAllGlobals();
});

test("fetchHealth keeps the body of an HTTP 503 answer", async () => {
    stubFetch(
        new Response(
            JSON.stringify(
                body({
                    status: "DOWN",
                    dependencies: { database: { name: "postgres", status: "DOWN", latency_ms: 1, message: "x" } },
                }),
            ),
            { status: 503 },
        ),
    );
    expect((await fetchHealth(SERVER, 1000)).status).toBe("DOWN");
});

test("fetchHealth rejects on another HTTP status", async () => {
    stubFetch(new Response("boom", { status: 500 }));
    await expect(fetchHealth(SERVER, 1000)).rejects.toThrow(/^500:/);
});

test("fetchHealth rejects a body that is not a health response, such as a proxy's own 503", async () => {
    for (const payload of [
        { error: "upstream down" },
        body({ status: "WEIRD" }),
        body({ dependencies: { database: { status: "UP", latency_ms: 1 }, hsm: "not-an-array" } }),
        body({ dependencies: { database: { status: "UP", latency_ms: 1 }, kmip: { status: "UP" } } }),
    ]) {
        stubFetch(new Response(JSON.stringify(payload), { status: 503 }));
        await expect(fetchHealth(SERVER, 1000)).rejects.toThrow();
    }
});

test("fetchHealth accepts the optional hsm and kmip dependencies", async () => {
    stubFetch(new Response(JSON.stringify(body()), { status: 200 }));
    expect((await fetchHealth(SERVER, 1000)).dependencies.hsm).toBeUndefined();

    const full = body({
        status: "DEGRADED",
        dependencies: {
            database: { name: "sqlite", status: "UP", latency_ms: 1 },
            hsm: [{ name: "hsm", status: "DOWN", latency_ms: 2000, message: "slot 1: no answer within 2000 ms" }],
            kmip: { name: "kmip", status: "UP", latency_ms: 0 },
        },
    });
    stubFetch(new Response(JSON.stringify(full), { status: 200 }));
    const health = await fetchHealth(SERVER, 1000);
    expect(health.dependencies.hsm?.[0].status).toBe("DOWN");
    expect(health.dependencies.kmip?.name).toBe("kmip");
});

test("fetchHealth aborts a request that does not answer in time", async () => {
    vi.useFakeTimers();
    vi.stubGlobal(
        "fetch",
        vi.fn(
            (_input: RequestInfo | URL, init?: RequestInit) =>
                new Promise<Response>((_resolve, reject) => {
                    init?.signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")), { once: true });
                }),
        ),
    );
    const pending = expect(fetchHealth(SERVER, 5000)).rejects.toThrow("aborted");
    await vi.advanceTimersByTimeAsync(5000);
    await pending;
    vi.useRealTimers();
});

test("fetchClusterStatus rejects a body without a node list", async () => {
    stubFetch(new Response(JSON.stringify({ leader: null }), { status: 200 }));
    await expect(fetchClusterStatus(SERVER, 1000)).rejects.toThrow();
    stubFetch(
        new Response(JSON.stringify({ nodes: [{ node_id: "a", version: "5.29.0", last_heartbeat: 1, leader: true }], leader: "a" }), {
            status: 200,
        }),
    );
    expect((await fetchClusterStatus(SERVER, 1000)).leader).toBe("a");
});

test("healthMarker maps the status to a traffic-light marker", () => {
    expect(healthMarker("UP")).toBe("🟢");
    expect(healthMarker(" degraded ")).toBe("🟡");
    expect(healthMarker("DOWN")).toBe("🔴");
    expect(healthMarker("Unavailable")).toBe("🔴");
});
