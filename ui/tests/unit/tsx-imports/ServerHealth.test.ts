import { fireEvent, screen, waitFor } from "@testing-library/react";
import React from "react";
import { afterEach, beforeEach, expect, test, vi } from "vitest";

import MainLayout from "../../../src/components/layout/MainLayout";
import ServerHealth from "../../../src/actions/Objects/ServerHealth";
import { smokeRender } from "../test-utils";

const json = (payload: unknown, status = 200) => Promise.resolve(new Response(JSON.stringify(payload), { status }));

/** Answers each endpoint from `routes`; anything else is a 404. */
const stubServer = (routes: Record<string, () => Promise<Response>>) => {
    const fetchMock = vi.fn((input: RequestInfo | URL) => (routes[String(input)] ?? (() => json({}, 404)))());
    vi.stubGlobal("fetch", fetchMock);
    return fetchMock;
};

const UP = () => json({ status: "UP", latency_ms: 1, dependencies: { database: { name: "sqlite", status: "UP", latency_ms: 1 } } });
const NO_NODES = () => json({ nodes: [], leader: null });
const healthCalls = (fetchMock: ReturnType<typeof stubServer>) => fetchMock.mock.calls.filter(([url]) => String(url) === "/health").length;

/** In-memory localStorage, so that a test neither reads nor leaves a stored period. */
const stubStorage = (initial: Record<string, string> = {}) => {
    const store = new Map(Object.entries(initial));
    const storage = {
        getItem: vi.fn((key: string) => store.get(key) ?? null),
        setItem: vi.fn((key: string, value: string) => void store.set(key, value)),
    };
    vi.stubGlobal("localStorage", storage);
    return storage;
};

beforeEach(() => {
    stubStorage();
});

afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    vi.useRealTimers();
});

test("ServerHealth renders hostile server text as inert text", async () => {
    const hostileName = '<img src=x onerror="window.__xss=1">';
    const hostileMessage = "<script>window.__xss=1</script>";
    stubServer({
        "/health": () =>
            json({
                status: "DEGRADED",
                latency_ms: 2,
                dependencies: {
                    database: { name: "sqlite", status: "UP", latency_ms: 1 },
                    hsm: [{ name: hostileName, status: "DOWN", latency_ms: 2000, message: hostileMessage }],
                    kmip: { name: "kmip", status: "UP", latency_ms: 0 },
                },
            }),
        "/cluster/status": () =>
            json({ nodes: [{ node_id: "node-1", version: "5.29.0", last_heartbeat: 1794931360, leader: true }], leader: "node-1" }),
    });

    const { container } = smokeRender(React.createElement(ServerHealth));

    expect(await screen.findByTestId("health-status")).toHaveTextContent("DEGRADED");
    expect(screen.getByTestId("health-dependencies")).toHaveTextContent(hostileName);
    expect(screen.getByTestId("health-dependencies")).toHaveTextContent(hostileMessage);
    expect(screen.getByTestId("health-dependencies")).toHaveTextContent("KMIP socket server");
    expect(container.querySelector("img, script")).toBeNull();
    expect(screen.getByTestId("cluster-node-id")).toHaveTextContent("node-1");
});

test("ServerHealth shows a failed section without hiding the other one", async () => {
    stubServer({
        "/health": () => json({ error: "upstream down" }, 503),
        "/cluster/status": () => json({ nodes: [], leader: null }),
    });

    smokeRender(React.createElement(ServerHealth));

    expect(await screen.findByTestId("health-error")).toHaveTextContent("Unexpected response from the server");
    expect(await screen.findByTestId("cluster-nodes")).toHaveTextContent("No leader elected yet");
    expect(screen.queryByTestId("health-status")).toBeNull();
});

test("an HTTP error shows its status and never the raw error text of the server", async () => {
    stubServer({
        "/health": UP,
        "/cluster/status": () => Promise.resolve(new Response("FATAL: password authentication failed for user kms", { status: 500 })),
    });

    smokeRender(React.createElement(ServerHealth));

    const error = await screen.findByTestId("cluster-error");
    expect(error).toHaveTextContent("HTTP 500");
    expect(error).not.toHaveTextContent("FATAL");
});

test("a /cluster/status that never answers does not hold back the /health result", async () => {
    stubServer({
        "/health": () =>
            json({ status: "DOWN", latency_ms: 1, dependencies: { database: { name: "postgres", status: "DOWN", latency_ms: 1 } } }, 503),
        "/cluster/status": () => new Promise<Response>(() => {}),
    });

    smokeRender(React.createElement(ServerHealth));

    expect(await screen.findByTestId("health-status")).toHaveTextContent("DOWN");
});

test("a DOWN /health answer does not hide the server version in the footer", async () => {
    stubServer({
        "/server-info": () => json({ fips_mode: false }),
        "/version": () => json("5.29.0"),
        "/me": () => json({ user: "admin" }),
        "/health": () =>
            json({ status: "DOWN", latency_ms: 1, dependencies: { database: { name: "sqlite", status: "DOWN", latency_ms: 1 } } }, 503),
    });

    smokeRender(React.createElement(MainLayout, { isDarkMode: false, setIsDarkMode: () => {}, authMethod: "None", wasmError: false }), {
        withRoutes: true,
        path: "/",
    });

    const link = await screen.findByTestId("footer-health");
    expect(link).toHaveTextContent("🔴 Health: DOWN (1ms)");
    expect(link).toHaveAttribute("href", "/server-health");
    await waitFor(() => expect(screen.getByText(/KMS Server Version: 5\.29\.0/)).toBeInTheDocument());
});

test("an unreachable /health shows the unavailable marker and keeps the version", async () => {
    stubServer({
        "/server-info": () => json({ fips_mode: false }),
        "/version": () => json("5.29.0"),
        "/me": () => json({ user: "admin" }),
        "/health": () => Promise.reject(new TypeError("Failed to fetch")),
    });

    smokeRender(React.createElement(MainLayout, { isDarkMode: false, setIsDarkMode: () => {}, authMethod: "None", wasmError: false }), {
        withRoutes: true,
        path: "/",
    });

    expect(await screen.findByTestId("footer-health")).toHaveTextContent("🔴 Health: Unavailable");
    await waitFor(() => expect(screen.getByText(/KMS Server Version: 5\.29\.0/)).toBeInTheDocument());
});

/** Opens the auto-refresh menu and picks the option with this label. */
const choosePeriod = async (label: string) => {
    fireEvent.mouseDown(screen.getByTestId("auto-refresh").querySelector(".ant-select-selector") as HTMLElement);
    const option = await waitFor(() => {
        const found = document.querySelector(`.ant-select-item-option[title="${label}"]`);
        expect(found).not.toBeNull();
        return found as HTMLElement;
    });
    fireEvent.click(option);
};

test("auto-refresh offers manual, 5 s, 10 s, 30 s and 1 min, and nothing faster", async () => {
    stubServer({ "/health": UP, "/cluster/status": NO_NODES });
    smokeRender(React.createElement(ServerHealth));
    await screen.findByTestId("health-status");

    fireEvent.mouseDown(screen.getByTestId("auto-refresh").querySelector(".ant-select-selector") as HTMLElement);
    await waitFor(() => expect(document.querySelectorAll(".ant-select-item-option")).toHaveLength(5));
    const labels = [...document.querySelectorAll(".ant-select-item-option")].map((option) => option.getAttribute("title"));
    expect(labels).toEqual(["Manual", "Every 5 s", "Every 10 s", "Every 30 s", "Every minute"]);
});

test("auto-refresh polls at the chosen period and stops when set back to manual", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const fetchMock = stubServer({ "/health": UP, "/cluster/status": NO_NODES });

    smokeRender(React.createElement(ServerHealth));
    await screen.findByTestId("health-status");
    const initial = healthCalls(fetchMock);

    await vi.advanceTimersByTimeAsync(30_000);
    expect(healthCalls(fetchMock)).toBe(initial);

    await choosePeriod("Every 5 s");
    await vi.advanceTimersByTimeAsync(5_000);
    await waitFor(() => expect(healthCalls(fetchMock)).toBe(initial + 1));
    await vi.advanceTimersByTimeAsync(5_000);
    await waitFor(() => expect(healthCalls(fetchMock)).toBe(initial + 2));

    await choosePeriod("Every 30 s");
    await vi.advanceTimersByTimeAsync(10_000);
    expect(healthCalls(fetchMock)).toBe(initial + 2);
    await vi.advanceTimersByTimeAsync(20_000);
    await waitFor(() => expect(healthCalls(fetchMock)).toBe(initial + 3));

    await choosePeriod("Manual");
    await vi.advanceTimersByTimeAsync(120_000);
    expect(healthCalls(fetchMock)).toBe(initial + 3);
});

test("auto-refresh does not poll while the browser tab is hidden", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const fetchMock = stubServer({ "/health": UP, "/cluster/status": NO_NODES });

    smokeRender(React.createElement(ServerHealth));
    await screen.findByTestId("health-status");
    const initial = healthCalls(fetchMock);

    vi.spyOn(document, "hidden", "get").mockReturnValue(true);
    await choosePeriod("Every 5 s");
    await vi.advanceTimersByTimeAsync(30_000);
    expect(healthCalls(fetchMock)).toBe(initial);
});

test("the chosen auto-refresh period is remembered and applied after a reload", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const storage = stubStorage();
    const fetchMock = stubServer({ "/health": UP, "/cluster/status": NO_NODES });

    const firstVisit = smokeRender(React.createElement(ServerHealth));
    await screen.findByTestId("health-status");
    await choosePeriod("Every 10 s");
    expect(storage.setItem).toHaveBeenCalledWith("serverHealthRefreshSeconds", "10");
    firstVisit.unmount();

    smokeRender(React.createElement(ServerHealth));
    await screen.findByTestId("health-status");
    expect(screen.getByTestId("auto-refresh")).toHaveTextContent("Every 10 s");
    const initial = healthCalls(fetchMock);
    await vi.advanceTimersByTimeAsync(10_000);
    await waitFor(() => expect(healthCalls(fetchMock)).toBe(initial + 1));
});

test("an unknown stored period falls back to manual", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    stubStorage({ serverHealthRefreshSeconds: "7" });
    const fetchMock = stubServer({ "/health": UP, "/cluster/status": NO_NODES });

    smokeRender(React.createElement(ServerHealth));
    await screen.findByTestId("health-status");
    expect(screen.getByTestId("auto-refresh")).toHaveTextContent("Manual");
    const initial = healthCalls(fetchMock);
    await vi.advanceTimersByTimeAsync(60_000);
    expect(healthCalls(fetchMock)).toBe(initial);
});

test("a browser that blocks storage does not break the page", async () => {
    const blocked = () => {
        throw new Error("storage blocked");
    };
    vi.stubGlobal("localStorage", { getItem: blocked, setItem: blocked });
    stubServer({ "/health": UP, "/cluster/status": NO_NODES });

    smokeRender(React.createElement(ServerHealth));
    await screen.findByTestId("health-status");
    await choosePeriod("Every 5 s");
    expect(screen.getByTestId("auto-refresh")).toHaveTextContent("Every 5 s");
});

test("a refresh on the page updates the footer marker too", async () => {
    let status = "UP";
    stubServer({
        "/server-info": () => json({ fips_mode: false }),
        "/version": () => json("5.29.0"),
        "/me": () => json({ user: "admin" }),
        "/health": () => json({ status, latency_ms: 1, dependencies: { database: { name: "sqlite", status: "UP", latency_ms: 1 } } }),
        "/cluster/status": NO_NODES,
    });

    smokeRender(React.createElement(MainLayout, { isDarkMode: false, setIsDarkMode: () => {}, authMethod: "None", wasmError: false }), {
        withRoutes: true,
        path: "/",
        outlet: React.createElement(ServerHealth),
    });
    await waitFor(() => expect(screen.getByTestId("footer-health")).toHaveTextContent("🟢 Health: UP"));

    status = "DEGRADED";
    fireEvent.click(screen.getByTestId("submit-btn"));
    await waitFor(() => expect(screen.getByTestId("footer-health")).toHaveTextContent("🟡 Health: DEGRADED"));
});

test("a failed refresh on the page marks the footer as unavailable", async () => {
    let reachable = true;
    stubServer({
        "/server-info": () => json({ fips_mode: false }),
        "/version": () => json("5.29.0"),
        "/me": () => json({ user: "admin" }),
        "/health": () => (reachable ? UP() : Promise.reject(new TypeError("Failed to fetch"))),
        "/cluster/status": NO_NODES,
    });

    smokeRender(React.createElement(MainLayout, { isDarkMode: false, setIsDarkMode: () => {}, authMethod: "None", wasmError: false }), {
        withRoutes: true,
        path: "/",
        outlet: React.createElement(ServerHealth),
    });
    await waitFor(() => expect(screen.getByTestId("footer-health")).toHaveTextContent("🟢 Health: UP"));

    reachable = false;
    fireEvent.click(screen.getByTestId("submit-btn"));
    await waitFor(() => expect(screen.getByTestId("footer-health")).toHaveTextContent("🔴 Health: Unavailable"));
});
