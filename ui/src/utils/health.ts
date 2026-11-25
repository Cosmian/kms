import { getNoTTLVRequest, stripHtml } from "./utils";

type HealthStatus = "UP" | "DEGRADED" | "DOWN";

export interface DependencyHealth {
    name?: string;
    status: HealthStatus;
    latency_ms: number;
    message?: string;
}

export interface HealthResponse {
    status: HealthStatus;
    latency_ms: number;
    dependencies: {
        database: DependencyHealth;
        /** Absent when no HSM is configured. */
        hsm?: DependencyHealth[];
        /** Absent when the KMIP socket server is disabled. */
        kmip?: DependencyHealth;
    };
}

export interface ClusterNode {
    node_id: string;
    version: string;
    /** Unix time in seconds. */
    last_heartbeat: number;
    leader: boolean;
}

export interface ClusterStatus {
    nodes: ClusterNode[];
    leader: string | null;
}

/** The server, or a proxy in front of it, answered with a body that is not the expected JSON. */
export class UnexpectedResponseError extends Error {}

const STATUSES: readonly string[] = ["UP", "DEGRADED", "DOWN"];

const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null;

const isDependency = (value: unknown): value is DependencyHealth =>
    isRecord(value) &&
    typeof value.status === "string" &&
    STATUSES.includes(value.status) &&
    typeof value.latency_ms === "number" &&
    (value.name === undefined || typeof value.name === "string") &&
    (value.message === undefined || typeof value.message === "string");

const isHealthResponse = (value: unknown): value is HealthResponse =>
    isRecord(value) &&
    typeof value.status === "string" &&
    STATUSES.includes(value.status) &&
    typeof value.latency_ms === "number" &&
    isRecord(value.dependencies) &&
    isDependency(value.dependencies.database) &&
    (value.dependencies.hsm === undefined || (Array.isArray(value.dependencies.hsm) && value.dependencies.hsm.every(isDependency))) &&
    (value.dependencies.kmip === undefined || isDependency(value.dependencies.kmip));

const isClusterStatus = (value: unknown): value is ClusterStatus =>
    isRecord(value) &&
    (value.leader === null || typeof value.leader === "string") &&
    Array.isArray(value.nodes) &&
    value.nodes.every(
        (node) =>
            isRecord(node) &&
            typeof node.node_id === "string" &&
            typeof node.version === "string" &&
            typeof node.last_heartbeat === "number" &&
            typeof node.leader === "boolean",
    );

/**
 * GET /health. Resolves with the body for HTTP 200 and for HTTP 503 (`DOWN`, or `DEGRADED` in
 * strict mode); rejects on any other status, on a body of another shape, and on timeout.
 */
export const fetchHealth = async (serverUrl: string, timeoutMs: number): Promise<HealthResponse> => {
    const controller = new AbortController();
    const timeoutHandle = setTimeout(() => controller.abort(), timeoutMs);
    try {
        const response = await fetch(`${serverUrl}/health`, {
            method: "GET",
            credentials: "include",
            signal: controller.signal,
        });
        if (response.status !== 200 && response.status !== 503) {
            throw new Error(`${response.status}: ${stripHtml(await response.text())}`);
        }
        const body: unknown = await response.json();
        if (!isHealthResponse(body)) {
            throw new UnexpectedResponseError();
        }
        return body;
    } finally {
        clearTimeout(timeoutHandle);
    }
};

/** GET /cluster/status (authenticated). It can hang when the node cannot reach the database, hence the timeout. */
export const fetchClusterStatus = async (serverUrl: string, timeoutMs: number): Promise<ClusterStatus> => {
    const body: unknown = await getNoTTLVRequest("/cluster/status", serverUrl, timeoutMs);
    if (!isClusterStatus(body)) {
        throw new UnexpectedResponseError();
    }
    return body;
};

/** 🟢 for `UP`, 🟡 for `DEGRADED`, 🔴 for anything else (`DOWN`, unavailable, unknown). */
export const healthMarker = (status: string): string => {
    switch (status.trim().toUpperCase()) {
        case "UP":
            return "🟢";
        case "DEGRADED":
            return "🟡";
        default:
            return "🔴";
    }
};
