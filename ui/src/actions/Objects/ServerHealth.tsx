import { Alert, Badge, Button, Card, Select, Space, Table, Tag } from "antd";
import dayjs from "dayjs";
import React, { useCallback, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { useOutletContext } from "react-router-dom";
import type { LayoutOutletContext } from "../../components/layout/NonFipsRoute";
import { useAuth } from "../../contexts/useAuth";
import {
    fetchClusterStatus,
    fetchHealth,
    UnexpectedResponseError,
    type ClusterNode,
    type ClusterStatus,
    type DependencyHealth,
    type HealthResponse,
} from "../../utils/health";

/** Auto-refresh periods in seconds, 0 being manual. A node heartbeat is 5 s and a node expires after 15 s. */
// No period under 5 s: a refresh is 2 requests, and the server logs and audits each of them.
const REFRESH_CHOICES = [0, 5, 10, 30, 60];
/** localStorage key of the chosen period, kept between visits. */
const REFRESH_STORAGE_KEY = "serverHealthRefreshSeconds";

const storedRefreshSeconds = (): number => {
    try {
        const seconds = Number(localStorage.getItem(REFRESH_STORAGE_KEY));
        return REFRESH_CHOICES.includes(seconds) ? seconds : 0;
    } catch {
        return 0; // storage blocked by the browser
    }
};

const storeRefreshSeconds = (seconds: number): void => {
    try {
        localStorage.setItem(REFRESH_STORAGE_KEY, String(seconds));
    } catch {
        // storage blocked by the browser: the choice then only lasts until the page is reloaded
    }
};

type DependencyType = "database" | "hsm" | "kmip";

interface DependencyRow {
    key: string;
    type: DependencyType;
    dependency: DependencyHealth;
}

const dependencyRows = (health: HealthResponse): DependencyRow[] => [
    { key: "database", type: "database", dependency: health.dependencies.database },
    ...(health.dependencies.hsm ?? []).map((dependency, index) => ({ key: `hsm:${index}`, type: "hsm" as const, dependency })),
    ...(health.dependencies.kmip ? [{ key: "kmip", type: "kmip" as const, dependency: health.dependencies.kmip }] : []),
];

// The server controls every string rendered below (dependency name and message, node id, version,
// error text), and i18n does not escape values: render them only as React text, never as markup.
const ServerHealth: React.FC = () => {
    const [isLoading, setIsLoading] = useState(false);
    const [refreshSeconds, setRefreshSeconds] = useState(storedRefreshSeconds);
    const inFlight = useRef(false);
    const [health, setHealth] = useState<HealthResponse | undefined>(undefined);
    const [cluster, setCluster] = useState<ClusterStatus | undefined>(undefined);
    const [healthError, setHealthError] = useState<string | undefined>(undefined);
    const [clusterError, setClusterError] = useState<string | undefined>(undefined);
    const { t } = useTranslation("actions");
    const { serverUrl } = useAuth();
    const reportHealth = useOutletContext<LayoutOutletContext | undefined>()?.reportHealth;

    const refresh = useCallback(async () => {
        // A tick must not stack a second request on a slow one (the health timeout is 10 s).
        if (inFlight.current) return;
        inFlight.current = true;
        setIsLoading(true);
        setHealthError(undefined);
        setClusterError(undefined);
        // Only the HTTP status is shown: /cluster/status answers with the raw error text, which /health redacts.
        const describe = (reason: unknown): string => {
            if (reason instanceof UnexpectedResponseError) return t("serverHealth.errorUnexpectedResponse");
            const status = /^(\d{3}):/.exec(reason instanceof Error ? reason.message : "")?.[1];
            return status ? `HTTP ${status}` : String(reason);
        };
        try {
            // Each answer is shown as soon as it arrives: a hung /cluster/status must not hide a /health that already says DOWN.
            await Promise.all([
                fetchHealth(serverUrl, 10_000).then(
                    (value) => {
                        setHealth(value);
                        reportHealth?.(value.status, value.latency_ms);
                    },
                    (reason: unknown) => {
                        setHealth(undefined);
                        reportHealth?.(t("main.unavailable", { ns: "layout" }), null);
                        setHealthError(t("serverHealth.errorHealth", { error: describe(reason) }));
                    },
                ),
                fetchClusterStatus(serverUrl, 5_000).then(
                    (value) => setCluster(value),
                    (reason: unknown) => {
                        setCluster(undefined);
                        setClusterError(t("serverHealth.errorCluster", { error: describe(reason) }));
                    },
                ),
            ]);
        } finally {
            inFlight.current = false;
            setIsLoading(false);
        }
    }, [reportHealth, serverUrl, t]);

    useEffect(() => {
        refresh();
    }, [refresh]);

    useEffect(() => {
        if (refreshSeconds === 0) return;
        const timer = setInterval(() => {
            if (!document.hidden) void refresh();
        }, refreshSeconds * 1000);
        return () => clearInterval(timer);
    }, [refreshSeconds, refresh]);

    const refreshLabel = (seconds: number): string =>
        seconds === 0
            ? t("serverHealth.refreshManual")
            : seconds === 60
              ? t("serverHealth.refreshEveryMinute")
              : t("serverHealth.refreshEverySeconds", { seconds });

    const statusColor = health?.status === "UP" ? "success" : health?.status === "DEGRADED" ? "warning" : "error";
    const statusHelp =
        health?.status === "UP"
            ? t("serverHealth.statusHelpUp")
            : health?.status === "DEGRADED"
              ? t("serverHealth.statusHelpDegraded")
              : t("serverHealth.statusHelpDown");

    return (
        <div className="p-6">
            <div className="flex justify-between items-center mb-6">
                <h1 className="text-2xl font-bold">{t("serverHealth.title")}</h1>
                <Space size="middle">
                    <label className="flex items-center gap-2">
                        {t("serverHealth.autoRefresh")}
                        <Select
                            value={refreshSeconds}
                            onChange={(seconds: number) => {
                                setRefreshSeconds(seconds);
                                storeRefreshSeconds(seconds);
                            }}
                            options={REFRESH_CHOICES.map((seconds) => ({ value: seconds, label: refreshLabel(seconds) }))}
                            className="w-40"
                            data-testid="auto-refresh"
                        />
                    </label>
                    <Button
                        type="primary"
                        onClick={refresh}
                        loading={isLoading}
                        data-testid="submit-btn"
                        className="bg-black-500 hover:bg-blue-700 border-0"
                    >
                        {t("serverHealth.refresh")}
                    </Button>
                </Space>
            </div>

            <p className="mb-8">{t("serverHealth.intro")}</p>

            <Space direction="vertical" size="middle" className="w-full">
                {(health || healthError) && (
                    <Card title={t("serverHealth.nodeStatusTitle")}>
                        {healthError ? (
                            <Alert type="error" showIcon message={healthError} data-testid="health-error" />
                        ) : (
                            health && (
                                <Space direction="vertical" size="small">
                                    <Tag color={statusColor} data-testid="health-status">
                                        {health.status}
                                    </Tag>
                                    <p>{statusHelp}</p>
                                    <p>{t("serverHealth.responseTime", { latency: health.latency_ms })}</p>
                                </Space>
                            )
                        )}
                    </Card>
                )}

                {health && (
                    <Card title={t("serverHealth.dependenciesTitle")} data-testid="health-dependencies">
                        <Table<DependencyRow>
                            dataSource={dependencyRows(health)}
                            rowKey="key"
                            pagination={false}
                            size="small"
                            columns={[
                                {
                                    title: t("serverHealth.colDependency"),
                                    key: "name",
                                    render: (_: unknown, row: DependencyRow) => row.dependency.name ?? "—",
                                },
                                {
                                    title: t("serverHealth.colType"),
                                    key: "type",
                                    render: (_: unknown, row: DependencyRow) =>
                                        row.type === "database"
                                            ? t("serverHealth.typeDatabase")
                                            : row.type === "hsm"
                                              ? t("serverHealth.typeHsm")
                                              : t("serverHealth.typeKmip"),
                                },
                                {
                                    title: t("serverHealth.colStatus"),
                                    key: "status",
                                    render: (_: unknown, row: DependencyRow) => (
                                        <Badge status={row.dependency.status === "UP" ? "success" : "error"} text={row.dependency.status} />
                                    ),
                                },
                                {
                                    title: t("serverHealth.colLatency"),
                                    key: "latency",
                                    render: (_: unknown, row: DependencyRow) => row.dependency.latency_ms,
                                },
                                {
                                    title: t("serverHealth.colDetails"),
                                    key: "details",
                                    render: (_: unknown, row: DependencyRow) => row.dependency.message ?? "—",
                                },
                            ]}
                        />
                    </Card>
                )}

                {(cluster || clusterError) && (
                    <Card title={t("serverHealth.clusterTitle")} data-testid="cluster-nodes">
                        {clusterError ? (
                            <Alert type="error" showIcon message={clusterError} data-testid="cluster-error" />
                        ) : (
                            cluster && (
                                <Space direction="vertical" size="small" className="w-full">
                                    <p>{t("serverHealth.clusterIntro")}</p>
                                    <p>
                                        {cluster.leader
                                            ? t("serverHealth.leaderLabel", { nodeId: cluster.leader })
                                            : t("serverHealth.noLeader")}
                                    </p>
                                    <Table<ClusterNode>
                                        dataSource={cluster.nodes}
                                        rowKey="node_id"
                                        pagination={false}
                                        size="small"
                                        locale={{ emptyText: t("serverHealth.noNodes") }}
                                        columns={[
                                            {
                                                title: t("serverHealth.colNodeId"),
                                                dataIndex: "node_id",
                                                key: "node_id",
                                                render: (nodeId: string) => (
                                                    <span className="font-mono text-xs" data-testid="cluster-node-id">
                                                        {nodeId}
                                                    </span>
                                                ),
                                            },
                                            { title: t("serverHealth.colVersion"), dataIndex: "version", key: "version" },
                                            {
                                                title: t("serverHealth.colLastHeartbeat"),
                                                dataIndex: "last_heartbeat",
                                                key: "last_heartbeat",
                                                render: (seconds: number) => dayjs.unix(seconds).format("YYYY-MM-DD HH:mm:ss"),
                                            },
                                            {
                                                title: t("serverHealth.colLeader"),
                                                dataIndex: "leader",
                                                key: "leader",
                                                render: (leader: boolean) =>
                                                    leader ? <Tag color="gold">{t("serverHealth.leaderTag")}</Tag> : null,
                                            },
                                        ]}
                                    />
                                </Space>
                            )
                        )}
                    </Card>
                )}
            </Space>
        </div>
    );
};

export default ServerHealth;
