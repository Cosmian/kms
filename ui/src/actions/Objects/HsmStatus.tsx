import { CopyOutlined } from "@ant-design/icons";
import { Badge, Button, Card, Space, Table, Tag, Tooltip, message } from "antd";
import type { TFunction } from "i18next";
import React, { useCallback, useEffect, useState } from "react";
import { Trans, useTranslation } from "react-i18next";
import { useAuth } from "../../contexts/AuthContext";
import { getNoTTLVRequest } from "../../utils/utils";

interface HsmSlotStatus {
    slot_id: number;
    accessible: boolean;
}

interface HsmInstanceStatus {
    prefix: string;
    model: string;
    slots: HsmSlotStatus[];
}

const makeSlotColumns = (prefix: string, t: TFunction) => [
    {
        title: t("hsmStatus.colSlotId"),
        dataIndex: "slot_id",
        key: "slot_id",
    },
    {
        title: t("hsmStatus.colKeyPrefix"),
        key: "key_prefix",
        render: (_: unknown, record: HsmSlotStatus) => {
            const uid = `${prefix}::${record.slot_id}::`;
            return (
                <Tooltip title={t("hsmStatus.copyTooltip")}>
                    <span className="font-mono text-xs">{uid}</span>
                    <Button
                        type="text"
                        size="small"
                        icon={<CopyOutlined />}
                        onClick={() => {
                            void navigator.clipboard.writeText(uid).then(() => {
                                void message.success(t("hsmStatus.copied", { uid }));
                            });
                        }}
                    />
                </Tooltip>
            );
        },
    },
    {
        title: t("hsmStatus.colAccessible"),
        dataIndex: "accessible",
        key: "accessible",
        render: (accessible: boolean) =>
            accessible ? (
                <Badge status="success" text={t("hsmStatus.accessibleYes")} />
            ) : (
                <Badge status="error" text={t("hsmStatus.accessibleNo")} />
            ),
    },
];

const HsmStatus: React.FC = () => {
    const [isLoading, setIsLoading] = useState(false);
    const [instances, setInstances] = useState<HsmInstanceStatus[]>([]);
    const [error, setError] = useState<string | undefined>(undefined);
    const { t } = useTranslation("actions");
    const { serverUrl } = useAuth();

    const fetchHsmStatus = useCallback(async () => {
        setIsLoading(true);
        setError(undefined);
        setInstances([]);
        try {
            const response = (await getNoTTLVRequest("/hsm/status", serverUrl)) as HsmInstanceStatus[];
            setInstances(response);
        } catch (e) {
            setError(t("hsmStatus.errorFetching", { error: String(e) }));
            console.error("Error fetching HSM status:", e);
        } finally {
            setIsLoading(false);
        }
    }, [serverUrl, t]);

    useEffect(() => {
        fetchHsmStatus();
    }, [fetchHsmStatus]);

    return (
        <div className="p-6">
            <div className="flex justify-between items-center mb-6">
                <h1 className="text-2xl font-bold">{t("hsmStatus.title")}</h1>
                <Button
                    type="primary"
                    onClick={fetchHsmStatus}
                    loading={isLoading}
                    data-testid="submit-btn"
                    className="bg-black-500 hover:bg-blue-700 border-0"
                >
                    {t("hsmStatus.refresh")}
                </Button>
            </div>

            <div className="mb-8 space-y-2">
                <p>{t("hsmStatus.intro")}</p>
                <p>
                    <Trans ns="actions" i18nKey="hsmStatus.intro2" components={{ code: <code /> }} />
                </p>
            </div>

            {instances.length === 0 && !isLoading && !error && (
                <Card data-testid="response-output">
                    <p className="text-gray-500 dark:text-gray-400">{t("hsmStatus.noInstances")}</p>
                </Card>
            )}

            <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                {instances.map((inst) => (
                    <Card
                        key={inst.prefix}
                        title={
                            <span>
                                <Tag color="blue">{inst.prefix}</Tag>
                                {inst.model}
                            </span>
                        }
                        data-testid="response-output"
                    >
                        <Table<HsmSlotStatus>
                            dataSource={inst.slots}
                            columns={makeSlotColumns(inst.prefix, t)}
                            rowKey="slot_id"
                            pagination={false}
                            size="small"
                            locale={{ emptyText: t("hsmStatus.noSlots") }}
                        />
                    </Card>
                ))}
            </Space>

            {error && (
                <Card title={t("hsmStatus.errorCard")} className="mt-4">
                    <p className="text-red-500 dark:text-red-400" data-testid="response-output">
                        {error}
                    </p>
                </Card>
            )}
        </div>
    );
};

export default HsmStatus;
