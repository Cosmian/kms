import { CopyOutlined } from "@ant-design/icons";
import { Badge, Button, Card, Space, Table, Tag, Tooltip, message } from "antd";
import React, { useCallback, useEffect, useState } from "react";
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

const makeSlotColumns = (prefix: string) => [
    {
        title: "Slot ID",
        dataIndex: "slot_id",
        key: "slot_id",
    },
    {
        title: "Key prefix",
        key: "key_prefix",
        render: (_: unknown, record: HsmSlotStatus) => {
            const uid = `${prefix}::${record.slot_id}::`;
            return (
                <Tooltip title="Copy key-prefix (append your key ID)">
                    <span className="font-mono text-xs">{uid}</span>
                    <Button
                        type="text"
                        size="small"
                        icon={<CopyOutlined />}
                        onClick={() => {
                            void navigator.clipboard.writeText(uid).then(() => {
                                void message.success(`Copied: ${uid}`);
                            });
                        }}
                    />
                </Tooltip>
            );
        },
    },
    {
        title: "Accessible",
        dataIndex: "accessible",
        key: "accessible",
        render: (accessible: boolean) =>
            accessible ? <Badge status="success" text="Yes" /> : <Badge status="error" text="No (no password)" />,
    },
];

const HsmStatus: React.FC = () => {
    const [isLoading, setIsLoading] = useState(false);
    const [instances, setInstances] = useState<HsmInstanceStatus[]>([]);
    const [error, setError] = useState<string | undefined>(undefined);
    const { idToken, serverUrl } = useAuth();

    const fetchHsmStatus = useCallback(async () => {
        setIsLoading(true);
        setError(undefined);
        setInstances([]);
        try {
            const response = (await getNoTTLVRequest("/hsm/status", idToken, serverUrl)) as HsmInstanceStatus[];
            setInstances(response);
        } catch (e) {
            setError(`Error fetching HSM status: ${e}`);
            console.error("Error fetching HSM status:", e);
        } finally {
            setIsLoading(false);
        }
    }, [idToken, serverUrl]);

    useEffect(() => {
        fetchHsmStatus();
    }, [fetchHsmStatus]);

    return (
        <div className="p-6">
            <div className="flex justify-between items-center mb-6">
                <h1 className="text-2xl font-bold">HSM Status</h1>
                <Button
                    type="primary"
                    onClick={fetchHsmStatus}
                    loading={isLoading}
                    data-testid="submit-btn"
                    className="bg-black-500 hover:bg-blue-700 border-0"
                >
                    Refresh
                </Button>
            </div>

            <div className="mb-8 space-y-2">
                <p>Displays all Hardware Security Module (HSM) instances connected to this KMS server.</p>
                <p>
                    Each instance is identified by a routing prefix (e.g. <code>hsm::softhsm2</code>, <code>hsm::utimaco</code>) and a model
                    name. The slot table shows which PKCS#11 slots are configured and whether a login password has been provided.
                </p>
            </div>

            {instances.length === 0 && !isLoading && !error && (
                <Card data-testid="response-output">
                    <p className="text-gray-500">No HSM instances configured on this server.</p>
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
                            columns={makeSlotColumns(inst.prefix)}
                            rowKey="slot_id"
                            pagination={false}
                            size="small"
                            locale={{ emptyText: "No slots configured" }}
                        />
                    </Card>
                ))}
            </Space>

            {error && (
                <Card title="Error" className="mt-4">
                    <p className="text-red-500" data-testid="response-output">
                        {error}
                    </p>
                </Card>
            )}
        </div>
    );
};

export default HsmStatus;
