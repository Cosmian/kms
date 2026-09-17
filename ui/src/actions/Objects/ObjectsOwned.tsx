import { Button, Card, Space, Table, Tag } from "antd";
import React, { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { useAuth } from "../../contexts/useAuth";
import { getNoTTLVRequest } from "../../utils/utils";

interface OwnedObject {
    object_id: string;
    state: string;
    attributes: {
        ObjectType: string;
    };
}

const ObjectsOwnedList: React.FC = () => {
    const [isLoading, setIsLoading] = useState(false);
    const [objects, setObjects] = useState<OwnedObject[]>([]);
    const [res, setRes] = useState<string | undefined>(undefined);
    const { t } = useTranslation("actions");
    const { serverUrl } = useAuth();

    const columns = [
        {
            title: t("objectsOwned.colUid"),
            dataIndex: "object_id",
            key: "object_id",
        },
        {
            title: t("objectsOwned.colType"),
            key: "attributes.ObjectType",
            render: (record: OwnedObject) => record.attributes?.ObjectType || "N/A",
        },
        {
            title: t("objectsOwned.colState"),
            dataIndex: "state",
            key: "state",
            render: (state: string) => <Tag color={state === "Active" ? "green" : "orange"}>{state}</Tag>,
        },
    ];

    const fetchOwnedObjects = useCallback(async () => {
        setIsLoading(true);
        setRes(undefined);
        setObjects([]);
        try {
            const response = await getNoTTLVRequest("/access/owned", serverUrl);
            if (response.length) {
                setObjects(response);
            } else {
                setRes(t("objectsOwned.emptyResult"));
            }
        } catch (e) {
            setRes(t("objectsOwned.errorListing", { error: String(e) }));
            console.error("Error listing objects:", e);
        } finally {
            setIsLoading(false);
        }
    }, [serverUrl, t]);

    useEffect(() => {
        fetchOwnedObjects();
    }, [fetchOwnedObjects]);

    return (
        <div className="p-6">
            <div className="flex justify-between items-center mb-6">
                <h1 className="text-2xl font-bold">{t("objectsOwned.title")}</h1>
                <Button type="primary" onClick={fetchOwnedObjects} loading={isLoading} className="bg-black-500 hover:bg-blue-700 border-0">
                    {t("objectsOwned.refresh")}
                </Button>
            </div>

            <div className="mb-8 space-y-2">
                <p>{t("objectsOwned.intro")}</p>
                <p>{t("objectsOwned.intro2")}</p>
            </div>
            <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                <Card>
                    <Table
                        dataSource={objects}
                        columns={columns}
                        rowKey="object_id"
                        loading={isLoading}
                        pagination={{
                            defaultPageSize: 50,
                            showSizeChanger: true,
                            pageSizeOptions: [50, 100, 500, 1000],
                        }}
                        className="border rounded"
                    />
                </Card>
            </Space>
            {res && <Card title={t("objectsOwned.responseTitle")}>{res}</Card>}
        </div>
    );
};

export default ObjectsOwnedList;
