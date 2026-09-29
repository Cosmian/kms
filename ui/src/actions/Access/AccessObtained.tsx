import { Button, Card, Space, Table, Tag } from "antd";
import React, { useCallback, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { useAuth } from "../../contexts/useAuth";
import { getNoTTLVRequest } from "../../utils/utils";

interface AccessRight {
    objectUid: string;
    objectState: string;
    owner: string;
    operations: string[];
}

const AccessObtainedList: React.FC = () => {
    const [isLoading, setIsLoading] = useState(false);
    const [accessRights, setAccessRights] = useState<AccessRight[]>([]);
    const [hasCreatePermission, setHasCreatePermission] = useState<boolean | undefined>(undefined);

    const [res, setRes] = useState<string | undefined>(undefined);
    const { serverUrl } = useAuth();
    const { t } = useTranslation("actions");
    const responseRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        if (res && responseRef.current) {
            responseRef.current.scrollIntoView({ behavior: "smooth" });
        }
    }, [res]);

    const columns = [
        {
            title: t("accessObtained.colObjectUid"),
            dataIndex: "object_id",
            key: "object_id",
        },
        {
            title: t("accessObtained.colState"),
            dataIndex: "state",
            key: "state",
            render: (state: string) => <Tag color={state === "Active" ? "green" : "orange"}>{state}</Tag>,
        },
        {
            title: t("accessObtained.colOwner"),
            dataIndex: "owner_id",
            key: "owner_id",
        },
        {
            title: t("accessObtained.colOperations"),
            dataIndex: "operations",
            key: "operations",
            render: (operations: string[]) => (
                <span>
                    {operations.map((op) => (
                        <Tag key={op} color="blue">
                            {op}
                        </Tag>
                    ))}
                </span>
            ),
        },
    ];

    const fetchAccessRights = useCallback(async () => {
        setIsLoading(true);
        setRes(undefined);
        setAccessRights([]);
        try {
            const response = await getNoTTLVRequest("/access/obtained", serverUrl);
            if (response.length) {
                setAccessRights(response);
            } else {
                setRes(t("accessObtained.emptyResult"));
            }
        } catch (e) {
            setRes(t("accessObtained.errorListing", { error: e }));
            console.error("Error listing objects:", e);
        } finally {
            setIsLoading(false);
        }
    }, [serverUrl, t]);

    const fetchCreatePermission = useCallback(async () => {
        setHasCreatePermission(undefined);
        try {
            const response = await getNoTTLVRequest("/access/create", serverUrl);
            setHasCreatePermission(response.has_create_permission);
        } catch (e) {
            console.error("Error fetching create permission:", e);
        }
    }, [serverUrl]);

    useEffect(() => {
        fetchAccessRights();
        fetchCreatePermission();
    }, [fetchAccessRights, fetchCreatePermission]);

    return (
        <div className="p-6">
            <div className="flex justify-between items-center mb-6">
                <h1 className="text-2xl font-bold ">{t("accessObtained.title")}</h1>
                <Button type="primary" onClick={fetchAccessRights} loading={isLoading} className="bg-primary">
                    {t("accessObtained.refresh")}
                </Button>
            </div>

            <div className="mb-8 space-y-2">
                <p>{t("accessObtained.intro")}</p>
            </div>
            <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                <Card>
                    <div className="mb-4 space-y-2">
                        <h3 className="text-m font-bold mb-4">{t("accessObtained.createAccessRight")}</h3>
                        <Tag color={hasCreatePermission ? "green" : "red"}>{t("common:create")}</Tag>
                        {t("accessObtained.createAccessStatus", {
                            status: hasCreatePermission ? t("accessObtained.youHave") : t("accessObtained.youDontHave"),
                        })}
                    </div>
                    <h3 className="text-m font-bold mb-4">{t("accessObtained.objectsAccessRights")}</h3>
                    <Table
                        dataSource={accessRights}
                        columns={columns}
                        rowKey="objectUid"
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
            {res && (
                <div ref={responseRef}>
                    <Card title={t("accessObtained.responseTitle")}>{res}</Card>
                </div>
            )}
        </div>
    );
};

export default AccessObtainedList;
