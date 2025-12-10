import { Button, Card, Space, Table, Tag } from "antd";
import React, { useCallback, useEffect, useRef, useState } from "react";
import { useAuth } from "./AuthContext";
import { getNoTTLVRequest } from "./utils";

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
    const { idToken, serverUrl } = useAuth();
    const responseRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        if (res && responseRef.current) {
            responseRef.current.scrollIntoView({ behavior: "smooth" });
        }
    }, [res]);

    const columns = [
        {
            title: "Object UID",
            dataIndex: "object_id",
            key: "object_id",
        },
        {
            title: "State",
            dataIndex: "state",
            key: "state",
            render: (state: string) => <Tag color={state === "Active" ? "green" : "orange"}>{state}</Tag>,
        },
        {
            title: "Owner",
            dataIndex: "owner_id",
            key: "owner_id",
        },
        {
            title: "Granted Operations",
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
            const response = await getNoTTLVRequest("/access/obtained", idToken, serverUrl);
            if (response.length) {
                setAccessRights(response);
            } else {
                setRes("Empty result - no access obtained.");
            }
        } catch (e) {
            setRes(`Error listing objects: ${e}`);
            console.error("Error listing objects:", e);
        } finally {
            setIsLoading(false);
        }
    }, [idToken, serverUrl]);

    const fetchCreatePermission = useCallback(async () => {
        setHasCreatePermission(undefined);
        try {
            const response = await getNoTTLVRequest("/access/create", idToken, serverUrl);
            setHasCreatePermission(response.has_create_permission);
        } catch (e) {
            console.error("Error fetching create permission:", e);
        }
    }, [idToken, serverUrl]);

    useEffect(() => {
        // Avoid unauthenticated calls in JWT mode: wait for token
        if (idToken) {
            fetchAccessRights();
            fetchCreatePermission();
        } else {
            setAccessRights([]);
            setHasCreatePermission(undefined);
        }
    }, [fetchAccessRights, fetchCreatePermission, idToken]);

    return (
        <div className="p-6">
            <div className="flex justify-between items-center mb-6">
                <h1 className="text-2xl font-bold ">Access rights obtained</h1>
                <Button type="primary" onClick={fetchAccessRights} loading={isLoading} className="bg-primary">
                    Refresh
                </Button>
            </div>

            <div className="mb-8 space-y-2">
                <p>
                    List of objects you have been granted access to, along with their current state, owner, and the operations you can
                    perform.
                </p>
            </div>
            <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                <Card>
                    <div className="mb-4 space-y-2">
                        <h3 className="text-m font-bold mb-4">Create access right</h3>
                        <Tag color={hasCreatePermission ? "green" : "red"}>Create</Tag>
                        {hasCreatePermission ? "You have" : "You don't have"} Create access right, enabling object creation and import from
                        KMS.
                    </div>
                    <h3 className="text-m font-bold mb-4">Objects access rights</h3>
                    <Table
                        dataSource={accessRights}
                        columns={columns}
                        rowKey="objectUid"
                        loading={isLoading}
                        pagination={{ pageSize: 10 }}
                        className="border rounded"
                    />
                </Card>
            </Space>
            {res && (
                <div ref={responseRef}>
                    <Card title="Obtained access response">{res}</Card>
                </div>
            )}
        </div>
    );
};

export default AccessObtainedList;
