import { Button, Card, Form, Input, Space, Table } from "antd";
import React, { useEffect, useRef, useState } from "react";
import { useAuth } from "./AuthContext";
import { getNoTTLVRequest } from "./utils";

interface AccessListFormData {
    unique_identifier: string;
}

interface AccessRight {
    user_id: string;
    operations: string[];
}

const AccessListForm: React.FC = () => {
    const [form] = Form.useForm<AccessListFormData>();
    const [accessRights, setAccessRights] = useState<AccessRight[]>([]);
    const [isLoading, setIsLoading] = useState(false);
    const [res, setRes] = useState<string | undefined>(undefined);
    const { idToken, serverUrl } = useAuth();
    const responseRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        if (res && responseRef.current) {
            responseRef.current.scrollIntoView({ behavior: "smooth" });
        }
    }, [res]);

    const onFinish = async (values: AccessListFormData) => {
        console.log("List access values:", values);
        setIsLoading(true);
        setRes(undefined);
        setAccessRights([]);
        try {
            const response = await getNoTTLVRequest(`/access/list/${values.unique_identifier}`, idToken, serverUrl);
            if (response.length) {
                setAccessRights(response);
            } else {
                setRes("Empty result - no access granted.");
            }
        } catch (e) {
            setRes(`Error listing access right: ${e}`);
            console.error("Error listing access right:", e);
        } finally {
            setIsLoading(false);
        }
    };

    const columns = [
        {
            title: "User",
            dataIndex: "user_id",
            key: "user_id",
        },
        {
            title: "Granted Operations",
            dataIndex: "operations",
            key: "operations",
            render: (operations: string[]) => operations.join(", "),
        },
    ];

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">List an object access rights</h1>

            <div className="mb-8 space-y-2">
                <p>View all access rights granted on an object.</p>
                <p>This action can only be performed by the owner of the object.</p>
            </div>

            <Form form={form} onFinish={onFinish} layout="vertical">
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <Form.Item
                            name="unique_identifier"
                            label="Object UID"
                            rules={[{ required: true, message: "Please enter the object UID" }]}
                            help="The unique identifier of the object stored in the KMS"
                        >
                            <Input placeholder="Enter object UID" />
                        </Form.Item>
                    </Card>
                    <Form.Item>
                        <Button type="primary" htmlType="submit" loading={isLoading} className="w-full text-white font-medium">
                            List Access Right
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            {res && (
                <div ref={responseRef}>
                    <Card title="List access response">{res}</Card>
                </div>
            )}

            {accessRights.length > 0 && (
                <div className="mt-8" ref={responseRef}>
                    <Card title="Access Rights">
                        <Table dataSource={accessRights} columns={columns} rowKey="user_id" pagination={false} />
                    </Card>
                </div>
            )}
        </div>
    );
};

export default AccessListForm;
