import { Button, Card, Form, Input, Space, Table } from "antd";
import React, { useState } from "react";
import { getNoTTLVRequest } from "../../utils/utils";
import { useActionState } from "../../hooks/useActionState";
import { ActionResponse } from "../../components/common/ActionResponse";

interface AccessListFormData {
    unique_identifier: string;
}

interface AccessRight {
    user_id: string;
    operations: string[];
}

const AccessListForm: React.FC = () => {
    const [form] = Form.useForm<AccessListFormData>();
    const { res, isLoading, responseRef, serverUrl, execute } = useActionState();
    const [accessRights, setAccessRights] = useState<AccessRight[]>([]);

    const onFinish = async (values: AccessListFormData) => {
        setAccessRights([]);
        await execute(async () => {
            const response = await getNoTTLVRequest(`/access/list/${values.unique_identifier}`, serverUrl);
            if (response.length) {
                setAccessRights(response);
            } else {
                return "Empty result - no access granted.";
            }
        });
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
                        <Button
                            type="primary"
                            htmlType="submit"
                            loading={isLoading}
                            className="w-full text-white font-medium"
                            data-testid="submit-btn"
                        >
                            List Access Rights
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            <ActionResponse res={res} responseRef={responseRef} title="List access response" />

            {accessRights.length > 0 && (
                <div className="mt-8" ref={responseRef} data-testid="response-output">
                    <Card title="Access Rights">
                        <Table dataSource={accessRights} columns={columns} rowKey="user_id" pagination={false} />
                    </Card>
                </div>
            )}
        </div>
    );
};

export default AccessListForm;
