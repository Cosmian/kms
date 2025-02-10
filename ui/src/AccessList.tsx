import { Button, Form, Input, Table } from 'antd'
import React, { useState } from 'react'
import { getNoTTLVRequest } from './utils'


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

    const onFinish = async (values: AccessListFormData) => {
        console.log('List access values:', values);
        setIsLoading(true);
        setRes(undefined);
        setAccessRights([])
        try {
            const response = await getNoTTLVRequest(`/access/list/${values.unique_identifier}`);
            if (response.length) {
                setAccessRights(response);
            } else {
                setRes("Empty result");
            }

        } catch (e) {
            setRes(`Error listing access right: ${e}`)
            console.error("Error listing access right:", e);
        } finally {
            setIsLoading(false);
        }
    };

    const columns = [
        {
            title: 'User',
            dataIndex: 'user_id',
            key: 'user_id',
        },
        {
            title: 'Granted Operations',
            dataIndex: 'operations',
            key: 'operations',
            render: (operations: string[]) => operations.join(', '),
        },
    ];

    return (
        <div className="bg-white rounded-lg shadow-md p-6 m-4">
            <h1 className="text-2xl font-bold  mb-6">List an object access rights</h1>

            <div className="mb-8 text-gray-600 space-y-2">
                <p>View all access rights granted on an object.</p>
                <p>This action can only be performed by the owner of the object.</p>
            </div>

            <Form
                form={form}
                onFinish={onFinish}
                layout="vertical"
                className="space-y-6"
            >
                <Form.Item
                    name="unique_identifier"
                    label="Object UID"
                    rules={[{ required: true, message: 'Please enter the object UID' }]}
                    help="The unique identifier of the object stored in the KMS"
                >
                    <Input placeholder="Enter object UID" />
                </Form.Item>

                <Form.Item>
                    <Button
                        type="primary"
                        htmlType="submit"
                        loading={isLoading}
                        className="w-full bg-primary hover:bg-blue-700 border-0 rounded-md py-2 text-white font-medium"
                    >
                        List Access Right
                    </Button>
                </Form.Item>
            </Form>
            {res && <div>{res}</div>}

            {accessRights.length > 0 && (
                <div className="mt-8">
                    <h2 className="text-lg font-semibold mb-4">Access Rights</h2>
                    <Table
                        dataSource={accessRights}
                        columns={columns}
                        rowKey="user_id"
                        pagination={false}
                    />
                </div>
            )}
        </div>
    );
};

export default AccessListForm;
