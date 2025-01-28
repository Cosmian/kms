import React, { useState } from 'react';
import { Form, Input, Button, Table } from 'antd';

interface AccessListFormData {
    objectUid: string;
}

interface AccessRight {
    user: string;
    operations: string[];
}

const AccessListForm: React.FC = () => {
    const [form] = Form.useForm<AccessListFormData>();
    const [accessRights, setAccessRights] = useState<AccessRight[]>([]);
    const [loading, setLoading] = useState(false);

    const onFinish = (values: AccessListFormData) => {
        setLoading(true);
        console.log('List access values:', values);
        // Handle form submission and update accessRights
        setLoading(false);
    };

    const columns = [
        {
            title: 'User',
            dataIndex: 'user',
            key: 'user',
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
            <h1 className="text-2xl font-bold text-gray-900 mb-6">List an object access rights</h1>

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
                    name="objectUid"
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
                        loading={loading}
                        className="w-full bg-blue-600 hover:bg-blue-700 border-0 rounded-md py-2 text-white font-medium"
                    >
                        List Access Rights
                    </Button>
                </Form.Item>
            </Form>

            {accessRights.length > 0 && (
                <div className="mt-8">
                    <h2 className="text-lg font-semibold mb-4">Access Rights</h2>
                    <Table
                        dataSource={accessRights}
                        columns={columns}
                        rowKey="user"
                        pagination={false}
                    />
                </div>
            )}
        </div>
    );
};

export default AccessListForm;
