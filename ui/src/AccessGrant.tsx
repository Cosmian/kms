import { Button, Card, Form, Input, Select, Space } from 'antd'
import React, { useState } from 'react'
import { postNoTTLVRequest } from './utils'


interface AccessGrantFormData {
    user_id: string;
    unique_identifier: string;
    operation_types: Array<
        | 'create'
        | 'get'
        | 'encrypt'
        | 'decrypt'
        | 'import'
        | 'revoke'
        | 'locate'
        | 'rekey'
        | 'destroy'
    >;
}

const KMIP_OPERATIONS = [
    { label: 'Create', value: 'create' },
    { label: 'Get', value: 'get' },
    { label: 'Encrypt', value: 'encrypt' },
    { label: 'Decrypt', value: 'decrypt' },
    { label: 'Import', value: 'import' },
    { label: 'Revoke', value: 'revoke' },
    { label: 'Locate', value: 'locate' },
    { label: 'Rekey', value: 'rekey' },
    { label: 'Destroy', value: 'destroy' },
];

const AccessGrantForm: React.FC = () => {
    const [form] = Form.useForm<AccessGrantFormData>();
    const [res, setRes] = useState<undefined | string>(undefined);
    const [isLoading, setIsLoading] = useState(false);

    const onFinish = async (values: AccessGrantFormData) => {
        console.log('Grant access values:', values);
        setIsLoading(true);
        setRes(undefined);
        try {
            const response = await postNoTTLVRequest("/access/grant", values);
            setRes(response.success)
        } catch (e) {
            setRes(`Error granting access: ${e}`)
            console.error("Error granting access:", e);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">Grant access rights</h1>

            <div className="mb-8 space-y-2">
                <p>Grant access rights to another user for specific KMIP operations on an object.</p>
                <p>This action can only be performed by the owner of the object.</p>
            </div>

            <Form
                form={form}
                onFinish={onFinish}
                layout="vertical"
            >
                <Space direction="vertical" size="middle" style={{ display: 'flex' }}>
                    <Card>
                        <Form.Item
                            name="user_id"
                            label="User Identifier"
                            rules={[{ required: true, message: 'Please enter the user identifier' }]}
                            help="The user to grant access to"
                        >
                            <Input placeholder="Enter user identifier" />
                        </Form.Item>

                        <Form.Item
                            name="unique_identifier"
                            label="Object UID"
                            rules={[{ required: true, message: 'Please enter the object UID' }]}
                            help="The unique identifier of the object stored in the KMS"
                        >
                            <Input placeholder="Enter object UID" />
                        </Form.Item>

                        <Form.Item
                            name="operation_types"
                            label="KMIP Operations"
                            rules={[{ required: true, message: 'Please select at least one operation' }]}
                            help="Select one or more operations to grant access to"
                        >
                            <Select
                                mode="multiple"
                                options={KMIP_OPERATIONS}
                                placeholder="Select operations"
                            />
                        </Form.Item>
                    </Card>
                    <Form.Item>
                        <Button
                            type="primary"
                            htmlType="submit"
                            loading={isLoading}
                            className="w-full text-white font-medium"
                        >
                            Grand Access
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            {res && <Card title="Grant access response">{res}</Card>}
        </div>
    );
};

export default AccessGrantForm;
