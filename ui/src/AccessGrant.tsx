import React from 'react';
import { Form, Input, Select, Button } from 'antd';

interface AccessGrantFormData {
    user: string;
    objectUid: string;
    operations: Array<
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

    const onFinish = (values: AccessGrantFormData) => {
        console.log('Grant access values:', values);
        // Handle form submission
    };

    return (
        <div className="bg-white rounded-lg shadow-md p-6 m-4">
            <h1 className="text-2xl font-bold text-gray-900 mb-6">Grant access rights</h1>

            <div className="mb-8 text-gray-600 space-y-2">
                <p>Grant access rights to another user for specific KMIP operations on an object.</p>
                <p>This action can only be performed by the owner of the object.</p>
            </div>

            <Form
                form={form}
                onFinish={onFinish}
                layout="vertical"
                className="space-y-6"
            >
                <Form.Item
                    name="user"
                    label="User Identifier"
                    rules={[{ required: true, message: 'Please enter the user identifier' }]}
                    help="The user to grant access to"
                >
                    <Input placeholder="Enter user identifier" />
                </Form.Item>

                <Form.Item
                    name="objectUid"
                    label="Object UID"
                    rules={[{ required: true, message: 'Please enter the object UID' }]}
                    help="The unique identifier of the object stored in the KMS"
                >
                    <Input placeholder="Enter object UID" />
                </Form.Item>

                <Form.Item
                    name="operations"
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

                <Form.Item>
                    <Button
                        type="primary"
                        htmlType="submit"
                        className="w-full bg-blue-600 hover:bg-blue-700 border-0 rounded-md py-2 text-white font-medium"
                    >
                        Grant Access
                    </Button>
                </Form.Item>
            </Form>
        </div>
    );
};

export default AccessGrantForm;
