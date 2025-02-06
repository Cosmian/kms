import React from 'react';
import { Form, Input, Select, Button } from 'antd';

interface AccessRevokeFormData {
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

const AccessRevokeForm: React.FC = () => {
    const [form] = Form.useForm<AccessRevokeFormData>();

    const onFinish = (values: AccessRevokeFormData) => {
        console.log('Revoke access values:', values);
        // Handle form submission
    };

    return (
        <div className="bg-white rounded-lg shadow-md p-6 m-4">
            <h1 className="text-2xl font-bold text-gray-900 mb-6">Revoke access rights</h1>

            <div className="mb-8 text-gray-600 space-y-2">
                <p>Revoke access rights from a user for specific KMIP operations on an object.</p>
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
                    help="The user to revoke access from"
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
                    help="Select one or more operations to revoke access from"
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
                        danger
                        htmlType="submit"
                        className="w-full bg-red-600 hover:bg-red-700 border-0 rounded-md py-2 text-white font-medium"
                    >
                        Revoke Access
                    </Button>
                </Form.Item>
            </Form>
        </div>
    );
};

export default AccessRevokeForm;
