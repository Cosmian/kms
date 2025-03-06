import { Button, Card, Form, Input, Select, Space } from 'antd'
import React, { useEffect, useRef, useState } from 'react'
import { useAuth } from "./AuthContext"
import { postNoTTLVRequest } from './utils'


interface AccessRevokeFormData {
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

const AccessRevokeForm: React.FC = () => {
    const [form] = Form.useForm<AccessRevokeFormData>();
    const [res, setRes] = useState<undefined | string>(undefined);
    const [isLoading, setIsLoading] = useState(false);
    const { idToken, serverUrl } = useAuth();
    const responseRef = useRef<HTMLDivElement>(null);
    useEffect(() => {
        if (res && responseRef.current) {
            responseRef.current.scrollIntoView({ behavior: 'smooth' });
        }
    }, [res]);


    const onFinish = async (values: AccessRevokeFormData) => {
        console.log('Revoke access values:', values);
        setIsLoading(true);
        setRes(undefined);


        try {
            const response = await postNoTTLVRequest("/access/revoke", values, idToken, serverUrl);
            setRes(response.success)
        } catch (e) {
            setRes(`Error revoking access: ${e}`)
            console.error("Error revoking access:", e);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">Revoke access rights</h1>

            <div className="mb-8 space-y-2">
                <p>Revoke access rights from a user for specific KMIP operations on an object.</p>
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
                            help="The user to revoke access from"
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
                            help="Select one or more operations to revoke access from"
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
                            danger
                            htmlType="submit"
                            loading={isLoading}
                            className="w-full text-white font-medium"
                        >
                            Revoke Access
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            {res && (
                <div ref={responseRef}>
                    <Card title="Revoke access response">{res}</Card>
                </div>
            )}
        </div>
    );
};

export default AccessRevokeForm;
