import React from 'react';
import { Form, Input, Select, Button } from 'antd';
import { WarningFilled } from '@ant-design/icons';

interface RevokeKeyFormData {
    revocationReason: string;
    keyId?: string;
    tags?: string[];
}

type KeyType = 'rsa' | 'ec' | 'symmetric';

interface KeyRevokeFormProps {
    key_type: KeyType;
}
const KeyRevokeForm: React.FC<KeyRevokeFormProps> = (props: KeyRevokeFormProps) => {
    const [form] = Form.useForm<RevokeKeyFormData>();

    const onFinish = (values: RevokeKeyFormData) => {
        console.log('Revoke key values:', values);
        // Handle form submission
    };

    let key_type_string = '';
    if (props.key_type === 'rsa') {
        key_type_string = 'an RSA';
    } else if (props.key_type === 'ec') {
        key_type_string = 'an EC';
    } else {
        key_type_string = 'a symmetric';
    };

    return (
        <div className="bg-white rounded-lg shadow-md p-6 m-4">
            <div className="flex items-center gap-3 mb-6">
                <WarningFilled className="text-2xl text-red-500" />
                <h1 className="text-2xl font-bold text-gray-900">Revoke {key_type_string} key</h1>
            </div>

            <div className="mb-8 space-y-2">
                <div className="bg-red-50 border border-red-200 rounded-md p-4">
                    <div className="text-red-800 text-sm space-y-2">
                        <p><strong>Warning:</strong> This action cannot be undone.</p>
                        <p>Once a key is revoked, it can only be exported by the owner by checking the <i>allow-revoked</i> flag.</p>
                        {props.key_type === 'rsa' || props.key_type === 'ec' ? (
                            <p>Revoking either the public or private key will revoke the whole key pair.</p>
                        ) : null}
                    </div>
                </div>
            </div>

            <Form
                form={form}
                onFinish={onFinish}
                layout="vertical"
                className="space-y-6"
            >
                <Form.Item
                    name="revocationReason"
                    label="Revocation Reason"
                    rules={[{
                        required: true,
                        message: 'Please specify the reason for revocation'
                    }]}
                    help="Provide a clear reason for revoking this key"
                >
                    <Input.TextArea
                        placeholder="Enter the reason for revocation"
                        rows={3}
                        className="max-w-[500px]"
                    />
                </Form.Item>

                <div className="bg-gray-50 p-4 rounded-lg space-y-4">
                    <h3 className="text-sm font-medium text-gray-700">Key Identification (required)</h3>

                    <Form.Item
                        name="keyId"
                        label="Key ID"
                        help="The unique identifier of the key to revoke"
                    >
                        <Input
                            placeholder="Enter key ID"
                            className="max-w-[500px]"
                        />
                    </Form.Item>

                    <Form.Item
                        name="tags"
                        label="Tags"
                        help="Alternative to Key ID: specify tags to identify the key"
                    >
                        <Select
                            mode="tags"
                            placeholder="Enter tags"
                            className="max-w-[500px]"
                            open={false}
                        />
                    </Form.Item>
                </div>

                <Form.Item>
                    <Button
                        type="primary"
                        htmlType="submit"
                        danger
                        className="w-full bg-red-600 hover:bg-red-700 border-0 rounded-md py-2 text-white font-medium"
                    >
                        Revoke Key
                    </Button>
                </Form.Item>
            </Form>
        </div>
    );
};

export default KeyRevokeForm;
