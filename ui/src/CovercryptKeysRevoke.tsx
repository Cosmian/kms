import React from 'react';
import { Form, Input, Select, Button } from 'antd';
import { WarningFilled } from '@ant-design/icons';

interface CovercryptRevokeFormData {
    keyId?: string;
    tags?: string[];
    revocationReason: string;
}

const CovercryptRevokeForm: React.FC = () => {
    const [form] = Form.useForm<CovercryptRevokeFormData>();

    const onFinish = (values: CovercryptRevokeFormData) => {
        console.log('Revoke key values:', values);
        // Handle form submission
    };

    return (
        <div className="bg-white rounded-lg shadow-md p-6 m-4">
            <div className="flex items-center gap-3 mb-6">
                <WarningFilled className="text-2xl text-red-500" />
                <h1 className="text-2xl font-bold text-gray-900">Revoke a Covercrypt key</h1>
            </div>

            <div className="mb-8 space-y-2">
                <div className="bg-red-50 border border-red-200 rounded-md p-4">
                    <div className="text-red-800 text-sm space-y-2">
                        <p><strong>Warning:</strong> This action cannot be undone.</p>
                        <ul className="list-disc pl-5 space-y-1">
                            <li>Once revoked, a key can only be exported by its owner using the --allow-revoked flag</li>
                            <li>Revoking a master key will revoke the entire key pair and all associated user keys</li>
                            <li>Revoked user keys will no longer be rekeyed during attribute rotation</li>
                            <li>Using tags for revocation will fail if multiple keys match</li>
                        </ul>
                    </div>
                </div>
            </div>

            <Form
                form={form}
                onFinish={onFinish}
                layout="vertical"
                className="space-y-6"
            >
                <div className="bg-gray-50 p-4 rounded-lg space-y-4">
                    <h3 className="text-sm font-medium text-gray-700">Key Identification (required)</h3>
                    <Form.Item
                        name="keyId"
                        label="Key ID"
                        help="The unique identifier of the key to revoke"
                    >
                        <Input placeholder="Enter key ID" />
                    </Form.Item>

                    <Form.Item
                        name="tags"
                        label="Tags"
                        help="Alternative to Key ID: specify tags to identify the key (must match exactly one key)"
                    >
                        <Select
                            mode="tags"
                            placeholder="Enter tags"
                            open={false}
                        />
                    </Form.Item>
                </div>

                <Form.Item
                    name="revocationReason"
                    label="Revocation Reason"
                    help="Provide a reason for revoking this key"
                    rules={[{ required: true, message: 'Please provide a revocation reason' }]}
                >
                    <Input.TextArea
                        placeholder="Enter reason for revocation"
                        rows={3}
                    />
                </Form.Item>

                <Form.Item>
                    <Button
                        type="primary"
                        danger
                        htmlType="submit"
                        className="w-full border-0 rounded-md py-2 font-medium"
                    >
                        Revoke Key
                    </Button>
                </Form.Item>
            </Form>
        </div >
    );
};

export default CovercryptRevokeForm;
