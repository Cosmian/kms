import { Button, Card, Checkbox, Form, Input, Select, Space } from 'antd'
import React, { useEffect, useRef, useState } from 'react'
import { useAuth } from "./AuthContext"
import { sendKmipRequest } from './utils'
import { create_covercrypt_user_key_ttlv_request, parse_create_ttlv_response } from "./wasm/pkg"

interface CovercryptUserKeyFormData {
    masterPrivateKeyId: string;
    accessPolicy: string;
    tags: string[];
    sensitive: boolean;
}

const POLICY_EXAMPLE = `Department::HR && Security Level::Confidential

More examples:
(Department::MKG && Security Level::Confidential) || (Department::HR && Security Level::Protected)`;

const CovercryptUserKeyForm: React.FC = () => {
    const [form] = Form.useForm<CovercryptUserKeyFormData>();
    const [res, setRes] = useState<undefined | string>(undefined);
    const [isLoading, setIsLoading] = useState(false);
    const { idToken, serverUrl  } = useAuth();
    const responseRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        if (res && responseRef.current) {
            responseRef.current.scrollIntoView({ behavior: 'smooth' });
        }
    }, [res]);

    const onFinish = async (values: CovercryptUserKeyFormData) => {
        console.log('Create user key values:', values);
        setIsLoading(true);
        setRes(undefined);
        try {
            const request = create_covercrypt_user_key_ttlv_request(values.masterPrivateKeyId, values.accessPolicy, values.tags, values.sensitive);
            const result_str = await sendKmipRequest(request, idToken, serverUrl);
            if (result_str) {
                const result = await parse_create_ttlv_response(result_str)
                setRes(`${result.UniqueIdentifier} has been created.`)
            }
        } catch (e) {
            setRes(`${e}`)
            console.error(e);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">Create a Covercrypt user key</h1>

            <div className="mb-8 space-y-2">
                <p>Create a new user decryption key with specific access rights.</p>
                <p>The access policy is a boolean expression combining policy attributes.</p>
            </div>

            <Form
                form={form}
                onFinish={onFinish}
                layout="vertical"
                initialValues={{
                    sensitive: false,
                    tags: []
                }}
            >
                <Space direction="vertical" size="middle" style={{ display: 'flex' }}>
                    <Card>
                        <div className="p-4 rounded-lg space-y-4">
                            <h3 className="text-m font-bold mb-4">Key Configuration</h3>

                            <Form.Item
                                name="masterPrivateKeyId"
                                label="Master Private Key ID"
                                help="The unique identifier of the master private key"
                                rules={[{ required: true, message: 'Please enter master private key ID' }]}
                            >
                                <Input placeholder="Enter master private key ID" />
                            </Form.Item>

                            <Form.Item
                                name="accessPolicy"
                                label="Access Policy"
                                help={
                                    <div className="text-sm space-y-2">
                                        <p>Boolean expression combining policy attributes</p>
                                        <div className="p-3 rounded">
                                            <p className="font-medium mb-2">Example formats:</p>
                                            <pre className="text-xs whitespace-pre-wrap">{POLICY_EXAMPLE}</pre>
                                            <p className="mt-2 text-xs">Note: A user with "Confidential" access will also have access to "Protected" data due to hierarchy.</p>
                                        </div>
                                        <ul className="list-disc pl-5 mt-2 space-y-1">
                                            <li>Use <code>&&</code> for AND, <code>||</code> for OR</li>
                                            <li>Group expressions with parentheses</li>
                                            <li>Use exact attribute names from the policy</li>
                                        </ul>
                                    </div>
                                }
                                rules={[{ required: true, message: 'Please enter access policy' }]}
                            >
                                <Input.TextArea
                                    placeholder="Enter access policy expression"
                                    rows={4}
                                    className="font-mono text-sm"
                                />
                            </Form.Item>
                        </div>
                    </Card>
                    <Card>
                        <Form.Item
                        name="tags"
                        label="Tags"
                        help="Optional tags to help retrieve the key later"
                        >
                            <Select
                                mode="tags"
                                placeholder="Enter tags"
                                open={false}
                            />
                        </Form.Item>

                        <Form.Item
                            name="sensitive"
                            valuePropName="checked"
                            help="If enabled, the key will not be exportable"
                        >
                            <Checkbox>
                                <span>Sensitive Key</span>
                            </Checkbox>
                        </Form.Item>
                    </Card>
                    <Form.Item>
                        <Button
                            type="primary"
                            htmlType="submit"
                            loading={isLoading}
                            className="w-full text-white font-medium"
                        >
                            Create User Key
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            {res && (
                <div ref={responseRef}>
                    <Card title="Covercrypt User key creation response">{res}</Card>
                </div>
            )}
        </div>
    );
};

export default CovercryptUserKeyForm;
