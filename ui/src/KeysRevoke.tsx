import { WarningFilled } from '@ant-design/icons'
import { Button, Card, Form, Input, Select, Space } from 'antd'
import React, { useState } from 'react'
import { sendKmipRequest } from './utils'
import { parse_revoke_ttlv_response, revoke_key_ttlv_request } from "./wasm/pkg"


interface RevokeKeyFormData {
    revocationReason: string;
    keyId?: string;
    tags?: string[];
}

type KeyType = 'rsa' | 'ec' | 'symmetric' | 'covercrypt';

interface KeyRevokeFormProps {
    key_type: KeyType;
}


type RevokeKeyResponse = {
    UniqueIdentifier: string,
}

const KeyRevokeForm: React.FC<KeyRevokeFormProps> = (props: KeyRevokeFormProps) => {
    const [form] = Form.useForm<RevokeKeyFormData>();
    const [res, setRes] = useState<undefined | string>(undefined);
    const [isLoading, setIsLoading] = useState(false);

    const onFinish = async (values: RevokeKeyFormData) => {
        console.log('Revoke key values:', values);
        setIsLoading(true);
        setRes(undefined);
        const id = values.keyId ? values.keyId : values.tags ? JSON.stringify(values.tags) : undefined;
        if (id == undefined) {
            setRes("Missing key identifier.")
            throw Error("Missing key identifier")
        }
        try {
            const request = revoke_key_ttlv_request(id , values.revocationReason);
            const result_str = await sendKmipRequest(request);
            if (result_str) {
                const result: RevokeKeyResponse = await parse_revoke_ttlv_response(result_str)
                setRes(`${result.UniqueIdentifier} has been revoked.`)
            }
        } catch (e) {
            setRes(`Error revoking key: ${e}`)
            console.error("Error revoking key:", e);
        } finally {
            setIsLoading(false);
        }
    };

    let key_type_string = '';
    if (props.key_type === 'rsa') {
        key_type_string = 'an RSA';
    } else if (props.key_type === 'ec') {
        key_type_string = 'an EC';
    } else if (props.key_type === 'covercrypt') {
        key_type_string = 'a CoverCrypt';
    } else {
        key_type_string = 'a symmetric';
    };

    return (
        <div className="p-6">
            <div className="flex items-center gap-3 mb-6">
                <WarningFilled className="text-2xl text-red-500" />
                <h1 className="text-2xl font-bold ">Revoke {key_type_string} key</h1>
            </div>

            <div className="mb-8 space-y-2">
                <div className="bg-red-200 border border-red-200 rounded-md p-4">
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
            >
                <Space direction="vertical" size="middle" style={{ display: 'flex' }}>
                    <Card>
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
                            />
                        </Form.Item>
                    </Card>
                    <Card>
                        <h3 className="text-m font-bold mb-4">Key Identification (required)</h3>

                        <Form.Item
                            name="keyId"
                            label="Key ID"
                            help="The unique identifier of the key to revoke"
                        >
                            <Input
                                placeholder="Enter key ID"
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
                                open={false}
                            />
                        </Form.Item>
                    </Card>

                    <Form.Item>
                        <Button
                            type="primary"
                            htmlType="submit"
                            loading={isLoading}
                            danger
                            className="w-full text-white font-medium"
                            >
                            Revoke Key
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            {res && <Card title="Key revoke response">{res}</Card>}
        </div>
    );
};

export default KeyRevokeForm;
