import { WarningFilled } from '@ant-design/icons'
import { Button, Card, Checkbox, Form, Input, Select, Space } from 'antd'
import React, { useState } from 'react'
import { sendKmipRequest } from './utils'
import { destroy_ttlv_request, parse_destroy_ttlv_response } from "./wasm/pkg"


interface DestroyKeyFormData {
    keyId?: string;
    tags?: string[];
    remove: boolean;
}

type KeyType = 'rsa' | 'ec' | 'symmetric' | 'covercrypt';

interface DestroyKeyFormProps {
    key_type: KeyType;
}

type DestroyKeyResponse = {
    UniqueIdentifier: string,
}

const KeyDestroyForm: React.FC<DestroyKeyFormProps> = (props: DestroyKeyFormProps) => {
    const [form] = Form.useForm<DestroyKeyFormData>();
    const [res, setRes] = useState<undefined | string>(undefined);
    const [isLoading, setIsLoading] = useState(false);

    const onFinish = async (values: DestroyKeyFormData) => {
        setIsLoading(true);
        setRes(undefined);
        console.log('Destroy key values:', values);
        const id = values.keyId ? values.keyId : values.tags ? JSON.stringify(values.tags) : undefined;
        if (id == undefined) {
            setRes("Missing key identifier.")
            throw Error("Missing key identifier")
        }
        try {
            const request = destroy_ttlv_request(id, values.remove);
            const result_str = await sendKmipRequest(request);
            if (result_str) {
                const result: DestroyKeyResponse = await parse_destroy_ttlv_response(result_str)
                setRes(`${result.UniqueIdentifier} has been destroyed.`)
            }
        } catch (e) {
            setRes(`Error destroyin key: ${e}`)
            console.error("Error destroyin key:", e);
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
        key_type_string = 'a Covercrypt';
    } else {
        key_type_string = 'a symmetric';
    };

    return (
        <div className="p-6">
            <div className="flex items-center gap-3 mb-6">
                <WarningFilled className="text-2xl text-red-600" />
                <h1 className="text-2xl font-bold ">Destroy {key_type_string} key</h1>
            </div>

            <div className="mb-8 space-y-2">
                <div className="bg-red-200 border-l-4 border-red-600 rounded-md p-4">
                    <div className="text-red-800 text-sm space-y-2">
                        <p className="font-bold">Warning: This is a destructive action!</p>
                        <ul className="list-disc pl-5 space-y-1">
                            <li>The key must be revoked first</li>
                            {props.key_type === 'rsa' || props.key_type === 'ec' || props.key_type === 'covercrypt' ? (
                                <li>Destroying either public or private key will destroy the whole key pair</li>
                            ) : null}
                            <li>Keys in external stores (HSMs) are automatically removed</li>
                            <li>Destroyed keys can only be exported by the owner, without key material</li>
                        </ul>
                    </div>
                </div>
            </div>

            <Form
                form={form}
                onFinish={onFinish}
                layout="vertical"
                initialValues={{
                    remove: false,
                }}
            >
                <Space direction="vertical" size="middle" style={{ display: 'flex' }}>
                    <Card>
                        <h3 className="text-m font-bold mb-4">Key Identification (required)</h3>

                        <Form.Item
                            name="keyId"
                            label="Key ID"
                            help="The unique identifier of the key to destroy"
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
                    <Card>
                        <Form.Item
                            name="remove"
                            valuePropName="checked"
                            help="If enabled, the key will be completely removed from the database. Otherwise, metadata will be retained."
                        >
                            <Checkbox>
                                Remove completely from database
                            </Checkbox>
                        </Form.Item>
                    </Card>
                    <Form.Item>
                    <Button
                            type="primary"
                            htmlType="submit"
                            loading={isLoading}
                            danger
                            disabled={isLoading}
                            className="w-full text-white font-medium"
                        >
                            Destroy Key
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            {res && <div>{res}</div>}
        </div>
    );
};

export default KeyDestroyForm;
