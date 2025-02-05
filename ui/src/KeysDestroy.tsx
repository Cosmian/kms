import { LoadingOutlined, WarningFilled } from '@ant-design/icons'
import { Button, Checkbox, Form, Input, Select, Spin } from 'antd'
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
        const id = values.keyId ? values.keyId : values.tags ? JSON.stringify(values.tags) : undefined; // TODO: check tags handling for revokation
        if (id == undefined) {
            setRes("Missing key identifier.")
            throw Error("Missing key identifier")
        }
        const request = destroy_ttlv_request(id, values.remove);
        try {
            const result_str = await sendKmipRequest(request);
            if (result_str) {
                const result: DestroyKeyResponse = await parse_destroy_ttlv_response(result_str)
                setRes(`${result.UniqueIdentifier} has been destroyed.`)
            }
        } catch (e) {
            setRes(`${e}`)
            console.error(e);
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
        <div className="bg-white rounded-lg shadow-md p-6 m-4">
            <div className="flex items-center gap-3 mb-6">
                <WarningFilled className="text-2xl text-red-600" />
                <h1 className="text-2xl font-bold text-gray-900">Destroy {key_type_string} key</h1>
            </div>

            <div className="mb-8 space-y-2">
                <div className="bg-red-50 border-l-4 border-red-600 rounded-md p-4">
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
                className="space-y-6"
            >
                <div className="bg-gray-50 p-4 rounded-lg space-y-4">
                    <h3 className="text-sm font-medium text-gray-700">Key Identification (required)</h3>

                    <Form.Item
                        name="keyId"
                        label="Key ID"
                        help="The unique identifier of the key to destroy"
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

                <Form.Item
                    name="remove"
                    valuePropName="checked"
                    help="If enabled, the key will be completely removed from the database. Otherwise, metadata will be retained."
                >
                    <Checkbox>
                        Remove completely from database
                    </Checkbox>
                </Form.Item>

                <div className="pt-4">
                    <Form.Item>
                    <Button
                            type="primary"
                            htmlType="submit"
                            danger
                            disabled={isLoading}
                            className="w-full bg-red-600 hover:bg-red-700 border-0 rounded-md py-2 text-white font-medium"
                        >
                            {isLoading ? (
                                <Spin
                                    indicator={<LoadingOutlined style={{ fontSize: 24, color: 'white' }} spin />}
                                />
                            ) : (
                                'Destroy Key'
                            )}
                        </Button>
                    </Form.Item>
                </div>
            </Form>
            {res && <div>{res}</div>}
        </div>
    );
};

export default KeyDestroyForm;
