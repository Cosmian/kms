import { Button, Card, Checkbox, Form, Input, InputNumber, Select, Space } from "antd";
import React, { useEffect, useRef, useState } from "react";
import { useAuth } from "./AuthContext";
import { sendKmipRequest } from "./utils";
import { create_rsa_key_pair_ttlv_request, parse_create_keypair_ttlv_response } from "./wasm/pkg";

interface RsaKeyCreateFormData {
    privateKeyId?: string;
    sizeInBits: number;
    tags: string[];
    sensitive: boolean;
    wrappingKeyId?: string;
}

type CreateKeyPairResponse = {
    PrivateKeyUniqueIdentifier: string;
    PublicKeyUniqueIdentifier: string;
};

const RsaKeyCreateForm: React.FC = () => {
    const [form] = Form.useForm<RsaKeyCreateFormData>();
    const [res, setRes] = useState<undefined | string>(undefined);
    const [isLoading, setIsLoading] = useState(false);
    const { idToken, serverUrl } = useAuth();
    const responseRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        if (res && responseRef.current) {
            responseRef.current.scrollIntoView({ behavior: "smooth" });
        }
    }, [res]);

    const onFinish = async (values: RsaKeyCreateFormData) => {
        setIsLoading(true);
        setRes(undefined);
        try {
            const request = create_rsa_key_pair_ttlv_request(
                values.privateKeyId,
                values.tags,
                values.sizeInBits,
                values.sensitive,
                values.wrappingKeyId
            );
            const result_str = await sendKmipRequest(request, idToken, serverUrl);
            if (result_str) {
                const result: CreateKeyPairResponse = await parse_create_keypair_ttlv_response(result_str);
                setRes(
                    `Key pair has been created. Private key Id: ${result.PrivateKeyUniqueIdentifier} - Public key Id: ${result.PublicKeyUniqueIdentifier}`
                );
            }
        } catch (e) {
            setRes(`Error creating keypair: ${e}`);
            console.error("Error creating keypair:", e);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">Create an RSA key pair</h1>

            <div className="mb-8 space-y-2">
                <p>Create a new RSA key pair:</p>
                <ul className="list-disc pl-5 space-y-1">
                    <li>The public key is used to encrypt or verify signatures and can be safely shared.</li>
                    <li>The private key is used to decrypt or sign and must be kept secret.</li>
                </ul>
                <p>When creating a key pair with a specified tag, the tag is applied to both keys.</p>
            </div>

            <Form
                form={form}
                onFinish={onFinish}
                layout="vertical"
                initialValues={{
                    sizeInBits: 4096,
                    tags: [],
                    sensitive: false,
                }}
            >
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <Form.Item
                            name="privateKeyId"
                            label="Private Key ID"
                            help="Optional: a random UUID will be generated if not specified"
                        >
                            <Input placeholder="Enter private key ID" />
                        </Form.Item>

                        <Form.Item
                            name="sizeInBits"
                            label="Size in Bits"
                            help="The expected size in bits for the RSA key"
                            rules={[{ required: true, message: "Please specify the key size" }]}
                        >
                            <InputNumber className="w-[200px]" min={1024} step={1024} max={8192} />
                        </Form.Item>

                        <Form.Item name="tags" label="Tags" help="Optional: Add tags to help retrieve the keys later">
                            <Select mode="tags" placeholder="Enter tags" open={false} />
                        </Form.Item>

                        <Form.Item
                            name="wrappingKeyId"
                            label="Wrapping Key ID"
                            help="Optional: ID of the key to wrap this new keypair with"
                        >
                            <Input placeholder="Enter wrapping key ID" />
                        </Form.Item>

                        <Form.Item name="sensitive" valuePropName="checked" help="If set, the private key will not be exportable">
                            <Checkbox>Sensitive</Checkbox>
                        </Form.Item>
                    </Card>
                    <Form.Item>
                        <Button type="primary" htmlType="submit" loading={isLoading} className="w-full text-white font-medium">
                            Create RSA Keypair
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            {res && (
                <div ref={responseRef}>
                    <Card title="RSA keys creation response">{res}</Card>
                </div>
            )}
        </div>
    );
};

export default RsaKeyCreateForm;
