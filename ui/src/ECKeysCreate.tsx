import { Button, Card, Checkbox, Form, Input, Select, Space } from "antd";
import React, { useEffect, useRef, useState } from "react";
import { useAuth } from "./AuthContext";
import { sendKmipRequest } from "./utils";
import { create_ec_key_pair_ttlv_request, parse_create_keypair_ttlv_response } from "./wasm/pkg";

interface ECKeyCreateFormData {
    privateKeyId?: string;
    curve: string;
    tags: string[];
    sensitive: boolean;
}

type CreateKeyPairResponse = {
    PrivateKeyUniqueIdentifier: string;
    PublicKeyUniqueIdentifier: string;
};

const ECKeyCreateForm: React.FC = () => {
    const [form] = Form.useForm<ECKeyCreateFormData>();
    const [res, setRes] = useState<undefined | string>(undefined);
    const [isLoading, setIsLoading] = useState(false);
    const { idToken, serverUrl } = useAuth();
    const responseRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        if (res && responseRef.current) {
            responseRef.current.scrollIntoView({ behavior: "smooth" });
        }
    }, [res]);

    const onFinish = async (values: ECKeyCreateFormData) => {
        setIsLoading(true);
        setRes(undefined);
        try {
            const request = create_ec_key_pair_ttlv_request(values.privateKeyId, values.tags, values.curve, values.sensitive);
            const result_str = await sendKmipRequest(request, idToken, serverUrl);
            if (result_str) {
                const result: CreateKeyPairResponse = await parse_create_keypair_ttlv_response(result_str);
                setRes(
                    `Key pair has been created. Private key Id: ${result.PrivateKeyUniqueIdentifier} - Public key Id: ${result.PublicKeyUniqueIdentifier}`
                );
            }
        } catch (e) {
            setRes(`Error creating EC keypair: ${e}`);
            console.error("Error creating EC keypair:", e);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">Create an EC key pair</h1>
            <div className="mb-8 space-y-2">
                <p>Create a new Elliptic Curve key pair:</p>
                <ul className="list-disc pl-5 space-y-1">
                    <li>The public key is used to encrypt or verify a signature and can be safely shared.</li>
                    <li>The private key is used to decrypt or sign and must be kept secret.</li>
                </ul>
            </div>

            <Form
                form={form}
                onFinish={onFinish}
                layout="vertical"
                initialValues={{
                    curve: "nist-p256",
                    tags: [],
                    sensitive: false,
                }}
            >
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <Form.Item
                            name="curve"
                            label="Curve"
                            help="Select the elliptic curve to use"
                            rules={[{ required: true, message: "Please select a curve" }]}
                        >
                            <Select>
                                <Select.Option value="nist-p192">NIST P-192</Select.Option>
                                <Select.Option value="nist-p224">NIST P-224</Select.Option>
                                <Select.Option value="nist-p256">NIST P-256</Select.Option>
                                <Select.Option value="nist-p384">NIST P-384</Select.Option>
                                <Select.Option value="nist-p521">NIST P-521</Select.Option>
                                <Select.Option value="ed25519">Ed25519</Select.Option>
                                <Select.Option value="ed448">Ed448</Select.Option>
                            </Select>
                        </Form.Item>

                        <Form.Item
                            name="privateKeyId"
                            label="Private Key ID"
                            help="Optional: a random UUID will be generated if not specified"
                        >
                            <Input placeholder="Enter private key ID" />
                        </Form.Item>

                        <Form.Item name="tags" label="Tags" help="Optional: Add tags to help retrieve the keys later">
                            <Select mode="tags" placeholder="Enter tags" open={false} />
                        </Form.Item>

                        <Form.Item name="sensitive" valuePropName="checked" help="If set, the private key will not be exportable">
                            <Checkbox>Sensitive</Checkbox>
                        </Form.Item>
                    </Card>

                    <Form.Item>
                        <Button type="primary" htmlType="submit" loading={isLoading} className="w-full text-white font-medium">
                            Create EC Keypair
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            {res && (
                <div ref={responseRef}>
                    <Card title="EC key pair creation response">{res}</Card>
                </div>
            )}
        </div>
    );
};

export default ECKeyCreateForm;
