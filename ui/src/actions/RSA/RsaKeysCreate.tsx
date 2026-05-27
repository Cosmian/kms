import { Button, Card, Checkbox, Divider, Form, Input, InputNumber, Select, Space } from "antd";
import React from "react";
import { sendKmipRequest } from "../../utils/utils";
import { create_rsa_key_pair_ttlv_request, parse_create_keypair_ttlv_response } from "../../wasm/pkg";
import * as wasm from "../../wasm/pkg";
import { useActionState } from "../../hooks/useActionState";
import { ActionResponse } from "../../components/common/ActionResponse";

interface RsaKeyCreateFormData {
    privateKeyId?: string;
    sizeInBits: number;
    tags: string[];
    sensitive: boolean;
    wrappingKeyId?: string;
    rotateName?: string;
    rotateInterval?: number;
    rotateOffset?: number;
}

type CreateKeyPairResponse = {
    PrivateKeyUniqueIdentifier: string;
    PublicKeyUniqueIdentifier: string;
};

const RsaKeyCreateForm: React.FC = () => {
    const [form] = Form.useForm<RsaKeyCreateFormData>();
    const { res, isLoading, responseRef, idToken, serverUrl, execute } = useActionState();

    const onFinish = async (values: RsaKeyCreateFormData) => {
        await execute(async () => {
            const request = create_rsa_key_pair_ttlv_request(
                values.privateKeyId,
                values.tags,
                values.sizeInBits,
                values.sensitive,
                values.wrappingKeyId,
            );
            const result_str = await sendKmipRequest(request, idToken, serverUrl);
            if (result_str) {
                const result: CreateKeyPairResponse = await parse_create_keypair_ttlv_response(result_str);
                const skId = result.PrivateKeyUniqueIdentifier;

                // Apply rotation policy on the private key (keyset anchor)
                if (values.rotateName || values.rotateInterval !== undefined || values.rotateOffset !== undefined) {
                    if (values.rotateInterval !== undefined) {
                        const req = wasm.set_rotate_interval_ttlv_request(skId, BigInt(values.rotateInterval));
                        await sendKmipRequest(req, idToken, serverUrl);
                    }
                    if (values.rotateOffset !== undefined) {
                        const req = wasm.set_rotate_offset_ttlv_request(skId, BigInt(values.rotateOffset));
                        await sendKmipRequest(req, idToken, serverUrl);
                    }
                    if (values.rotateName) {
                        const req = wasm.set_rotate_name_ttlv_request(skId, values.rotateName);
                        await sendKmipRequest(req, idToken, serverUrl);
                    }
                }

                return `Key pair has been created. Private key Id: ${skId} - Public key Id: ${result.PublicKeyUniqueIdentifier}`;
            }
        });
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

                        <Divider orientation="left" plain>
                            Rotation Policy (optional)
                        </Divider>

                        <Form.Item
                            name="rotateName"
                            label="Rotation Name"
                            help="Keyset name for addressing generations via name@latest, name@first, name@N"
                        >
                            <Input placeholder="e.g. my-keyset" data-testid="rsa-rotation-name" />
                        </Form.Item>

                        <Form.Item
                            name="rotateInterval"
                            label="Rotation Interval (seconds)"
                            help="Auto-rotate the key pair every N seconds. Set 0 to disable."
                        >
                            <InputNumber className="w-[200px]" min={0} placeholder="e.g. 86400" data-testid="rsa-rotation-interval" />
                        </Form.Item>

                        <Form.Item
                            name="rotateOffset"
                            label="Rotation Offset (seconds)"
                            help="Delay before the first rotation occurs."
                        >
                            <InputNumber className="w-[200px]" min={0} placeholder="e.g. 3600" data-testid="rsa-rotation-offset" />
                        </Form.Item>
                    </Card>
                    <Form.Item>
                        <Button
                            type="primary"
                            htmlType="submit"
                            loading={isLoading}
                            className="w-full text-white font-medium"
                            data-testid="submit-btn"
                        >
                            Create RSA Keypair
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            <ActionResponse res={res} responseRef={responseRef} title="RSA keys creation response" />
        </div>
    );
};

export default RsaKeyCreateForm;
