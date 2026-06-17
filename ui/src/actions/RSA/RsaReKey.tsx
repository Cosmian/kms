import { Button, Card, Form, Input, Space } from "antd";
import React from "react";
import { ActionResponse } from "../../components/common/ActionResponse";
import { useActionState } from "../../hooks/useActionState";
import { sendKmipRequest } from "../../utils/utils";
import * as wasm from "../../wasm/pkg";

interface ReKeyFormData {
    keyId: string;
}

type ReKeyKeyPairResponse = {
    PrivateKeyUniqueIdentifier: string;
    PublicKeyUniqueIdentifier: string;
};

const RsaReKeyForm: React.FC = () => {
    const [form] = Form.useForm<ReKeyFormData>();
    const { res, isLoading, responseRef, idToken, serverUrl, execute } = useActionState();

    const onFinish = async (values: ReKeyFormData) => {
        await execute(async () => {
            const request = wasm.rekey_keypair_ttlv_request(values.keyId);
            const result_str = await sendKmipRequest(request, idToken, serverUrl);
            if (result_str) {
                const result: ReKeyKeyPairResponse = await wasm.parse_rekey_keypair_ttlv_response(result_str);
                return `The RSA key pair was successfully rotated.\nNew private key: ${result.PrivateKeyUniqueIdentifier}\nNew public key: ${result.PublicKeyUniqueIdentifier}`;
            }
        });
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">Re-Key an RSA key pair</h1>

            <div className="mb-8 space-y-2">
                <p>Rotate an existing RSA key pair, generating new key material.</p>
                <ul className="list-disc pl-5 space-y-1">
                    <li>A new private key and public key are created with the same algorithm and key size.</li>
                    <li>The old key pair is linked to the new one via replacement links.</li>
                    <li>The rotation generation counter is incremented on the new key.</li>
                </ul>
            </div>

            <Form form={form} onFinish={onFinish} layout="vertical">
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <Form.Item
                            name="keyId"
                            label="Private Key ID"
                            rules={[{ required: true, message: "Please enter the private key ID" }]}
                        >
                            <Input placeholder="Enter the unique identifier of the private key to re-key" data-testid="rekey-key-id" />
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
                            Re-Key
                        </Button>
                    </Form.Item>
                </Space>
                <ActionResponse res={res} responseRef={responseRef} title="Re-Key response" />
            </Form>
        </div>
    );
};

export default RsaReKeyForm;
