import { Button, Card, Form, Input, Space } from "antd";
import React from "react";
import { ActionResponse } from "../../components/common/ActionResponse";
import { useActionState } from "../../hooks/useActionState";
import { sendKmipRequest } from "../../utils/utils";
import * as wasm from "../../wasm/pkg";

interface ReKeyFormData {
    keyId: string;
}

type ReKeyResponse = {
    UniqueIdentifier: string;
};

const KeysReKeyForm: React.FC = () => {
    const [form] = Form.useForm<ReKeyFormData>();
    const { res, isLoading, responseRef, idToken, serverUrl, execute } = useActionState();

    const onFinish = async (values: ReKeyFormData) => {
        await execute(async () => {
            const request = wasm.rekey_ttlv_request(values.keyId);
            const result_str = await sendKmipRequest(request, idToken, serverUrl);
            if (result_str) {
                const result: ReKeyResponse = await wasm.parse_rekey_ttlv_response(result_str);
                return `The symmetric key was successfully refreshed. New key: ${result.UniqueIdentifier}`;
            }
        });
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">Re-Key a symmetric key</h1>

            <div className="mb-8 space-y-2">
                <p>Refresh an existing symmetric key, generating a new key value.</p>
                <ul className="list-disc pl-5 space-y-1">
                    <li>The old key is deactivated and a new key is created as its replacement.</li>
                    <li>The rotation generation counter is incremented on the new key.</li>
                </ul>
            </div>

            <Form form={form} onFinish={onFinish} layout="vertical">
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <Form.Item
                            name="keyId"
                            label="Key ID"
                            rules={[{ required: true, message: "Please enter the key ID" }]}
                        >
                            <Input placeholder="Enter the unique identifier of the key to re-key" data-testid="rekey-key-id" />
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

export default KeysReKeyForm;
