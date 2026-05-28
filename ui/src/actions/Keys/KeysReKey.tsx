import { Button, Card, Form, Input, Select, Space } from "antd";
import React from "react";
import { sendKmipRequest } from "../../utils/utils";
import { parse_rekey_ttlv_response, rekey_ttlv_request } from "../../wasm/pkg/cosmian_kms_client_wasm";
import { useActionState } from "../../hooks/useActionState";
import { ActionResponse } from "../../components/common/ActionResponse";

interface KeysReKeyFormData {
    id?: string;
    tags?: string[];
}

type ReKeyResponse = {
    UniqueIdentifier: string;
};

const KeysReKeyForm: React.FC = () => {
    const [form] = Form.useForm<KeysReKeyFormData>();
    const { res, isLoading, responseRef, idToken, serverUrl, execute } = useActionState();

    const onFinish = async (values: KeysReKeyFormData) => {
        const id = values.id ? values.id : values.tags ? JSON.stringify(values.tags) : undefined;
        await execute(async () => {
            if (id == undefined) {
                throw new Error("Missing object identifier.");
            }

            const request = rekey_ttlv_request(id);
            const result_str = await sendKmipRequest(request, idToken, serverUrl);
            if (result_str) {
                const result: ReKeyResponse = parse_rekey_ttlv_response(result_str);
                return `Key has been re-keyed. New key: ${result.UniqueIdentifier}`;
            }
        });
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">Re-Key Symmetric Key</h1>

            <div className="mb-8 space-y-2">
                <p>Generate fresh key material for an existing symmetric key. The original key is preserved with a link to the new key.</p>
                <ul className="list-disc pl-5 space-y-1">
                    <li>A new key is created with the same algorithm and length.</li>
                    <li>
                        The old key gets a <code>ReplacementObjectLink</code> pointing to the new key.
                    </li>
                    <li>
                        The new key gets a <code>ReplacedObjectLink</code> pointing to the old key.
                    </li>
                    <li>If the key is a wrapping key, all dependent wrapped keys are re-wrapped automatically.</li>
                </ul>
            </div>

            <Form form={form} onFinish={onFinish} layout="vertical">
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card title="Object Identification">
                        <div className="mb-5">Specify either the Object ID or one or more tags to identify the key to re-key.</div>

                        <Form.Item name="id" label="Object ID" help="The unique identifier of the symmetric key">
                            <Input data-testid="key-id-input" placeholder="Enter key ID" />
                        </Form.Item>

                        <Form.Item name="tags" label="Tags" help="Tags to use to retrieve the key when no key ID is specified">
                            <Select mode="tags" style={{ width: "100%" }} placeholder="Enter tags" tokenSeparators={[","]} />
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
