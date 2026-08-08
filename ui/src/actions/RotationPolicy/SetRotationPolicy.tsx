import { Button, Card, Form, Input, InputNumber, Space } from "antd";
import React from "react";
import { ActionResponse } from "../../components/common/ActionResponse";
import { useActionState } from "../../hooks/useActionState";
import { sendKmipRequest } from "../../utils/utils";
import * as wasm from "../../wasm/pkg";

interface SetRotationPolicyFormData {
    keyId: string;
    interval?: number;
    offset?: number;
    name?: string;
}

const SetRotationPolicyForm: React.FC = () => {
    const [form] = Form.useForm<SetRotationPolicyFormData>();
    const { res, isLoading, responseRef, serverUrl, execute } = useActionState();

    const onFinish = async (values: SetRotationPolicyFormData) => {
        await execute(async () => {
            if (values.interval !== undefined && values.interval !== null) {
                const intervalRequest = wasm.set_rotate_interval_ttlv_request(values.keyId, BigInt(values.interval));
                const intervalResult = await sendKmipRequest(intervalRequest, serverUrl);
                if (!intervalResult) return;
                wasm.parse_set_attribute_ttlv_response(intervalResult);
            }

            if (values.offset !== undefined && values.offset !== null) {
                const offsetRequest = wasm.set_rotate_offset_ttlv_request(values.keyId, BigInt(values.offset));
                const offsetResult = await sendKmipRequest(offsetRequest, serverUrl);
                if (!offsetResult) return;
                wasm.parse_set_attribute_ttlv_response(offsetResult);
            }

            if (values.name) {
                const nameRequest = wasm.set_rotate_name_ttlv_request(values.keyId, values.name);
                const nameResult = await sendKmipRequest(nameRequest, serverUrl);
                if (!nameResult) return;
                wasm.parse_set_attribute_ttlv_response(nameResult);
            }

            return "Rotation policy set successfully.";
        });
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">Set Rotation Policy</h1>

            <div className="mb-8 space-y-2">
                <p>Configure an automatic periodic rotation policy on a key.</p>
                <ul className="list-disc pl-5 space-y-1">
                    <li>The interval defines how often (in seconds) the key is automatically rotated.</li>
                    <li>The offset defines the delay (in seconds) before activation of a newly rotated key.</li>
                    <li>The name assigns a keyset name for addressing key generations via name@version syntax.</li>
                </ul>
            </div>

            <Form form={form} onFinish={onFinish} layout="vertical">
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <Form.Item name="keyId" label="Key ID" rules={[{ required: true, message: "Please enter the key ID" }]}>
                            <Input placeholder="Enter the unique identifier of the key" data-testid="rotation-key-id" />
                        </Form.Item>

                        <Form.Item name="interval" label="Interval (seconds)" help="How often the key should be automatically rotated">
                            <InputNumber className="w-[200px]" min={0} placeholder="e.g. 86400 (1 day)" data-testid="rotation-interval" />
                        </Form.Item>

                        <Form.Item name="offset" label="Offset (seconds)" help="Optional: delay before new key activation after rotation">
                            <InputNumber className="w-[200px]" min={0} placeholder="e.g. 3600 (1 hour)" data-testid="rotation-offset" />
                        </Form.Item>

                        <Form.Item
                            name="name"
                            label="Keyset Name"
                            help="Optional: a name for addressing key generations (name@latest, name@first, name@N)"
                        >
                            <Input placeholder="e.g. my-key" data-testid="rotation-name" />
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
                            Set Rotation Policy
                        </Button>
                    </Form.Item>
                </Space>
                <ActionResponse res={res} responseRef={responseRef} title="Set Rotation Policy response" />
            </Form>
        </div>
    );
};

export default SetRotationPolicyForm;
