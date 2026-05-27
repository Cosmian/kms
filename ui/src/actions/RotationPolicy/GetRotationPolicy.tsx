import { Button, Card, Descriptions, Form, Input, Space } from "antd";
import React, { useState } from "react";
import { ActionResponse } from "../../components/common/ActionResponse";
import { useActionState } from "../../hooks/useActionState";
import { sendKmipRequest } from "../../utils/utils";
import * as wasm from "../../wasm/pkg";

interface GetRotationPolicyFormData {
    keyId: string;
}

interface RotationPolicy {
    interval?: number;
    offset?: number;
    name?: string;
    generation?: number;
    date?: string;
}

const GetRotationPolicyForm: React.FC = () => {
    const [form] = Form.useForm<GetRotationPolicyFormData>();
    const { res, isLoading, responseRef, idToken, serverUrl, execute } = useActionState();
    const [policy, setPolicy] = useState<RotationPolicy | null>(null);

    const onFinish = async (values: GetRotationPolicyFormData) => {
        setPolicy(null);
        await execute(async () => {
            const request = wasm.get_attributes_ttlv_request(values.keyId);
            const result_str = await sendKmipRequest(request, idToken, serverUrl);
            if (result_str) {
                const result: RotationPolicy = await wasm.parse_rotation_policy_response(result_str);
                setPolicy(result);
                if (!result.interval && !result.name && !result.generation) {
                    return "No rotation policy configured for this key.";
                }
                return "Rotation policy retrieved successfully.";
            }
        });
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">Get Rotation Policy</h1>

            <div className="mb-8 space-y-2">
                <p>Retrieve the current automatic rotation policy for a key.</p>
            </div>

            <Form form={form} onFinish={onFinish} layout="vertical">
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <Form.Item name="keyId" label="Key ID" rules={[{ required: true, message: "Please enter the key ID" }]}>
                            <Input placeholder="Enter the unique identifier of the key" data-testid="get-rotation-key-id" />
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
                            Get Rotation Policy
                        </Button>
                    </Form.Item>
                </Space>
                <ActionResponse res={res} responseRef={responseRef} title="Rotation Policy response" />
            </Form>

            {policy && (policy.interval || policy.name || policy.generation) && (
                <Card className="mt-6" title="Rotation Policy Details" data-testid="rotation-policy-details">
                    <Descriptions bordered column={1}>
                        <Descriptions.Item label="Interval (seconds)">{policy.interval ?? "Not set"}</Descriptions.Item>
                        <Descriptions.Item label="Offset (seconds)">{policy.offset ?? "Not set"}</Descriptions.Item>
                        <Descriptions.Item label="Keyset Name">{policy.name ?? "Not set"}</Descriptions.Item>
                        <Descriptions.Item label="Generation">{policy.generation ?? "Not set"}</Descriptions.Item>
                        <Descriptions.Item label="Last Rotation Date">{policy.date ?? "Never"}</Descriptions.Item>
                    </Descriptions>
                </Card>
            )}
        </div>
    );
};

export default GetRotationPolicyForm;
