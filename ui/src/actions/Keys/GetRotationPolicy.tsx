import { Button, Card, Descriptions, Form, Input, Select, Space } from "antd";
import React, { useState } from "react";
import { sendKmipRequest } from "../../utils/utils";
import { get_attributes_ttlv_request, parse_rotation_policy_response } from "../../wasm/pkg/cosmian_kms_client_wasm";
import { useActionState } from "../../hooks/useActionState";

interface GetRotationPolicyFormData {
    id?: string;
    tags?: string[];
}

interface RotationPolicy {
    interval: number;
    offset: number;
    name: string | null;
    generation: number;
    date: string | null;
}

const GetRotationPolicyForm: React.FC = () => {
    const [form] = Form.useForm<GetRotationPolicyFormData>();
    const { res, isLoading, responseRef, idToken, serverUrl, execute } = useActionState();
    const [policy, setPolicy] = useState<RotationPolicy | null>(null);

    const onFinish = async (values: GetRotationPolicyFormData) => {
        setPolicy(null);
        const id = values.id ? values.id : values.tags ? JSON.stringify(values.tags) : undefined;
        await execute(async () => {
            if (id == undefined) {
                throw new Error("Missing object identifier.");
            }

            const request = get_attributes_ttlv_request(id);
            const result_str = await sendKmipRequest(request, idToken, serverUrl);
            if (result_str) {
                const parsed = parse_rotation_policy_response(result_str) as RotationPolicy;
                setPolicy(parsed);
                return undefined;
            }
            return undefined;
        });
    };

    const formatInterval = (secs: number): string => {
        if (secs === 0) return "Disabled";
        const days = Math.floor(secs / 86400);
        const hours = Math.floor((secs % 86400) / 3600);
        const mins = Math.floor((secs % 3600) / 60);
        const parts: string[] = [];
        if (days > 0) parts.push(`${days}d`);
        if (hours > 0) parts.push(`${hours}h`);
        if (mins > 0) parts.push(`${mins}m`);
        if (parts.length === 0) parts.push(`${secs}s`);
        return `${parts.join(" ")} (${secs}s)`;
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">Get Rotation Policy</h1>

            <div className="mb-8 space-y-2">
                <p>View the current rotation policy of a key, including interval, generation count, and last rotation date.</p>
            </div>

            <Form form={form} onFinish={onFinish} layout="vertical">
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card title="Object Identification">
                        <div className="mb-5">Specify either the Object ID or one or more tags to identify the key.</div>

                        <Form.Item name="id" label="Object ID" help="The unique identifier of the key">
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
                            Get Rotation Policy
                        </Button>
                    </Form.Item>
                </Space>
            </Form>

            {res && !policy && (
                <Card>
                    <div ref={responseRef} data-testid="response-output">
                        {res}
                    </div>
                </Card>
            )}

            {policy && (
                <div ref={responseRef} data-testid="response-output">
                    <Card title="Rotation Policy">
                        <Descriptions column={1} bordered size="small">
                            <Descriptions.Item label="Status">
                                <span data-testid="policy-status">{policy.interval > 0 ? "Enabled" : "Disabled"}</span>
                            </Descriptions.Item>
                            <Descriptions.Item label="Interval">{formatInterval(policy.interval)}</Descriptions.Item>
                            <Descriptions.Item label="Offset">{formatInterval(policy.offset)}</Descriptions.Item>
                            <Descriptions.Item label="Name">{policy.name ?? "(none)"}</Descriptions.Item>
                            <Descriptions.Item label="Generation">{policy.generation}</Descriptions.Item>
                            <Descriptions.Item label="Last Rotated">{policy.date ?? "(never)"}</Descriptions.Item>
                        </Descriptions>
                    </Card>
                </div>
            )}
        </div>
    );
};

export default GetRotationPolicyForm;
