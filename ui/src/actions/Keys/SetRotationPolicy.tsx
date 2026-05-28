import { Button, Card, Form, Input, InputNumber, Select, Space } from "antd";
import React from "react";
import { sendKmipRequest } from "../../utils/utils";
import {
    parse_set_attribute_ttlv_response,
    set_rotate_interval_ttlv_request,
    set_rotate_name_ttlv_request,
    set_rotate_offset_ttlv_request,
} from "../../wasm/pkg/cosmian_kms_client_wasm";
import { useActionState } from "../../hooks/useActionState";
import { ActionResponse } from "../../components/common/ActionResponse";

interface SetRotationPolicyFormData {
    id?: string;
    tags?: string[];
    interval: number;
    offset: number;
    name?: string;
}

const SetRotationPolicyForm: React.FC = () => {
    const [form] = Form.useForm<SetRotationPolicyFormData>();
    const { res, isLoading, responseRef, idToken, serverUrl, execute } = useActionState();

    const onFinish = async (values: SetRotationPolicyFormData) => {
        const id = values.id ? values.id : values.tags ? JSON.stringify(values.tags) : undefined;
        await execute(async () => {
            if (id == undefined) {
                throw new Error("Missing object identifier.");
            }

            // Set RotateInterval
            const intervalRequest = set_rotate_interval_ttlv_request(id, values.interval);
            const intervalResult = await sendKmipRequest(intervalRequest, idToken, serverUrl);
            if (intervalResult) {
                parse_set_attribute_ttlv_response(intervalResult);
            }

            // Set RotateOffset
            const offsetRequest = set_rotate_offset_ttlv_request(id, values.offset);
            const offsetResult = await sendKmipRequest(offsetRequest, idToken, serverUrl);
            if (offsetResult) {
                parse_set_attribute_ttlv_response(offsetResult);
            }

            // Set RotateName if provided
            if (values.name && values.name.trim().length > 0) {
                const nameRequest = set_rotate_name_ttlv_request(id, values.name.trim());
                const nameResult = await sendKmipRequest(nameRequest, idToken, serverUrl);
                if (nameResult) {
                    parse_set_attribute_ttlv_response(nameResult);
                }
            }

            return `Rotation policy has been set for ${id}.`;
        });
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">Set Rotation Policy</h1>

            <div className="mb-8 space-y-2">
                <p>Configure automatic key rotation for a symmetric key.</p>
                <ul className="list-disc pl-5 space-y-1">
                    <li>
                        <strong>Interval</strong>: rotation period in seconds. Set to <code>0</code> to disable auto-rotation.
                    </li>
                    <li>
                        <strong>Offset</strong>: delay (in seconds) from the key&apos;s Initial Date before the first rotation.
                    </li>
                    <li>
                        <strong>Name</strong>: optional human-readable label (e.g. &quot;hourly&quot;, &quot;daily&quot;).
                    </li>
                </ul>
            </div>

            <Form
                form={form}
                onFinish={onFinish}
                layout="vertical"
                initialValues={{
                    interval: 3600,
                    offset: 0,
                }}
            >
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card title="Object Identification">
                        <div className="mb-5">Specify either the Object ID or one or more tags to identify the key.</div>

                        <Form.Item name="id" label="Object ID" help="The unique identifier of the symmetric key">
                            <Input data-testid="key-id-input" placeholder="Enter key ID" />
                        </Form.Item>

                        <Form.Item name="tags" label="Tags" help="Tags to use to retrieve the key when no key ID is specified">
                            <Select mode="tags" style={{ width: "100%" }} placeholder="Enter tags" tokenSeparators={[","]} />
                        </Form.Item>
                    </Card>

                    <Card title="Rotation Policy">
                        <Form.Item
                            name="interval"
                            label="Rotation Interval (seconds)"
                            rules={[{ required: true, message: "Please enter an interval" }]}
                            help="How often the key should be rotated. Use 0 to disable."
                        >
                            <InputNumber className="w-[200px]" min={0} step={3600} />
                        </Form.Item>

                        <Form.Item name="offset" label="Offset (seconds)" help="Delay from Initial Date before first rotation triggers">
                            <InputNumber className="w-[200px]" min={0} step={60} />
                        </Form.Item>

                        <Form.Item name="name" label="Policy Name" help='Optional label, e.g. "hourly", "daily", "annual"'>
                            <Input data-testid="name-input" placeholder="Enter rotation policy name" />
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
                <ActionResponse res={res} responseRef={responseRef} title="Rotation policy response" />
            </Form>
        </div>
    );
};

export default SetRotationPolicyForm;
