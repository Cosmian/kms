import { Button, Card, Form, Input, InputNumber, Space } from "antd";
import React, { useEffect, useRef, useState } from "react";
import { useAuth } from "../../contexts/AuthContext";
import { ObjectType, getObjectLabel, sendKmipRequest } from "../../utils/utils";
import { parse_set_attribute_ttlv_response, set_attribute_ttlv_request } from "../../wasm/pkg/cosmian_kms_client_wasm";

interface SetRotationPolicyFormData {
    objectId: string;
    rotateInterval?: number;
    rotateName?: string;
    rotateOffset?: number;
}

interface SetRotationPolicyProps {
    objectType: ObjectType;
}

const SetRotationPolicyForm: React.FC<SetRotationPolicyProps> = ({ objectType }) => {
    const [form] = Form.useForm<SetRotationPolicyFormData>();
    const [res, setRes] = useState<string | undefined>(undefined);
    const [isLoading, setIsLoading] = useState(false);
    const { idToken, serverUrl } = useAuth();
    const responseRef = useRef<HTMLDivElement>(null);
    const label = getObjectLabel(objectType);

    useEffect(() => {
        if (res && responseRef.current) {
            responseRef.current.scrollIntoView({ behavior: "smooth" });
        }
    }, [res]);

    const onFinish = async (values: SetRotationPolicyFormData) => {
        setIsLoading(true);
        setRes(undefined);

        const attrsToSet: Array<[string, string]> = [];
        if (values.rotateInterval != null) {
            attrsToSet.push(["rotate_interval", String(Math.round(values.rotateInterval))]);
        }
        if (values.rotateName) {
            attrsToSet.push(["rotate_name", values.rotateName]);
        }
        if (values.rotateOffset != null) {
            attrsToSet.push(["rotate_offset", String(Math.round(values.rotateOffset))]);
        }

        if (attrsToSet.length === 0) {
            setRes("No rotation policy attributes specified. Please fill in at least one field.");
            setIsLoading(false);
            return;
        }

        try {
            const updates: string[] = [];
            for (const [attrName, attrValue] of attrsToSet) {
                const request = set_attribute_ttlv_request(values.objectId, attrName, attrValue);
                const result_str = await sendKmipRequest(request, idToken, serverUrl);
                if (result_str) {
                    const response = parse_set_attribute_ttlv_response(result_str);
                    updates.push(`${attrName}=${attrValue} set on ${response.UniqueIdentifier}`);
                }
            }
            setRes(`Rotation policy updated for ${label} ${values.objectId}: ${updates.join(", ")}`);
        } catch (e) {
            setRes(`Error setting rotation policy: ${e}`);
            console.error("Error setting rotation policy:", e);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">Set {label} rotation policy</h1>

            <div className="mb-8 space-y-2">
                <p>Configure automatic rotation for a {label}:</p>
                <ul className="list-disc pl-5 space-y-1">
                    <li>
                        <strong>Interval</strong>: time in seconds between automatic re-keys (set to 0 to disable rotation).
                    </li>
                    <li>
                        <strong>Name</strong>: optional label to identify this rotation policy.
                    </li>
                    <li>
                        <strong>Offset</strong>: delay in seconds before the first rotation.
                    </li>
                </ul>
            </div>

            <Form form={form} onFinish={onFinish} layout="vertical">
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <Form.Item
                            name="objectId"
                            label={`${label} ID`}
                            rules={[{ required: true, message: `Please enter the ${label} ID` }]}
                        >
                            <Input placeholder="Enter key ID" />
                        </Form.Item>

                        <Form.Item
                            name="rotateInterval"
                            label="Rotation Interval (seconds)"
                            help="Time between automatic re-keys. Set 0 to disable."
                        >
                            <InputNumber className="w-[200px]" min={0} step={3600} placeholder="e.g. 86400" />
                        </Form.Item>

                        <Form.Item name="rotateName" label="Rotation Name" help="Optional label for this rotation policy">
                            <Input placeholder="e.g. daily-rotation" />
                        </Form.Item>

                        <Form.Item name="rotateOffset" label="Rotation Offset (seconds)" help="Delay in seconds before the first rotation">
                            <InputNumber className="w-[200px]" min={0} step={3600} placeholder="e.g. 0" />
                        </Form.Item>
                    </Card>

                    <Button type="primary" htmlType="submit" loading={isLoading} data-testid="submit-btn">
                        Set Rotation Policy
                    </Button>
                </Space>
            </Form>

            {res && (
                <div ref={responseRef} className="mt-6 p-4 bg-gray-100 rounded" data-testid="response-output">
                    {res}
                </div>
            )}
        </div>
    );
};

export default SetRotationPolicyForm;
