import { Button, Card, Form, Input, InputNumber, Space } from "antd";
import React, { useEffect, useRef, useState } from "react";
import { useAuth } from "../../contexts/AuthContext";
import { sendKmipRequest } from "../../utils/utils";
import {
    parse_rekey_ttlv_response,
    parse_set_attribute_ttlv_response,
    rekey_ttlv_request,
    set_attribute_ttlv_request,
} from "../../wasm/pkg/cosmian_kms_client_wasm";

interface KeysReKeyFormData {
    keyId: string;
    rotateInterval?: number;
    rotateName?: string;
    rotateOffset?: number;
}

type ReKeyResponse = {
    UniqueIdentifier: string;
};

interface KeysReKeyFormProps {
    /** Human-readable label for the key type, e.g. "symmetric key", "RSA private key". */
    objectLabel: string;
}

const KeysReKeyForm: React.FC<KeysReKeyFormProps> = ({ objectLabel }) => {
    const [form] = Form.useForm<KeysReKeyFormData>();
    const [res, setRes] = useState<string | undefined>(undefined);
    const [isRekeying, setIsRekeying] = useState(false);
    const [isSettingPolicy, setIsSettingPolicy] = useState(false);
    const { idToken, serverUrl } = useAuth();
    const responseRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        if (res && responseRef.current) {
            responseRef.current.scrollIntoView({ behavior: "smooth" });
        }
    }, [res]);

    const onReKey = async () => {
        try {
            const values = await form.validateFields(["keyId"]);
            setIsRekeying(true);
            setRes(undefined);
            const request = rekey_ttlv_request(values.keyId);
            const result_str = await sendKmipRequest(request, idToken, serverUrl);
            if (result_str) {
                const response: ReKeyResponse = await parse_rekey_ttlv_response(result_str);
                setRes(`${objectLabel} ${values.keyId} has been re-keyed. New key ID: ${response.UniqueIdentifier}`);
            }
        } catch (e) {
            setRes(`Error re-keying: ${e}`);
            console.error("Error re-keying:", e);
        } finally {
            setIsRekeying(false);
        }
    };

    const onSetPolicy = async () => {
        try {
            const values = await form.validateFields(["keyId"]);
            const allValues = form.getFieldsValue();
            const attrsToSet: Array<[string, string]> = [];
            if (allValues.rotateInterval != null) {
                attrsToSet.push(["rotate_interval", String(Math.round(allValues.rotateInterval))]);
            }
            if (allValues.rotateName) {
                attrsToSet.push(["rotate_name", allValues.rotateName]);
            }
            if (allValues.rotateOffset != null) {
                attrsToSet.push(["rotate_offset", String(Math.round(allValues.rotateOffset))]);
            }
            if (attrsToSet.length === 0) {
                setRes("No rotation policy attributes specified. Please fill in at least one field.");
                return;
            }
            setIsSettingPolicy(true);
            setRes(undefined);
            const updates: string[] = [];
            for (const [attrName, attrValue] of attrsToSet) {
                const request = set_attribute_ttlv_request(values.keyId, attrName, attrValue);
                const result_str = await sendKmipRequest(request, idToken, serverUrl);
                if (result_str) {
                    const response = parse_set_attribute_ttlv_response(result_str) as { UniqueIdentifier: string };
                    updates.push(`${attrName}=${attrValue} set on ${response.UniqueIdentifier}`);
                }
            }
            setRes(`Rotation policy updated for ${values.keyId}: ${updates.join(", ")}`);
        } catch (e) {
            setRes(`Error setting rotation policy: ${e}`);
            console.error("Error setting rotation policy:", e);
        } finally {
            setIsSettingPolicy(false);
        }
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">Re-Key / Rotation Policy — {objectLabel}</h1>

            <Form form={form} layout="vertical">
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <Form.Item name="keyId" label="Key ID" rules={[{ required: true, message: "Please enter the key ID" }]}>
                            <Input placeholder="Enter key ID" />
                        </Form.Item>
                    </Card>

                    <Card title="Re-Key now">
                        <p className="mb-4 text-gray-600">
                            Immediately generate a new {objectLabel} derived from the existing one under a new unique identifier. The
                            original key is preserved; objects encrypted with it can still be decrypted. The rotation policy (interval,
                            name, offset) is inherited by the new key.
                        </p>
                        <Button type="primary" onClick={onReKey} loading={isRekeying} data-testid="submit-btn">
                            Re-Key
                        </Button>
                    </Card>

                    <Card title="Auto-rotation policy">
                        <p className="mb-4 text-gray-600">
                            Configure automatic periodic rotation. The server will re-key this object at the given interval.
                        </p>
                        <Form.Item
                            name="rotateInterval"
                            label="Rotation interval (seconds)"
                            help="Automatically re-key at this interval. Set 0 to disable."
                        >
                            <InputNumber className="w-[200px]" min={0} step={3600} placeholder="e.g. 86400" />
                        </Form.Item>
                        <Form.Item name="rotateName" label="Rotation name" help="Optional label for this rotation lineage.">
                            <Input placeholder="e.g. daily-rotation" />
                        </Form.Item>
                        <Form.Item name="rotateOffset" label="Rotation offset (seconds)" help="Delay before the first automatic rotation.">
                            <InputNumber className="w-[200px]" min={0} step={3600} placeholder="e.g. 0" />
                        </Form.Item>
                        <Button type="default" onClick={onSetPolicy} loading={isSettingPolicy} data-testid="set-rotation-policy-btn">
                            Set Rotation Policy
                        </Button>
                    </Card>
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

export default KeysReKeyForm;
