import { Button, Card, Form, Input, InputNumber, Select, Space } from "antd";
import React, { useEffect, useRef, useState } from "react";
import { useAuth } from "../../contexts/AuthContext";
import { sendKmipRequest } from "../../utils/utils";
import * as wasm from "../../wasm/pkg";
import { parse_set_attribute_ttlv_response, set_attribute_ttlv_request } from "../../wasm/pkg/cosmian_kms_client_wasm";

/** Supported duration units for the rotation interval picker. */
const DURATION_UNITS = [
    { label: "Days", value: 86400 },
    { label: "Weeks", value: 604800 },
    { label: "Months (30 days)", value: 2592000 },
];

interface CovercryptReKeyFormData {
    mskId: string;
    accessPolicy: string;
    rotateIntervalValue?: number;
    rotateIntervalUnit?: number;
    rotateName?: string;
    rotateOffsetValue?: number;
    rotateOffsetUnit?: number;
}

type ReKeyKeyPairResponse = {
    PrivateKeyUniqueIdentifier: string;
    PublicKeyUniqueIdentifier: string;
};

const CovercryptReKeyForm: React.FC = () => {
    const [form] = Form.useForm<CovercryptReKeyFormData>();
    const [res, setRes] = useState<string | undefined>(undefined);
    const [isLoading, setIsLoading] = useState(false);
    const [isSettingPolicy, setIsSettingPolicy] = useState(false);
    const { idToken, serverUrl } = useAuth();
    const responseRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        if (res && responseRef.current) {
            responseRef.current.scrollIntoView({ behavior: "smooth" });
        }
    }, [res]);

    const onFinish = async (values: CovercryptReKeyFormData) => {
        setIsLoading(true);
        setRes(undefined);
        try {
            const w = wasm as unknown as {
                rekey_cc_keypair_ttlv_request?: (mskId: string, accessPolicy: string) => unknown;
                parse_rekey_cc_keypair_ttlv_response?: (response: string) => ReKeyKeyPairResponse;
            };
            if (!w.rekey_cc_keypair_ttlv_request || !w.parse_rekey_cc_keypair_ttlv_response) {
                throw new Error("Covercrypt re-key is not available in this build (requires non-FIPS mode).");
            }
            const request = w.rekey_cc_keypair_ttlv_request(values.mskId, values.accessPolicy) as object;
            const result_str = await sendKmipRequest(request, idToken, serverUrl);
            if (result_str) {
                const response = w.parse_rekey_cc_keypair_ttlv_response(result_str);
                setRes(
                    `Access policy re-keyed on master key pair. ` +
                        `New private key: ${response.PrivateKeyUniqueIdentifier} — ` +
                        `New public key: ${response.PublicKeyUniqueIdentifier}`,
                );
            }
        } catch (e) {
            setRes(`Error re-keying Covercrypt access policy: ${e}`);
            console.error("Error re-keying Covercrypt access policy:", e);
        } finally {
            setIsLoading(false);
        }
    };

    const onSetPolicy = async () => {
        try {
            const values = await form.validateFields(["mskId"]);
            const allValues = form.getFieldsValue();
            const attrsToSet: Array<[string, string]> = [];
            if (allValues.rotateIntervalValue != null && allValues.rotateIntervalValue > 0) {
                const seconds = allValues.rotateIntervalValue * (allValues.rotateIntervalUnit ?? 86400);
                attrsToSet.push(["rotate_interval", String(Math.round(seconds))]);
            }
            if (allValues.rotateName) {
                attrsToSet.push(["rotate_name", allValues.rotateName]);
            }
            if (allValues.rotateOffsetValue != null && allValues.rotateOffsetValue > 0) {
                const seconds = allValues.rotateOffsetValue * (allValues.rotateOffsetUnit ?? 86400);
                attrsToSet.push(["rotate_offset", String(Math.round(seconds))]);
            }
            if (attrsToSet.length === 0) {
                setRes("No rotation policy attributes specified. Please fill in at least one field.");
                return;
            }
            setIsSettingPolicy(true);
            setRes(undefined);
            const updates: string[] = [];
            for (const [attrName, attrValue] of attrsToSet) {
                const request = set_attribute_ttlv_request(values.mskId, attrName, attrValue);
                const result_str = await sendKmipRequest(request, idToken, serverUrl);
                if (result_str) {
                    const response = parse_set_attribute_ttlv_response(result_str) as { UniqueIdentifier: string };
                    updates.push(`${attrName}=${attrValue} set on ${response.UniqueIdentifier}`);
                }
            }
            setRes(`Rotation policy updated for ${values.mskId}: ${updates.join(", ")}`);
        } catch (e) {
            setRes(`Error setting rotation policy: ${e}`);
            console.error("Error setting rotation policy:", e);
        } finally {
            setIsSettingPolicy(false);
        }
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">Re-Key / Rotation Policy — Covercrypt master key</h1>

            <div className="mb-8 space-y-2">
                <p>Re-key an access policy on a Covercrypt master key pair:</p>
                <ul className="list-disc pl-5 space-y-1">
                    <li>All active user decryption keys (USKs) matching the access policy are automatically re-keyed.</li>
                    <li>Revoked or destroyed USKs are not affected.</li>
                    <li>USKs that have not been re-keyed can still decrypt data encrypted before this operation.</li>
                    <li>New USKs will decrypt only data encrypted after the re-key.</li>
                </ul>
            </div>

            <Form form={form} onFinish={onFinish} layout="vertical">
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <Form.Item
                            name="mskId"
                            label="Master Secret Key ID"
                            rules={[{ required: true, message: "Please enter the Master Secret Key ID" }]}
                        >
                            <Input placeholder="Enter Master Secret Key ID" />
                        </Form.Item>

                        <Form.Item
                            name="accessPolicy"
                            label="Access Policy"
                            help='Boolean expression of attributes to re-key, e.g. "Department::HR && Security Level::Confidential"'
                            rules={[{ required: true, message: "Please enter the access policy expression" }]}
                        >
                            <Input.TextArea
                                placeholder='e.g. "Department::HR && Security Level::Confidential"'
                                rows={3}
                                data-testid="access-policy-input"
                            />
                        </Form.Item>
                    </Card>

                    <Button type="primary" htmlType="submit" loading={isLoading} data-testid="submit-btn">
                        Re-Key Access Policy
                    </Button>

                    <Card title="Auto-rotation policy">
                        <p className="mb-4 text-gray-600">
                            Configure automatic periodic rotation of this master key. The server will re-key the access policy at the given
                            interval.
                        </p>
                        <Form.Item
                            label="Rotation interval"
                            help="Automatically re-key at this interval (minimum 1 day). Leave empty to disable."
                        >
                            <Input.Group compact>
                                <Form.Item name="rotateIntervalValue" noStyle>
                                    <InputNumber className="w-[120px]" min={1} step={1} placeholder="e.g. 1" />
                                </Form.Item>
                                <Form.Item name="rotateIntervalUnit" noStyle initialValue={86400}>
                                    <Select className="w-[170px]" options={DURATION_UNITS} />
                                </Form.Item>
                            </Input.Group>
                        </Form.Item>
                        <Form.Item name="rotateName" label="Rotation name" help="Optional label for this rotation lineage.">
                            <Input placeholder="e.g. daily-rotation" />
                        </Form.Item>
                        <Form.Item label="Rotation offset" help="Delay before the first automatic rotation (minimum 1 day).">
                            <Input.Group compact>
                                <Form.Item name="rotateOffsetValue" noStyle>
                                    <InputNumber className="w-[120px]" min={1} step={1} placeholder="e.g. 1" />
                                </Form.Item>
                                <Form.Item name="rotateOffsetUnit" noStyle initialValue={86400}>
                                    <Select className="w-[170px]" options={DURATION_UNITS} />
                                </Form.Item>
                            </Input.Group>
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

export default CovercryptReKeyForm;
