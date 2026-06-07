import { Button, Card, Form, Input, InputNumber, Space } from "antd";
import React, { useCallback, useState } from "react";
import { sendKmipRequest } from "../../utils/utils";
import { useActionState } from "../../hooks/useActionState";
import { ActionResponse } from "../../components/common/ActionResponse";
import LocateButton from "../../components/common/LocateButton";

interface JoinSplitKeyFormData {
    shareCount: number;
    shareIds: { value: string }[];
    objectType: string;
}

const OBJECT_TYPES_OPTIONS = [
    { label: "Symmetric Key", value: "SymmetricKey" },
    { label: "Secret Data", value: "SecretData" },
];

const buildJoinSplitKeyRequest = (shareIds: string[], objectType: string) => ({
    tag: "JoinSplitKey",
    type: "Structure",
    value: [
        { tag: "ObjectType", type: "Enumeration", value: objectType },
        ...shareIds.map((id) => ({
            tag: "PrivateKeyUniqueIdentifier",
            type: "TextString",
            value: id,
        })),
        { tag: "SplitKeyMethod", type: "Enumeration", value: "XOR" },
    ],
});

type JoinSplitKeyResponse = {
    tag: string;
    type: string;
    value: { tag: string; type: string; value: string }[];
};

const JoinSplitKeyForm: React.FC = () => {
    const [form] = Form.useForm<JoinSplitKeyFormData>();
    const { res, isLoading, responseRef, serverUrl, execute } = useActionState();
    const [shareCount, setShareCount] = useState<number>(3);

    const onLocateSelect = useCallback(
        (index: number, uid: string) => {
            const currentShares: { value: string }[] = form.getFieldValue("shareIds") || [];
            const updated = [...currentShares];
            if (index < updated.length) {
                updated[index] = { value: uid };
            }
            form.setFieldsValue({ shareIds: updated });
        },
        [form],
    );

    const onShareCountChange = useCallback(
        (value: number | null) => {
            const count = value ?? 2;
            setShareCount(count);
            form.setFieldsValue({
                shareIds: Array.from({ length: count }, () => ({ value: "" })),
            });
        },
        [form],
    );

    const onFinish = async (values: JoinSplitKeyFormData) => {
        await execute(async () => {
            const shareIds = values.shareIds.map((item) => item.value).filter((v) => v && v.trim().length > 0);
            if (shareIds.length < 2) {
                throw new Error("At least 2 share UIDs are required to reconstruct a key.");
            }
            const request = buildJoinSplitKeyRequest(shareIds, values.objectType);
            const resultStr = await sendKmipRequest(request, serverUrl);
            if (resultStr) {
                const parsed: JoinSplitKeyResponse = JSON.parse(resultStr);
                const uid = parsed.value.find((item) => item.tag === "UniqueIdentifier");
                if (uid) {
                    return `Key successfully reconstructed from ${shareIds.length} shares.\nReconstructed key UID: ${uid.value}`;
                }
                return `Join operation completed. Response: ${resultStr}`;
            }
        });
    };

    const initialValues = {
        objectType: "SymmetricKey" as const,
        shareIds: Array.from({ length: shareCount }, () => ({ value: "" })),
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">Join Split Key</h1>

            <div className="mb-8 space-y-2">
                <p>Reconstruct a key from XOR split-key shares (n-of-n):</p>
                <ul className="list-disc pl-5 space-y-1">
                    <li>
                        <strong>All n shares are required</strong> — provide every share UID from the split operation.
                    </li>
                    <li>Set the share count to match the number of parts used when the key was split.</li>
                    <li>
                        To activate a <strong>Crypto Officer ceremony</strong>, use{" "}
                        <strong>Access → Crypto Officer Role → Activate Ceremony</strong> instead.
                    </li>
                </ul>
            </div>

            <Form form={form} onFinish={onFinish} layout="vertical" initialValues={initialValues}>
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <Form.Item label="Number of shares (n)" name="shareCount">
                            <InputNumber
                                min={2}
                                max={20}
                                value={shareCount}
                                onChange={onShareCountChange}
                                data-testid="share-count-input"
                            />
                        </Form.Item>

                        <Form.List name="shareIds">
                            {(fields) => (
                                <>
                                    <label className="block font-medium mb-2">Share Unique Identifiers</label>
                                    {fields.map((field, index) => (
                                        <Form.Item key={field.key} required>
                                            <Space align="baseline" className="w-full">
                                                <Form.Item
                                                    {...field}
                                                    name={[field.name, "value"]}
                                                    rules={[{ required: true, message: "Share UID is required" }]}
                                                    noStyle
                                                >
                                                    <Input
                                                        placeholder={`Share ${index + 1} UID`}
                                                        style={{ width: 400 }}
                                                        data-testid={`join-share-id-${index}`}
                                                    />
                                                </Form.Item>
                                                <LocateButton
                                                    objectType="SplitKey"
                                                    onSelect={(uid: string) => onLocateSelect(index, uid)}
                                                />
                                            </Space>
                                        </Form.Item>
                                    ))}
                                </>
                            )}
                        </Form.List>

                        <Form.Item name="objectType" label="Reconstructed Object Type" rules={[{ required: true }]}>
                            <select data-testid="join-object-type-select" className="ant-select-selector w-full border rounded p-2">
                                {OBJECT_TYPES_OPTIONS.map((opt) => (
                                    <option key={opt.value} value={opt.value}>
                                        {opt.label}
                                    </option>
                                ))}
                            </select>
                        </Form.Item>
                    </Card>

                    <Form.Item>
                        <Button
                            type="primary"
                            htmlType="submit"
                            loading={isLoading}
                            className="w-full text-white font-medium"
                            data-testid="join-split-key-submit-btn"
                        >
                            Join Split Key
                        </Button>
                    </Form.Item>
                </Space>
                <ActionResponse res={res} responseRef={responseRef} title="Join Split Key Response" />
            </Form>
        </div>
    );
};

export default JoinSplitKeyForm;
