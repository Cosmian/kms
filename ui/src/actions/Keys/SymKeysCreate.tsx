import { Button, Card, Checkbox, Divider, Form, Input, InputNumber, Select, Space } from "antd";
import React, { useEffect, useState } from "react";
import { sendKmipRequest } from "../../utils/utils";
import * as wasm from "../../wasm/pkg";
import { useActionState } from "../../hooks/useActionState";
import { ActionResponse } from "../../components/common/ActionResponse";

interface SymKeyCreateFormData {
    keyId?: string;
    algorithm: string; // options provided by WASM get_symmetric_algorithms()
    numberOfBits?: number;
    bytesB64?: string;
    tags: string[];
    sensitive: boolean;
    wrappingKeyId?: string;
    enrollKeyset: boolean;
    rotateInterval?: number;
    rotateOffset?: number;
}

type CreateResponse = {
    ObjectType: string;
    UniqueIdentifier: string;
};

const SymKeyCreateForm: React.FC = () => {
    const [form] = Form.useForm<SymKeyCreateFormData>();
    const { res, isLoading, responseRef, serverUrl, execute } = useActionState();
    const [algoOptions, setAlgoOptions] = useState<{ value: string; label: string }[]>([]);

    useEffect(() => {
        try {
            const w = wasm as unknown as { get_symmetric_algorithms?: () => { value: string; label: string }[] };
            const opts = w.get_symmetric_algorithms ? w.get_symmetric_algorithms() : [];
            setAlgoOptions(opts);
        } catch (e) {
            console.error("Error loading symmetric algorithms from WASM:", e);
        }
    }, []);

    const onFinish = async (values: SymKeyCreateFormData) => {
        await execute(async () => {
            const request = wasm.create_sym_key_ttlv_request(
                values.keyId,
                values.tags,
                values.numberOfBits,
                values.algorithm,
                values.sensitive,
                values.wrappingKeyId,
                values.bytesB64,
            );
            const result_str = await sendKmipRequest(request, serverUrl);
            if (result_str) {
                const result: CreateResponse = await wasm.parse_create_ttlv_response(result_str);
                const keyId = result.UniqueIdentifier;

                // Apply rotation policy if any fields were provided
                if (values.enrollKeyset || values.rotateInterval !== undefined || values.rotateOffset !== undefined) {
                    if (values.rotateInterval !== undefined) {
                        const req = wasm.set_rotate_interval_ttlv_request(keyId, BigInt(values.rotateInterval));
                        await sendKmipRequest(req, idToken, serverUrl);
                    }
                    if (values.rotateOffset !== undefined) {
                        const req = wasm.set_rotate_offset_ttlv_request(keyId, BigInt(values.rotateOffset));
                        await sendKmipRequest(req, idToken, serverUrl);
                    }
                    if (values.enrollKeyset) {
                        // rotation name must equal the key ID for SQL-backed keys
                        const req = wasm.set_rotate_name_ttlv_request(keyId, keyId);
                        await sendKmipRequest(req, idToken, serverUrl);
                    }
                }

                return `${keyId} has been created.`;
            }
        });
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">Create a symmetric key</h1>

            <div className="mb-8 space-y-2">
                <p>Create a new symmetric key:</p>
                <ul className="list-disc pl-5 space-y-1">
                    <li>When bytes are specified, the key will be created from the provided bytes.</li>
                    <li>Otherwise, the key will be randomly generated with the specified number of bits.</li>
                    <li>If no options are specified, a fresh 256-bit AES key will be created.</li>
                </ul>
            </div>

            <Form
                form={form}
                onFinish={onFinish}
                layout="vertical"
                initialValues={{
                    algorithm: "Aes",
                    numberOfBits: 256,
                    tags: [],
                    sensitive: false,
                    enrollKeyset: false,
                }}
            >
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <Form.Item name="algorithm" label="Algorithm" rules={[{ required: true, message: "Please select an algorithm" }]}>
                            <Select options={algoOptions} />
                        </Form.Item>

                        <Form.Item name="numberOfBits" label="Number of Bits" help="The length of the generated random key in bits">
                            <InputNumber className="w-[200px]" min={128} step={128} max={512} />
                        </Form.Item>

                        <Form.Item
                            name="bytesB64"
                            label="Key Bytes (Base64)"
                            help="Optional: specify the key bytes directly instead of generating random ones"
                        >
                            <Input.TextArea placeholder="Enter base64 encoded key bytes" rows={4} />
                        </Form.Item>

                        <Form.Item name="keyId" label="Key ID" help="Optional: a random UUID will be generated if not specified">
                            <Input placeholder="Enter key ID" />
                        </Form.Item>

                        <Form.Item name="tags" label="Tags" help="Optional: Add tags to help retrieve the key later">
                            <Select mode="tags" placeholder="Enter tags" open={false} />
                        </Form.Item>

                        <Form.Item name="wrappingKeyId" label="Wrapping Key ID" help="Optional: ID of the key to wrap this new key with">
                            <Input placeholder="Enter wrapping key ID" />
                        </Form.Item>

                        <Form.Item name="sensitive" valuePropName="checked" help="If set, the key will not be exportable">
                            <Checkbox>Sensitive</Checkbox>
                        </Form.Item>

                        <Divider orientation="left" plain>
                            Rotation Policy (optional)
                        </Divider>

                        <Form.Item
                            name="enrollKeyset"
                            valuePropName="checked"
                            help="When checked, the rotation name is set to the key ID so this key can be addressed via name@latest, name@first, name@N"
                        >
                            <Checkbox data-testid="sym-enroll-keyset">Enroll in keyset (rotation name = key ID)</Checkbox>
                        </Form.Item>

                        <Form.Item noStyle shouldUpdate={(prev, curr) => prev.enrollKeyset !== curr.enrollKeyset}>
                            {({ getFieldValue }) =>
                                getFieldValue("enrollKeyset") ? (
                                    <>
                                        <Form.Item
                                            name="rotateInterval"
                                            label="Rotation Interval (seconds)"
                                            help="Auto-rotate the key every N seconds. Set 0 to disable."
                                        >
                                            <InputNumber
                                                className="w-[200px]"
                                                min={0}
                                                placeholder="e.g. 86400"
                                                data-testid="sym-rotation-interval"
                                            />
                                        </Form.Item>

                                        <Form.Item
                                            name="rotateOffset"
                                            label="Rotation Offset (seconds)"
                                            help="Delay before the first rotation occurs."
                                        >
                                            <InputNumber
                                                className="w-[200px]"
                                                min={0}
                                                placeholder="e.g. 3600"
                                                data-testid="sym-rotation-offset"
                                            />
                                        </Form.Item>
                                    </>
                                ) : null
                            }
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
                            Create Symmetric Key
                        </Button>
                    </Form.Item>
                </Space>
                <ActionResponse res={res} responseRef={responseRef} title="Symmetric keys creation response" />
            </Form>
        </div>
    );
};

export default SymKeyCreateForm;
