import { Button, Card, Checkbox, Divider, Form, Input, InputNumber, Select, Space } from "antd";
import React, { useEffect, useState } from "react";
import { useBranding } from "../../contexts/useBranding";
import { sendKmipRequest } from "../../utils/utils";
import * as wasm from "../../wasm/pkg";
import { useActionState } from "../../hooks/useActionState";
import { ActionResponse } from "../../components/common/ActionResponse";

interface PqcKeyCreateFormData {
    algorithm: string;
    tags: string[];
    sensitive: boolean;
    enrollKeyset: boolean;
    rotateInterval?: number;
    rotateOffset?: number;
}

type CreateKeyPairResponse = {
    PrivateKeyUniqueIdentifier: string;
    PublicKeyUniqueIdentifier: string;
};

const PqcKeysCreateForm: React.FC = () => {
    const [form] = Form.useForm<PqcKeyCreateFormData>();
    const { res, isLoading, responseRef, serverUrl, execute } = useActionState();
    const branding = useBranding();
    const [algorithmOptions, setAlgorithmOptions] = useState<{ value: string; label: string }[]>([]);

    useEffect(() => {
        try {
            const w = wasm as unknown as { get_pqc_algorithms?: () => { value: string; label: string }[] };
            const opts = w.get_pqc_algorithms ? w.get_pqc_algorithms() : [];
            const hidden = branding.hiddenPqcAlgorithms ?? [];
            setAlgorithmOptions(opts.filter((o) => !hidden.includes(o.value)));
        } catch (e) {
            console.error("Error loading PQC algorithms from WASM:", e);
        }
    }, [branding.hiddenPqcAlgorithms]);

    useEffect(() => {
        if (algorithmOptions.length > 0) {
            const current = form.getFieldValue("algorithm");
            if (!current) {
                form.setFieldsValue({ algorithm: algorithmOptions[0].value });
            }
        }
    }, [algorithmOptions, form]);

    const onFinish = async (values: PqcKeyCreateFormData) => {
        await execute(async () => {
            const request = wasm.create_pqc_key_pair_ttlv_request(values.tags, values.algorithm, values.sensitive);
            const result_str = await sendKmipRequest(request, serverUrl);
            if (result_str) {
                const result: CreateKeyPairResponse = await wasm.parse_create_keypair_ttlv_response(result_str);
                const skId = result.PrivateKeyUniqueIdentifier;

                // Apply rotation policy on the private key (keyset anchor)
                if (values.enrollKeyset || values.rotateInterval !== undefined || values.rotateOffset !== undefined) {
                    if (values.rotateInterval !== undefined) {
                        const req = wasm.set_rotate_interval_ttlv_request(skId, BigInt(values.rotateInterval));
                        await sendKmipRequest(req, idToken, serverUrl);
                    }
                    if (values.rotateOffset !== undefined) {
                        const req = wasm.set_rotate_offset_ttlv_request(skId, BigInt(values.rotateOffset));
                        await sendKmipRequest(req, idToken, serverUrl);
                    }
                    if (values.enrollKeyset) {
                        // rotation name is set to the private key ID (server-generated for PQC)
                        const req = wasm.set_rotate_name_ttlv_request(skId, skId);
                        await sendKmipRequest(req, idToken, serverUrl);
                    }
                }

                return `Key pair has been created. Private key Id: ${skId} - Public key Id: ${result.PublicKeyUniqueIdentifier}`;
            }
        });
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">Create a Post-Quantum key pair</h1>
            <div className="mb-8 space-y-2">
                <p>Create a new Post-Quantum Cryptography key pair:</p>
                <ul className="list-disc pl-5 space-y-1">
                    <li>
                        <strong>ML-KEM</strong> (Key Encapsulation Mechanism): the public key is used to encapsulate a shared secret, and
                        the private key to decapsulate it.
                    </li>
                    <li>
                        <strong>Hybrid KEM</strong> (X25519MLKEM768, X448MLKEM1024): combines a classical key exchange with ML-KEM for
                        hybrid post-quantum key encapsulation.
                    </li>
                    <li>
                        <strong>ML-DSA</strong> (Digital Signature Algorithm): the private key is used to sign data, and the public key to
                        verify the signature.
                    </li>
                    <li>
                        <strong>SLH-DSA</strong> (Stateless Hash-Based Signature): a hash-based signature scheme offering an alternative
                        post-quantum signature approach.
                    </li>
                </ul>
                <p>When creating a key pair with a specified tag, the tag is applied to both keys.</p>
            </div>

            <Form
                form={form}
                onFinish={onFinish}
                layout="vertical"
                initialValues={{
                    tags: [],
                    sensitive: false,
                    enrollKeyset: false,
                }}
            >
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <Form.Item
                            name="algorithm"
                            label="Algorithm"
                            help="Select the PQC algorithm to use"
                            rules={[{ required: true, message: "Please select an algorithm" }]}
                        >
                            <Select options={algorithmOptions} data-testid="pqc-algorithm-select" />
                        </Form.Item>

                        <Form.Item name="tags" label="Tags" help="Optional: Add tags to help retrieve the keys later">
                            <Select mode="tags" placeholder="Enter tags" open={false} />
                        </Form.Item>

                        <Form.Item name="sensitive" valuePropName="checked" help="If set, the private key will not be exportable">
                            <Checkbox>Sensitive</Checkbox>
                        </Form.Item>

                        <Divider orientation="left" plain>
                            Rotation Policy (optional)
                        </Divider>

                        <Form.Item
                            name="rotateName"
                            label="Rotation Name"
                            help="Keyset name for addressing generations via name@latest, name@first, name@N"
                        >
                            <Input placeholder="e.g. my-keyset" data-testid="pqc-rotation-name" />
                        </Form.Item>

                        <Form.Item
                            name="rotateInterval"
                            label="Rotation Interval (seconds)"
                            help="Auto-rotate the key pair every N seconds. Set 0 to disable."
                        >
                            <InputNumber className="w-[200px]" min={0} placeholder="e.g. 86400" data-testid="pqc-rotation-interval" />
                        </Form.Item>

                        <Form.Item name="rotateOffset" label="Rotation Offset (seconds)" help="Delay before the first rotation occurs.">
                            <InputNumber className="w-[200px]" min={0} placeholder="e.g. 3600" data-testid="pqc-rotation-offset" />
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
                            Create PQC Keypair
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            <ActionResponse res={res} responseRef={responseRef} title="PQC key pair creation response" />
        </div>
    );
};

export default PqcKeysCreateForm;
