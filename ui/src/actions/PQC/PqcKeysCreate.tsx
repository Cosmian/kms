import { Button, Card, Checkbox, Form, Select, Space } from "antd";
import React, { useEffect, useRef, useState } from "react";
import { useAuth } from "../../contexts/AuthContext";
import { useBranding } from "../../contexts/useBranding";
import { sendKmipRequest } from "../../utils/utils";
import * as wasm from "../../wasm/pkg";

interface PqcKeyCreateFormData {
    algorithm: string;
    tags: string[];
    sensitive: boolean;
}

type CreateKeyPairResponse = {
    PrivateKeyUniqueIdentifier: string;
    PublicKeyUniqueIdentifier: string;
};

const PqcKeysCreateForm: React.FC = () => {
    const [form] = Form.useForm<PqcKeyCreateFormData>();
    const [res, setRes] = useState<undefined | string>(undefined);
    const [isLoading, setIsLoading] = useState(false);
    const { idToken, serverUrl } = useAuth();
    const branding = useBranding();
    const responseRef = useRef<HTMLDivElement>(null);
    const [algorithmOptions, setAlgorithmOptions] = useState<{ value: string; label: string }[]>([]);

    useEffect(() => {
        if (res && responseRef.current) {
            responseRef.current.scrollIntoView({ behavior: "smooth" });
        }
    }, [res]);

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
        setIsLoading(true);
        setRes(undefined);
        try {
            const request = wasm.create_pqc_key_pair_ttlv_request(values.tags, values.algorithm, values.sensitive);
            const result_str = await sendKmipRequest(request, idToken, serverUrl);
            if (result_str) {
                const result: CreateKeyPairResponse = await wasm.parse_create_keypair_ttlv_response(result_str);
                setRes(
                    `Key pair has been created. Private key Id: ${result.PrivateKeyUniqueIdentifier} - Public key Id: ${result.PublicKeyUniqueIdentifier}`,
                );
            }
        } catch (e) {
            setRes(`Error creating PQC keypair: ${e}`);
            console.error("Error creating PQC keypair:", e);
        } finally {
            setIsLoading(false);
        }
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
            {res && (
                <div ref={responseRef} data-testid="response-output">
                    <Card title="PQC key pair creation response">{res}</Card>
                </div>
            )}
        </div>
    );
};

export default PqcKeysCreateForm;
