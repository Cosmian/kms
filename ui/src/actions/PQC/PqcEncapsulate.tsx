import { Button, Card, Form, Input, Select, Space } from "antd";
import React from "react";
import { downloadFile, sendKmipRequest } from "../../utils/utils";
import { encrypt_ec_ttlv_request, parse_encrypt_ttlv_response } from "../../wasm/pkg";
import { useActionState } from "../../hooks/useActionState";
import { ActionResponse } from "../../components/common/ActionResponse";

interface PqcEncapsulateFormData {
    keyId?: string;
    tags?: string[];
}

const PqcEncapsulateForm: React.FC = () => {
    const [form] = Form.useForm<PqcEncapsulateFormData>();
    const { res, isLoading, responseRef, serverUrl, execute } = useActionState();

    const onFinish = async (values: PqcEncapsulateFormData) => {
        const id = values.keyId ? values.keyId : values.tags ? JSON.stringify(values.tags) : undefined;
        await execute(async () => {
            if (id == undefined) {
                throw new Error("Missing key identifier.");
            }
            // ML-KEM encapsulation: send empty plaintext, server returns shared_secret + ciphertext
            const request = encrypt_ec_ttlv_request(id, new Uint8Array());
            const result_str = await sendKmipRequest(request, serverUrl);
            if (result_str) {
                const response = await parse_encrypt_ttlv_response(result_str);
                const respObj = response as unknown as Record<string, unknown>;

                // shared_secret is in Data, ciphertext is in IVCounterNonce
                const sharedSecret = respObj.Data as Uint8Array | number[] | undefined;
                const ciphertext = respObj.IVCounterNonce as Uint8Array | number[] | undefined;

                if (ciphertext) {
                    const ctBytes = ciphertext instanceof Uint8Array ? ciphertext : new Uint8Array(ciphertext);
                    downloadFile(ctBytes, "encapsulation.bin", "application/octet-stream");
                }

                if (sharedSecret) {
                    const ssBytes = sharedSecret instanceof Uint8Array ? sharedSecret : new Uint8Array(sharedSecret);
                    downloadFile(ssBytes, "shared_secret.key", "application/octet-stream");
                }

                return "Encapsulation successful. Ciphertext and shared secret downloaded.";
            }
        });
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">PQC KEM Encapsulate</h1>

            <div className="mb-8 space-y-2">
                <p>Encapsulate a shared secret using a PQC KEM public key (ML-KEM or Hybrid KEM).</p>
                <p>
                    This produces a <strong>shared secret</strong> and a <strong>ciphertext</strong> (encapsulation).
                </p>
                <p>
                    The ciphertext should be sent to the decapsulating party, who can recover the same shared secret using the corresponding
                    private key.
                </p>
            </div>

            <Form form={form} onFinish={onFinish} layout="vertical">
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <h3 className="text-m font-bold mb-4">Key Identification (required)</h3>
                        <Form.Item name="keyId" label="Public Key ID" help="The unique identifier of the PQC KEM public key">
                            <Input placeholder="Enter public key ID" />
                        </Form.Item>

                        <Form.Item name="tags" label="Tags" help="Alternative to Key ID: specify tags to identify the key">
                            <Select mode="tags" placeholder="Enter tags" open={false} />
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
                            Encapsulate
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            <ActionResponse res={res} responseRef={responseRef} title="PQC KEM encapsulate response" />
        </div>
    );
};

export default PqcEncapsulateForm;
