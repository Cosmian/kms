import { Button, Card, Form, Input, Select, Space } from "antd";
import React from "react";
import { ActionResponse } from "../../components/common/ActionResponse";
import { useActionState } from "../../hooks/useActionState";
import { sendKmipRequest } from "../../utils/utils";
import {
    parse_rekey_keypair_ttlv_response,
    parse_rekey_ttlv_response,
    rekey_keypair_ttlv_request,
    rekey_ttlv_request,
} from "../../wasm/pkg/cosmian_kms_client_wasm";

/** Key types supported by the ReKey operation. */
type ReKeyType = "symmetric" | "rsa" | "ec" | "pqc";

interface ReKeyFormData {
    keyId?: string;
    tags?: string[];
}

interface ReKeyKeyPairResponse {
    PrivateKeyUniqueIdentifier: string;
    PublicKeyUniqueIdentifier: string;
}

interface ReKeySymmetricResponse {
    UniqueIdentifier: string;
}

interface ReKeyConfig {
    title: string;
    description: string;
    bullets: string[];
    keyLabel: string;
    isKeyPair: boolean;
}

const REKEY_CONFIG: Record<ReKeyType, ReKeyConfig> = {
    symmetric: {
        title: "Re-Key a symmetric key",
        description: "Refresh an existing symmetric key, generating a new key value.",
        bullets: [
            "The old key is deactivated and a new key is created as its replacement.",
            "The rotation generation counter is incremented on the new key.",
        ],
        keyLabel: "Key ID",
        isKeyPair: false,
    },
    rsa: {
        title: "Re-Key an RSA key pair",
        description: "Rotate an existing RSA key pair, generating new key material.",
        bullets: [
            "A new private key and public key are created with the same algorithm and key size.",
            "The old key pair is linked to the new one via replacement links.",
            "The rotation generation counter is incremented on the new key.",
        ],
        keyLabel: "Private Key ID",
        isKeyPair: true,
    },
    ec: {
        title: "Re-Key an Elliptic Curve key pair",
        description: "Rotate an existing EC key pair, generating new key material.",
        bullets: [
            "A new private key and public key are created with the same curve.",
            "The old key pair is linked to the new one via replacement links.",
            "The rotation generation counter is incremented on the new key.",
        ],
        keyLabel: "Private Key ID",
        isKeyPair: true,
    },
    pqc: {
        title: "Re-Key a Post-Quantum key pair",
        description: "Rotate an existing post-quantum key pair (ML-KEM, ML-DSA), generating new key material.",
        bullets: [
            "A new private key and public key are created with the same algorithm.",
            "The old key pair is linked to the new one via replacement links.",
            "The rotation generation counter is incremented on the new key.",
        ],
        keyLabel: "Private Key ID",
        isKeyPair: true,
    },
};

function buildSuccessMessage(keyType: ReKeyType, response: ReKeySymmetricResponse | ReKeyKeyPairResponse): string {
    if (keyType === "symmetric") {
        return `The symmetric key was successfully refreshed. New key: ${(response as ReKeySymmetricResponse).UniqueIdentifier}`;
    }
    const kpResponse = response as ReKeyKeyPairResponse;
    const typeLabel = keyType === "rsa" ? "RSA" : keyType === "ec" ? "EC" : "post-quantum";
    return `The ${typeLabel} key pair was successfully rotated.\nNew private key: ${kpResponse.PrivateKeyUniqueIdentifier}\nNew public key: ${kpResponse.PublicKeyUniqueIdentifier}`;
}

interface ObjectsReKeyProps {
    keyType: ReKeyType;
}

/**
 * Generic Re-Key form for symmetric keys and asymmetric key pairs.
 *
 * Renders appropriate titles, descriptions, and calls the correct WASM function
 * depending on the {@link ReKeyType} prop.
 */
const ObjectsReKeyForm: React.FC<ObjectsReKeyProps> = ({ keyType }) => {
    const [form] = Form.useForm<ReKeyFormData>();
    const { res, isLoading, responseRef, idToken, serverUrl, execute } = useActionState();

    const config = REKEY_CONFIG[keyType];

    const onFinish = async (values: ReKeyFormData) => {
        const id = values.keyId || (values.tags?.length ? JSON.stringify(values.tags) : undefined);
        await execute(async () => {
            if (!id) {
                throw new Error(`Please provide a ${config.keyLabel.toLowerCase()} or at least one tag.`);
            }
            if (config.isKeyPair) {
                const request = rekey_keypair_ttlv_request(id);
                const resultStr = await sendKmipRequest(request, idToken, serverUrl);
                if (resultStr) {
                    const result = parse_rekey_keypair_ttlv_response(resultStr) as ReKeyKeyPairResponse;
                    return buildSuccessMessage(keyType, result);
                }
            } else {
                const request = rekey_ttlv_request(id);
                const resultStr = await sendKmipRequest(request, idToken, serverUrl);
                if (resultStr) {
                    const result = parse_rekey_ttlv_response(resultStr) as ReKeySymmetricResponse;
                    return buildSuccessMessage(keyType, result);
                }
            }
        });
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">{config.title}</h1>

            <div className="mb-8 space-y-2">
                <p>{config.description}</p>
                <ul className="list-disc pl-5 space-y-1">
                    {config.bullets.map((bullet) => (
                        <li key={bullet}>{bullet}</li>
                    ))}
                </ul>
            </div>

            <Form form={form} onFinish={onFinish} layout="vertical">
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <Form.Item
                            name="keyId"
                            label={config.keyLabel}
                            help={`The unique identifier of the ${config.keyLabel.toLowerCase()} to re-key`}
                        >
                            <Input
                                placeholder={`Enter the unique identifier of the ${config.keyLabel.toLowerCase()} to re-key`}
                                data-testid="rekey-key-id"
                            />
                        </Form.Item>
                        <Form.Item name="tags" label="Tags" help={`Alternative to ${config.keyLabel}: specify tags to identify the key`}>
                            <Select mode="tags" placeholder="Enter tags" open={false} data-testid="rekey-tags" />
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
                            Re-Key
                        </Button>
                    </Form.Item>
                </Space>
                <ActionResponse res={res} responseRef={responseRef} title="Re-Key response" />
            </Form>
        </div>
    );
};

export default ObjectsReKeyForm;
