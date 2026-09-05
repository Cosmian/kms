import { Button, Card, Form, Input, InputNumber, Radio, Select, Space, Tag } from "antd";
import React, { useEffect, useState } from "react";
import { Trans, useTranslation } from "react-i18next";
import { getNoTTLVRequest, sendKmipRequest } from "../../utils/utils";
import {
    create_secret_data_ttlv_request,
    derive_key_asymmetric_ttlv_request,
    derive_key_ttlv_request,
    parse_derive_key_asymmetric_ttlv_response,
    parse_derive_key_ttlv_response,
    parse_import_ttlv_response,
} from "../../wasm/pkg";
import { useActionState } from "../../hooks/useActionState";
import KeyIdInput from "../../components/common/KeyIdInput";

const HASHING_ALGORITHMS = [
    { label: "SHA-256", value: "SHA256" },
    { label: "SHA-384", value: "SHA384" },
    { label: "SHA-512", value: "SHA512" },
    { label: "SHA3-256", value: "SHA3256" },
    { label: "SHA3-384", value: "SHA3384" },
    { label: "SHA3-512", value: "SHA3512" },
];

const SYMMETRIC_ALGORITHMS = [
    { label: "AES", value: "Aes" },
    { label: "ChaCha20", value: "Chacha20" },
];

const KEY_LENGTHS = [{ length: 128 }, { length: 192 }, { length: 256 }];

const HEX_PATTERN = /^[0-9a-fA-F]+$/;

function hexToBytes(hex: string): Uint8Array {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
    }
    return bytes;
}

interface DeriveKeyFormData {
    sourceType: "key_id" | "password";
    keyId?: string;
    password?: string;
    derivationMethod: "PBKDF2" | "HKDF" | "X25519";
    salt: string;
    iterationCount: number;
    initializationVector?: string;
    hashingAlgorithm: string;
    symmetricAlgorithm: string;
    cryptographicLength: number;
    derivedKeyId?: string;
    // X25519 ECDH (asymmetric) fields
    privateKeyId?: string;
    peerPublicKeyId?: string;
}

type ImportResponse = { UniqueIdentifier: string };
type DeriveKeyResponse = { UniqueIdentifier: string };

const DeriveKeyForm: React.FC = () => {
    const [form] = Form.useForm<DeriveKeyFormData>();
    const { res, isLoading, responseRef, serverUrl, execute } = useActionState();
    const { t } = useTranslation("actions");
    const sourceType = Form.useWatch("sourceType", form);
    const derivationMethod = Form.useWatch("derivationMethod", form);
    const isAsymmetric = derivationMethod === "X25519";
    // X25519 ECDH derivation is not supported in FIPS mode: the server rejects
    // `derive_key_asymmetric` with `NotSupported`. Query `/server-info` once to hide/disable
    // the option so users are never directed toward a request that can never succeed.
    const [isFips, setIsFips] = useState(false);
    useEffect(() => {
        let cancelled = false;
        const checkFips = async () => {
            try {
                const info = await getNoTTLVRequest("/server-info", serverUrl);
                if (!cancelled) setIsFips(Boolean((info as { fips_mode?: boolean })?.fips_mode));
            } catch {
                // Server info unavailable: default to non-FIPS (option remains visible).
            }
        };
        void checkFips();
        return () => {
            cancelled = true;
        };
    }, [serverUrl]);

    const onFinish = async (values: DeriveKeyFormData) => {
        await execute(async () => {
            if (isAsymmetric) {
                if (!values.privateKeyId) throw new Error(t("deriveKey.privateKeyIdRequired"));
                if (!values.peerPublicKeyId) throw new Error(t("deriveKey.peerPublicKeyIdRequired"));

                const request = derive_key_asymmetric_ttlv_request(
                    values.privateKeyId,
                    values.peerPublicKeyId,
                    values.derivedKeyId || null,
                );

                const resultStr = await sendKmipRequest(request, serverUrl);
                if (resultStr) {
                    const result: DeriveKeyResponse = await parse_derive_key_asymmetric_ttlv_response(resultStr);
                    return t("deriveKey.success", { keyId: result.UniqueIdentifier });
                }
                return;
            }

            let baseKeyId: string;

            if (values.sourceType === "password") {
                if (!values.password) {
                    throw new Error(t("deriveKey.passwordRequired"));
                }
                // Import password as a SecretData object, then derive from it
                const importRequest = create_secret_data_ttlv_request("Password", values.password, undefined, [], true);
                const importStr = await sendKmipRequest(importRequest, serverUrl);
                if (!importStr) throw new Error(t("deriveKey.importPasswordFailed"));
                const importResp: ImportResponse = await parse_import_ttlv_response(importStr);
                baseKeyId = importResp.UniqueIdentifier;
            } else {
                if (!values.keyId) throw new Error(t("deriveKey.keyIdRequired"));
                baseKeyId = values.keyId;
            }

            const saltBytes = hexToBytes(values.salt);
            const ivBytes =
                values.initializationVector && values.initializationVector.length > 0 ? hexToBytes(values.initializationVector) : undefined;

            const request = derive_key_ttlv_request(
                baseKeyId,
                values.derivationMethod,
                saltBytes,
                values.iterationCount,
                ivBytes,
                values.hashingAlgorithm,
                values.symmetricAlgorithm,
                values.cryptographicLength,
                values.derivedKeyId || null,
            );

            const resultStr = await sendKmipRequest(request, serverUrl);
            if (resultStr) {
                const result: DeriveKeyResponse = await parse_derive_key_ttlv_response(resultStr);
                return t("deriveKey.success", { keyId: result.UniqueIdentifier });
            }
        });
    };

    return (
        <div className="rounded-lg p-6 m-4">
            <h1 className="text-2xl font-bold mb-6">{t("deriveKey.title")}</h1>

            <div className="mb-8 space-y-2">
                <p>{t("deriveKey.intro")}</p>
                <ul className="list-disc pl-5 space-y-1">
                    <li>
                        <Trans ns="actions" i18nKey="deriveKey.introKeyId" components={{ strong: <strong />, em: <em /> }} />
                    </li>
                    <li>
                        <Trans ns="actions" i18nKey="deriveKey.introPassword" components={{ strong: <strong /> }} />
                    </li>
                    <li>{t("deriveKey.introSalt")}</li>
                    <li>
                        <Trans ns="actions" i18nKey="deriveKey.introX25519" components={{ strong: <strong /> }} />
                    </li>
                </ul>
            </div>

            <Form
                form={form}
                onFinish={onFinish}
                layout="vertical"
                initialValues={{
                    sourceType: "key_id",
                    derivationMethod: "PBKDF2",
                    iterationCount: 4096,
                    hashingAlgorithm: "SHA256",
                    symmetricAlgorithm: "Aes",
                    cryptographicLength: 256,
                }}
            >
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    {/* Derivation method */}
                    <Card title={t("deriveKey.methodCard")}>
                        <Form.Item name="derivationMethod" label={t("deriveKey.derivationMethod")}>
                            <Radio.Group>
                                <Radio value="PBKDF2" data-testid="derivation-method-pbkdf2">
                                    PBKDF2
                                </Radio>
                                <Radio value="HKDF" data-testid="derivation-method-hkdf">
                                    HKDF
                                </Radio>
                                <Radio value="X25519" data-testid="derivation-method-x25519" disabled={isFips}>
                                    {t("deriveKey.x25519Method")}
                                    {isFips && (
                                        <Tag color="orange" style={{ marginLeft: 8 }}>
                                            {t("deriveKey.nonFipsOnly")}
                                        </Tag>
                                    )}
                                </Radio>
                            </Radio.Group>
                        </Form.Item>
                    </Card>

                    {isAsymmetric ? (
                        /* X25519 ECDH key agreement */
                        <Card title={t("deriveKey.x25519Card")}>
                            <p className="mb-4 text-sm text-gray-500 dark:text-gray-400">{t("deriveKey.x25519Intro")}</p>
                            <KeyIdInput
                                form={form}
                                fieldName="privateKeyId"
                                label={t("deriveKey.privateKeyId")}
                                help={t("deriveKey.privateKeyIdHelp")}
                                objectType="PrivateKey"
                                rules={[{ required: true, message: t("deriveKey.pleaseEnterPrivateKeyId") }]}
                                placeholder={t("deriveKey.enterPrivateKeyId")}
                            />

                            <KeyIdInput
                                form={form}
                                fieldName="peerPublicKeyId"
                                label={t("deriveKey.peerPublicKeyId")}
                                help={t("deriveKey.peerPublicKeyIdHelp")}
                                objectType="PublicKey"
                                rules={[{ required: true, message: t("deriveKey.pleaseEnterPeerPublicKeyId") }]}
                                placeholder={t("deriveKey.enterPeerPublicKeyId")}
                            />

                            <Form.Item name="derivedKeyId" label={t("deriveKey.derivedKeyId")} help={t("deriveKey.derivedKeyIdHelp")}>
                                <Input placeholder={t("deriveKey.derivedKeyIdPlaceholder")} />
                            </Form.Item>
                        </Card>
                    ) : (
                        <>
                            {/* Source */}
                            <Card title={t("deriveKey.sourceCard")}>
                                <Form.Item name="sourceType" label={t("deriveKey.sourceType")}>
                                    <Radio.Group>
                                        <Radio value="key_id">{t("deriveKey.existingKeyId")}</Radio>
                                        <Radio value="password">{t("deriveKey.password")}</Radio>
                                    </Radio.Group>
                                </Form.Item>

                                {sourceType === "key_id" && (
                                    <KeyIdInput
                                        form={form}
                                        fieldName="keyId"
                                        label={t("common:keyId")}
                                        help={t("deriveKey.keyIdHelp")}
                                        rules={[{ required: true, message: t("deriveKey.pleaseEnterSourceKeyId") }]}
                                        placeholder={t("deriveKey.enterSourceKeyId")}
                                    />
                                )}

                                {sourceType === "password" && (
                                    <Form.Item
                                        name="password"
                                        label={t("deriveKey.password")}
                                        rules={[{ required: true, message: t("deriveKey.pleaseEnterPassword") }]}
                                        help={t("deriveKey.passwordHelp")}
                                    >
                                        <Input.Password placeholder={t("deriveKey.enterPassword")} />
                                    </Form.Item>
                                )}
                            </Card>

                            {/* Derivation parameters */}
                            <Card title={t("deriveKey.paramsCard")}>
                                <Form.Item
                                    name="salt"
                                    label={t("deriveKey.salt")}
                                    rules={[
                                        { required: true, message: t("deriveKey.pleaseEnterSalt") },
                                        {
                                            pattern: HEX_PATTERN,
                                            message: t("deriveKey.saltHexError"),
                                        },
                                        {
                                            validator: (_, value: string) =>
                                                value && value.length % 2 !== 0
                                                    ? Promise.reject(new Error(t("deriveKey.saltEvenError")))
                                                    : Promise.resolve(),
                                        },
                                    ]}
                                    help={t("deriveKey.saltHelp")}
                                >
                                    <Input placeholder={t("deriveKey.saltPlaceholder")} />
                                </Form.Item>

                                {derivationMethod === "PBKDF2" && (
                                    <Form.Item
                                        name="iterationCount"
                                        label={t("deriveKey.iterationCount")}
                                        help={t("deriveKey.iterationCountHelp")}
                                        rules={[{ required: true, message: t("deriveKey.pleaseEnterIterationCount") }]}
                                    >
                                        <InputNumber min={1} style={{ width: "100%" }} />
                                    </Form.Item>
                                )}

                                <Form.Item
                                    name="initializationVector"
                                    label={t("deriveKey.initializationVector")}
                                    rules={[
                                        {
                                            pattern: /^([0-9a-fA-F]{2})*$/,
                                            message: t("deriveKey.ivHexError"),
                                        },
                                    ]}
                                    help={t("deriveKey.ivHelp")}
                                >
                                    <Input placeholder={t("deriveKey.ivPlaceholder")} />
                                </Form.Item>

                                <Form.Item
                                    name="hashingAlgorithm"
                                    label={t("deriveKey.hashingAlgorithm")}
                                    rules={[{ required: true, message: t("deriveKey.pleaseSelectHashingAlgorithm") }]}
                                    help={t("deriveKey.hashingAlgorithmHelp")}
                                >
                                    <Select data-testid="hashing-algorithm-select" options={HASHING_ALGORITHMS} />
                                </Form.Item>
                            </Card>

                            {/* Output key specification */}
                            <Card title={t("deriveKey.outputCard")}>
                                <Form.Item
                                    name="symmetricAlgorithm"
                                    label={t("deriveKey.algorithm")}
                                    rules={[{ required: true, message: t("deriveKey.pleaseSelectOutputAlgorithm") }]}
                                    help={t("deriveKey.algorithmHelp")}
                                >
                                    <Select data-testid="symmetric-algorithm-select" options={SYMMETRIC_ALGORITHMS} />
                                </Form.Item>

                                <Form.Item
                                    name="cryptographicLength"
                                    label={t("deriveKey.keyLength")}
                                    rules={[{ required: true, message: t("deriveKey.pleaseSelectKeyLength") }]}
                                    help={t("deriveKey.keyLengthHelp")}
                                >
                                    <Select
                                        data-testid="key-length-select"
                                        options={KEY_LENGTHS.map((o) => ({
                                            value: o.length,
                                            label: t("deriveKey.bitsLabel", { length: o.length }),
                                        }))}
                                    />
                                </Form.Item>

                                <Form.Item name="derivedKeyId" label={t("deriveKey.derivedKeyId")} help={t("deriveKey.derivedKeyIdHelp")}>
                                    <Input placeholder={t("deriveKey.derivedKeyIdPlaceholder")} />
                                </Form.Item>
                            </Card>
                        </>
                    )}

                    <Button type="primary" htmlType="submit" loading={isLoading} data-testid="submit-btn">
                        {t("deriveKey.submit")}
                    </Button>
                </Space>
            </Form>

            {res && (
                <div ref={responseRef} data-testid="response-output" className="mt-6 p-4 rounded-lg bg-gray-100 dark:bg-gray-800 break-all">
                    <pre className="whitespace-pre-wrap text-sm">{res}</pre>
                </div>
            )}
        </div>
    );
};

export default DeriveKeyForm;
