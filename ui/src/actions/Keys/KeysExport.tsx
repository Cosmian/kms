import { Button, Card, Checkbox, Divider, Form, Input, Select, Space } from "antd";
import React, { useEffect } from "react";
import { useTranslation } from "react-i18next";
import { downloadFile, sendKmipRequest } from "../../utils/utils";
import { export_ttlv_request, parse_export_ttlv_response } from "../../wasm/pkg";
import { useActionState } from "../../hooks/useActionState";

interface KeyExportFormData {
    keyId?: string;
    tags?: string[];
    keyFormat: ExportKeyFormat;
    unwrap: boolean;
    wrapKeyId?: string;
    allowRevoked: boolean;
    wrappingAlgorithm?: WrappingAlgorithm;
    authenticatedAdditionalData?: string;
}

type ExportKeyFormat = "json-ttlv" | "sec1-pem" | "sec1-der" | "pkcs1-pem" | "pkcs1-der" | "pkcs8-pem" | "pkcs8-der" | "base64" | "raw";

type WrappingAlgorithm = "aes-key-wrap-padding" | "nist-key-wrap" | "aes-gcm" | "rsa-pkcs-v15" | "rsa-oaep" | "rsa-aes-key-wrap";

const WRAPPING_ALGORITHMS: { labelKey: string; value: WrappingAlgorithm }[] = [
    { labelKey: "keysExport.wrapAlgoAesKeyWrapPadding", value: "aes-key-wrap-padding" },
    { labelKey: "keysExport.wrapAlgoNistKeyWrap", value: "nist-key-wrap" },
    { labelKey: "keysExport.wrapAlgoAesGcm", value: "aes-gcm" },
    { labelKey: "keysExport.wrapAlgoRsaPkcsV15", value: "rsa-pkcs-v15" },
    { labelKey: "keysExport.wrapAlgoRsaOaep", value: "rsa-oaep" },
    { labelKey: "keysExport.wrapAlgoRsaAesKeyWrap", value: "rsa-aes-key-wrap" },
];

type KeyType = "rsa" | "ec" | "symmetric" | "fpe" | "covercrypt" | "pqc" | "secret-data" | "opaque-object";

const exportFileExtension = {
    "json-ttlv": "json",
    "sec1-pem": "pem",
    "pkcs1-pem": "pem",
    "pkcs8-pem": "pem",
    "sec1-der": "der",
    "pkcs1-der": "der",
    "pkcs8-der": "der",
    base64: "b64",
    raw: "",
};

interface KeyExportFormProps {
    key_type: KeyType;
}

const KeyExportForm: React.FC<KeyExportFormProps> = ({ key_type }) => {
    const [form] = Form.useForm<KeyExportFormData>();
    const { res, isLoading, responseRef, serverUrl, execute } = useActionState();
    const { t } = useTranslation("actions");
    const wrapKeyId = Form.useWatch("wrapKeyId", form);
    const selectedAlgorithm: WrappingAlgorithm | undefined = Form.useWatch("wrappingAlgorithm", form);

    const isSecretData = key_type === "secret-data";
    const isOpaqueObject = key_type === "opaque-object";
    const isDataLike = isSecretData || isOpaqueObject;
    const displayName = isSecretData
        ? t("keysExport.secretData")
        : isOpaqueObject
          ? t("keysExport.opaqueObject")
          : t("keysExport.keyName", { keyType: key_type.toUpperCase() });

    useEffect(() => {
        if (!wrapKeyId) {
            form.setFieldsValue({
                wrappingAlgorithm: undefined,
                authenticatedAdditionalData: undefined,
            });
        }
    }, [wrapKeyId, form]);

    useEffect(() => {
        if (selectedAlgorithm !== "aes-gcm") {
            form.setFieldsValue({ authenticatedAdditionalData: undefined });
        }
    }, [selectedAlgorithm, form]);

    const onFinish = async (values: KeyExportFormData) => {
        const id = values.keyId ? values.keyId : values.tags ? JSON.stringify(values.tags) : undefined;
        await execute(async () => {
            if (!id) {
                throw new Error(t("keysExport.missingIdentifier"));
            }
            const request = export_ttlv_request(id, values.unwrap, values.keyFormat, values.wrapKeyId, values.wrappingAlgorithm);
            const result_str = await sendKmipRequest(request, serverUrl);
            if (result_str) {
                const data = await parse_export_ttlv_response(result_str, values.keyFormat);
                const filename = `${id}.${exportFileExtension[values.keyFormat]}`;
                const mimeType =
                    values.keyFormat === "json-ttlv"
                        ? "application/json"
                        : values.keyFormat === "base64"
                          ? "text/plain"
                          : "application/octet-stream";
                downloadFile(data, filename, mimeType);
                return t("keysExport.success");
            }
        });
    };

    let keyFormats = [];
    if (key_type === "rsa") {
        keyFormats = [
            { label: t("keysExport.formatJsonTtlv"), value: "json-ttlv" },
            { label: t("keysExport.formatPkcs1Pem"), value: "pkcs1-pem" },
            { label: t("keysExport.formatPkcs1Der"), value: "pkcs1-der" },
            { label: t("keysExport.formatPkcs8Pem"), value: "pkcs8-pem" },
            { label: t("keysExport.formatPkcs8Der"), value: "pkcs8-der" },
            { label: t("keysExport.formatBase64"), value: "base64" },
            { label: t("keysExport.formatRaw"), value: "raw" },
        ];
    } else if (key_type === "ec") {
        keyFormats = [
            { label: t("keysExport.formatJsonTtlv"), value: "json-ttlv" },
            { label: t("keysExport.formatSec1Pem"), value: "sec1-pem" },
            { label: t("keysExport.formatSec1Der"), value: "sec1-der" },
            { label: t("keysExport.formatPkcs8Pem"), value: "pkcs8-pem" },
            { label: t("keysExport.formatPkcs8Der"), value: "pkcs8-der" },
            { label: t("keysExport.formatBase64"), value: "base64" },
            { label: t("keysExport.formatRaw"), value: "raw" },
        ];
    } else if (key_type === "symmetric" || key_type === "fpe" || isDataLike) {
        keyFormats = [
            { label: t("keysExport.formatJsonTtlv"), value: "json-ttlv" },
            { label: t("keysExport.formatBase64"), value: "base64" },
            { label: t("keysExport.formatRaw"), value: "raw" },
        ];
    } else {
        keyFormats = [
            { label: t("keysExport.formatJsonTtlv"), value: "json-ttlv" },
            { label: t("keysExport.formatRaw"), value: "raw" },
        ];
    }

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">{t("keysExport.title", { displayName })}</h1>

            <div className="mb-8 space-y-2">
                <p>{t("keysExport.intro", { displayName, object: t("keysExport.object") })}</p>
                {!isDataLike && (
                    <>
                        <p>{t("keysExport.introKeyPair")}</p>
                        <p>{t("keysExport.introUnwrap")}</p>
                        <p className="text-sm text-yellow-600">{t("keysExport.introNote")}</p>
                    </>
                )}
            </div>

            <Form
                form={form}
                onFinish={onFinish}
                layout="vertical"
                initialValues={{
                    keyFormat: "json-ttlv",
                    unwrap: false,
                    allowRevoked: false,
                }}
            >
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <h3 className="text-m font-bold mb-4">
                            {isDataLike ? t("keysExport.identificationObject") : t("keysExport.identificationKey")}
                        </h3>
                        <Form.Item
                            name="keyId"
                            label={
                                isSecretData
                                    ? t("keysExport.secretDataIdLabel")
                                    : isOpaqueObject
                                      ? t("keysExport.opaqueObjectIdLabel")
                                      : t("keysExport.keyIdLabel")
                            }
                        >
                            <Input
                                placeholder={
                                    isSecretData
                                        ? t("keysExport.enterSecretDataId")
                                        : isOpaqueObject
                                          ? t("keysExport.enterOpaqueObjectId")
                                          : t("keysExport.enterKeyId")
                                }
                            />
                        </Form.Item>

                        <Form.Item name="tags" label={t("common:tags")}>
                            <Select mode="tags" placeholder={t("common:enterTags")} open={false} />
                        </Form.Item>
                    </Card>

                    <Card>
                        <Form.Item name="keyFormat" label={t("keysExport.exportFormat")} rules={[{ required: true }]}>
                            <Select options={keyFormats} />
                        </Form.Item>
                    </Card>

                    {!isSecretData && (
                        <Card>
                            <h3 className="text-m font-bold mb-4">{t("keysExport.unwrappingOptions")}</h3>
                            <Form.Item name="unwrap" valuePropName="checked">
                                <Checkbox>{isDataLike ? t("keysExport.unwrapBeforeObject") : t("keysExport.unwrapBeforeKey")}</Checkbox>
                            </Form.Item>

                            <Divider />
                            <h3 className="text-m font-bold mb-4">{t("keysExport.wrappingOptions")}</h3>
                            <Form.Item name="wrapKeyId" label={t("keysExport.wrapKeyId")}>
                                <Input placeholder={t("keysExport.enterWrapKeyId")} />
                            </Form.Item>

                            <Form.Item name="wrappingAlgorithm" label={t("keysExport.wrappingAlgorithm")}>
                                <Select
                                    options={WRAPPING_ALGORITHMS.map((a) => ({ value: a.value, label: t(a.labelKey) }))}
                                    placeholder={t("keysExport.selectAlgorithm")}
                                    disabled={!wrapKeyId}
                                />
                            </Form.Item>

                            {selectedAlgorithm === "aes-gcm" && (
                                <Form.Item name="authenticatedAdditionalData" label={t("keysExport.authenticatedAdditionalData")}>
                                    <Input placeholder={t("keysExport.enterAuthenticatedData")} disabled={!wrapKeyId} />
                                </Form.Item>
                            )}
                        </Card>
                    )}

                    <Card>
                        <Form.Item name="allowRevoked" valuePropName="checked">
                            <Checkbox>{t("keysExport.allowRevoked")}</Checkbox>
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
                            {isDataLike ? t("keysExport.submitObject") : t("keysExport.submitKey")}
                        </Button>
                    </Form.Item>
                </Space>
            </Form>

            {res && (
                <div ref={responseRef} data-testid="response-output">
                    <Card title={isDataLike ? t("keysExport.responseTitleObject") : t("keysExport.responseTitleKey")}>{res}</Card>
                </div>
            )}
        </div>
    );
};

export default KeyExportForm;
