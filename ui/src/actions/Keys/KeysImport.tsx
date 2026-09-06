import { UploadOutlined } from "@ant-design/icons";
import { Button, Card, Checkbox, Form, Input, Select, Space } from "antd";
import React from "react";
import { useTranslation } from "react-i18next";
import { FormUpload } from "../../components/common/FormUpload";
import { sendKmipRequest } from "../../utils/utils";
import { import_ttlv_request, parse_import_ttlv_response } from "../../wasm/pkg";
import { useActionState } from "../../hooks/useActionState";
import { ActionResponse } from "../../components/common/ActionResponse";

type ImportKeyFormat = "json-ttlv" | "pem" | "sec1" | "pkcs1-priv" | "pkcs1-pub" | "pkcs8-pub" | "pkcs8-priv" | "aes" | "chacha20";

type KeyUsage = "Sign" | "Verify" | "Encrypt" | "Decrypt" | "WrapKey" | "UnwrapKey";

interface ImportKeyFormData {
    keyFile: Uint8Array;
    keyId?: string;
    keyFormat: ImportKeyFormat;
    publicKeyId?: string;
    privateKeyId?: string;
    certificateId?: string;
    unwrap: boolean;
    replaceExisting: boolean;
    tags: string[];
    keyUsage?: KeyUsage[];
    authenticatedAdditionalData?: string;
    wrappingKeyId?: string;
}

type KeyType = "rsa" | "ec" | "symmetric" | "fpe" | "covercrypt" | "pqc" | "secret-data" | "opaque-object";

interface KeyImportFormProps {
    key_type: KeyType;
}

type KeyImportResponse = {
    UniqueIdentifier: string;
};

const KeyImportForm: React.FC<KeyImportFormProps> = ({ key_type }) => {
    const [form] = Form.useForm<ImportKeyFormData>();
    const { res, isLoading, responseRef, serverUrl, execute } = useActionState();
    const { t } = useTranslation("actions");

    const onFinish = async (values: ImportKeyFormData) => {
        await execute(async () => {
            const request = import_ttlv_request(
                values.keyId,
                values.keyFile,
                values.keyFormat,
                values.publicKeyId,
                values.privateKeyId,
                values.certificateId,
                values.unwrap,
                values.replaceExisting,
                values.tags,
                values.keyUsage,
                values.wrappingKeyId,
            );
            const result_str = await sendKmipRequest(request, serverUrl);
            if (result_str) {
                const result: KeyImportResponse = await parse_import_ttlv_response(result_str);
                return t("keysImport.success", { objectId: result.UniqueIdentifier });
            }
        });
    };

    let key_formats = [];
    let key_usages = [];

    if (key_type === "rsa") {
        key_formats = [
            { label: t("keysImport.formatJsonTtlv"), value: "json-ttlv" },
            { label: t("keysImport.formatPem"), value: "pem" },
            { label: t("keysImport.formatPkcs1Priv"), value: "pkcs1-priv" },
            { label: t("keysImport.formatPkcs1Pub"), value: "pkcs1-pub" },
            { label: t("keysImport.formatPkcs8Priv"), value: "pkcs8-priv" },
            { label: t("keysImport.formatPkcs8Pub"), value: "pkcs8-pub" },
        ];
        key_usages = [
            { label: t("keysImport.usageSign"), value: "Sign" },
            { label: t("keysImport.usageVerify"), value: "Verify" },
            { label: t("keysImport.usageEncrypt"), value: "Encrypt" },
            { label: t("keysImport.usageDecrypt"), value: "Decrypt" },
            { label: t("keysImport.usageWrap"), value: "WrapKey" },
            { label: t("keysImport.usageUnwrap"), value: "UnwrapKey" },
        ];
    } else if (key_type === "ec") {
        key_formats = [
            { label: t("keysImport.formatJsonTtlv"), value: "json-ttlv" },
            { label: t("keysImport.formatPem"), value: "pem" },
            { label: t("keysImport.formatSec1"), value: "sec1" },
            { label: t("keysImport.formatPkcs8Pub"), value: "pkcs8-pub" },
            { label: t("keysImport.formatPkcs8Priv"), value: "pkcs8-priv" },
        ];
        key_usages = [
            { label: t("keysImport.usageSign"), value: "Sign" },
            { label: t("keysImport.usageVerify"), value: "Verify" },
            { label: t("keysImport.usageEncrypt"), value: "Encrypt" },
            { label: t("keysImport.usageDecrypt"), value: "Decrypt" },
            { label: t("keysImport.usageWrap"), value: "WrapKey" },
            { label: t("keysImport.usageUnwrap"), value: "UnwrapKey" },
        ];
    } else if (key_type === "symmetric" || key_type === "fpe") {
        key_formats = [
            { label: t("keysImport.formatJsonTtlv"), value: "json-ttlv" },
            { label: t("keysImport.formatAes"), value: "aes" },
            { label: t("keysImport.formatChacha20"), value: "chacha20" },
        ];
        key_usages = [
            { label: t("keysImport.usageEncrypt"), value: "Encrypt" },
            { label: t("keysImport.usageDecrypt"), value: "Decrypt" },
            { label: t("keysImport.usageWrap"), value: "WrapKey" },
            { label: t("keysImport.usageUnwrap"), value: "UnwrapKey" },
        ];
    } else if (key_type === "secret-data" || key_type === "opaque-object") {
        key_formats = [{ label: t("keysImport.formatJsonTtlv"), value: "json-ttlv" }];
        key_usages = [
            { label: t("keysImport.usageWrap"), value: "WrapKey" },
            { label: t("keysImport.usageUnwrap"), value: "UnwrapKey" },
        ];
    } else {
        key_formats = [{ label: t("keysImport.formatJsonTtlv"), value: "json-ttlv" }];
        key_usages = [
            { label: t("keysImport.usageEncrypt"), value: "Encrypt" },
            { label: t("keysImport.usageDecrypt"), value: "Decrypt" },
        ];
    }

    const isSecretData = key_type === "secret-data";
    const isOpaqueObject = key_type === "opaque-object";
    const isDataLike = isSecretData || isOpaqueObject;
    const displayName = isSecretData
        ? t("keysImport.secretData")
        : isOpaqueObject
          ? t("keysImport.opaqueObject")
          : t("keysImport.keyName", { keyType: key_type.toUpperCase() });

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">{t("keysImport.title", { displayName })}</h1>

            <div className="mb-8 space-y-2">
                <p>{t("keysImport.intro", { displayName })}</p>
                <p>{t("keysImport.introUuid")}</p>
            </div>

            <Form
                form={form}
                onFinish={onFinish}
                layout="vertical"
                initialValues={{
                    keyFormat: "json-ttlv",
                    unwrap: false,
                    replaceExisting: false,
                    tags: [],
                }}
            >
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <Form.Item
                            name="keyFile"
                            label={isDataLike ? t("keysImport.dataFileLabel") : t("keysImport.keyFileLabel")}
                            rules={[{ required: true, message: t("keysImport.pleaseUploadFile") }]}
                            help={
                                isSecretData
                                    ? t("keysImport.secretDataFileHelp")
                                    : isOpaqueObject
                                      ? t("keysImport.opaqueObjectFileHelp")
                                      : t("keysImport.keyFileHelp")
                            }
                        >
                            <FormUpload
                                beforeUpload={(file) => {
                                    const reader = new FileReader();
                                    reader.onload = (e) => {
                                        const content = e.target?.result;
                                        if (typeof content === "string") {
                                            try {
                                                if (/^[A-Za-z0-9+/=]+$/.test(content.trim())) {
                                                    const decoded = atob(content.trim());
                                                    const bytes = new Uint8Array([...decoded].map((char) => char.charCodeAt(0)));
                                                    form.setFieldsValue({ keyFile: bytes });
                                                } else {
                                                    throw new Error(t("keysImport.invalidBase64"));
                                                }
                                            } catch {
                                                const binaryReader = new FileReader();
                                                binaryReader.onload = (event) => {
                                                    const rawContent = event.target?.result;
                                                    if (rawContent instanceof ArrayBuffer) {
                                                        const bytes = new Uint8Array(rawContent);
                                                        form.setFieldsValue({ keyFile: bytes });
                                                    }
                                                };
                                                binaryReader.readAsArrayBuffer(file);
                                            }
                                        }
                                    };
                                    reader.readAsText(file);
                                    return false;
                                }}
                                maxCount={1}
                            >
                                <Button icon={<UploadOutlined />}>
                                    {isSecretData
                                        ? t("keysImport.uploadSecretData")
                                        : isOpaqueObject
                                          ? t("keysImport.uploadOpaqueObject")
                                          : t("keysImport.uploadKeyFile")}
                                </Button>
                            </FormUpload>
                        </Form.Item>

                        <Form.Item name="keyId" label={t("keysImport.idLabel")} help={t("keysImport.idHelp")}>
                            <Input placeholder={t("keysImport.enterId")} />
                        </Form.Item>

                        <Form.Item
                            name="keyFormat"
                            label={t("keysImport.formatLabel")}
                            help={t("keysImport.formatHelp")}
                            rules={[{ required: true }]}
                        >
                            <Select options={key_formats} />
                        </Form.Item>
                    </Card>

                    {!isSecretData && (
                        <Card>
                            <h3 className="text-m font-bold mb-4">{t("keysImport.keyRelationships")}</h3>

                            <Form.Item name="publicKeyId" label={t("keysImport.publicKeyId")} help={t("keysImport.publicKeyIdHelp")}>
                                <Input placeholder={t("keysImport.enterPublicKeyId")} />
                            </Form.Item>

                            <Form.Item name="privateKeyId" label={t("keysImport.privateKeyId")} help={t("keysImport.privateKeyIdHelp")}>
                                <Input placeholder={t("keysImport.enterPrivateKeyId")} />
                            </Form.Item>

                            <Form.Item name="certificateId" label={t("keysImport.certificateId")} help={t("keysImport.certificateIdHelp")}>
                                <Input placeholder={t("keysImport.enterCertificateId")} />
                            </Form.Item>
                        </Card>
                    )}

                    <Card>
                        <Form.Item name="keyUsage" label={t("keysImport.usageLabel")} help={t("keysImport.usageHelp")}>
                            <Select mode="multiple" options={key_usages} placeholder={t("keysImport.selectUsage")} />
                        </Form.Item>

                        <Form.Item name="tags" label={t("common:tags")} help={t("keysImport.tagsHelp")}>
                            <Select mode="tags" placeholder={t("common:enterTags")} open={false} />
                        </Form.Item>

                        <Form.Item name="wrappingKeyId" label={t("keysImport.wrappingKeyId")} help={t("keysImport.wrappingKeyIdHelp")}>
                            <Input placeholder={t("keysImport.enterWrappingKeyId")} />
                        </Form.Item>
                    </Card>

                    <Card>
                        <Form.Item name="unwrap" valuePropName="checked" help={t("keysImport.unwrapHelp")}>
                            <Checkbox>{t("keysImport.unwrapBeforeImport")}</Checkbox>
                        </Form.Item>

                        <Form.Item name="replaceExisting" valuePropName="checked" help={t("keysImport.replaceExistingHelp")}>
                            <Checkbox>{t("keysImport.replaceExisting")}</Checkbox>
                        </Form.Item>
                    </Card>

                    <Card>
                        <Form.Item
                            name="authenticatedAdditionalData"
                            label={t("keysImport.authenticatedAdditionalData")}
                            help={t("keysImport.authenticatedAdditionalDataHelp")}
                        >
                            <Input placeholder={t("keysImport.enterAuthenticatedData")} />
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
                            {isDataLike ? t("keysImport.submitData") : t("keysImport.submitKey")}
                        </Button>
                    </Form.Item>
                </Space>
            </Form>

            <ActionResponse res={res} responseRef={responseRef} title={t("keysImport.responseTitle")} />
        </div>
    );
};

export default KeyImportForm;
