import { Button, Card, Form, Select, Space } from "antd";
import React from "react";
import { Trans, useTranslation } from "react-i18next";
import { downloadFile, sendKmipRequest } from "../../utils/utils";
import { encrypt_ec_ttlv_request, parse_encrypt_ttlv_response } from "../../wasm/pkg";
import { useActionState } from "../../hooks/useActionState";
import { ActionResponse } from "../../components/common/ActionResponse";
import KeyIdInput from "../../components/common/KeyIdInput";

interface PqcEncapsulateFormData {
    keyId?: string;
    tags?: string[];
}

const PqcEncapsulateForm: React.FC = () => {
    const [form] = Form.useForm<PqcEncapsulateFormData>();
    const { res, isLoading, responseRef, serverUrl, execute } = useActionState();
    const { t } = useTranslation("actions");

    const onFinish = async (values: PqcEncapsulateFormData) => {
        const id = values.keyId ? values.keyId : values.tags ? JSON.stringify(values.tags) : undefined;
        await execute(async () => {
            if (id == undefined) {
                throw new Error(t("pqcEncapsulate.missingKeyId"));
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

                return t("pqcEncapsulate.success");
            }
        });
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">{t("pqcEncapsulate.title")}</h1>

            <div className="mb-8 space-y-2">
                <p>{t("pqcEncapsulate.intro")}</p>
                <p>
                    <Trans ns="actions" i18nKey="pqcEncapsulate.introSharedSecret" components={{ strong: <strong /> }} />
                </p>
                <p>{t("pqcEncapsulate.introCiphertext")}</p>
            </div>

            <Form form={form} onFinish={onFinish} layout="vertical">
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <h3 className="text-m font-bold mb-4">{t("pqcEncapsulate.keyIdentification")}</h3>
                        <KeyIdInput
                            form={form}
                            fieldName="keyId"
                            label={t("pqcEncapsulate.publicKeyId")}
                            help={t("pqcEncapsulate.publicKeyIdHelp")}
                            placeholder={t("pqcEncapsulate.enterPublicKeyId")}
                            objectType="PublicKey"
                        />

                        <Form.Item name="tags" label={t("common:tags")} help={t("pqcEncapsulate.tagsHelp")}>
                            <Select mode="tags" placeholder={t("common:enterTags")} open={false} />
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
                            {t("pqcEncapsulate.submit")}
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            <ActionResponse res={res} responseRef={responseRef} title={t("pqcEncapsulate.responseTitle")} />
        </div>
    );
};

export default PqcEncapsulateForm;
