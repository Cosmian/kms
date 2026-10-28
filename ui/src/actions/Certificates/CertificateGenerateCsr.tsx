import { Alert, Button, Card, Checkbox, Form, Input, Radio, Select, Space } from "antd";
import React, { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { ActionResponse } from "../../components/common/ActionResponse";
import { useAuth } from "../../contexts/useAuth";
import { useActionState } from "../../hooks/useActionState";
import { downloadFile, postNoTTLVRequest } from "../../utils/utils";
import * as wasm from "../../wasm/pkg";

type KeySource = "existing" | "generate";

interface GenerateCsrFormData {
    keySource: KeySource;
    privateKeyId?: string;
    subjectName: string;
    algorithm?: string;
    inHsm?: boolean;
    sensitive?: boolean;
}

interface AlgoOption {
    label: string;
    value: string;
}

interface CsrResponse {
    csr_pem: string;
    private_key_id: string;
    public_key_id?: string;
}

const CertificateGenerateCsrForm: React.FC = () => {
    const [form] = Form.useForm<GenerateCsrFormData>();
    const { res, isLoading, responseRef, execute } = useActionState();
    const { serverUrl } = useAuth();
    const { t } = useTranslation("actions");
    const [keySource, setKeySource] = useState<KeySource>("existing");
    const [inHsm, setInHsm] = useState(false);
    const [algorithmOptions, setAlgorithmOptions] = useState<AlgoOption[]>([]);

    useEffect(() => {
        try {
            // Same enumeration as the Certify page; the KEM algorithms cannot sign a CSR and RSA 1024 is too weak.
            const w = wasm as unknown as { get_certificate_algorithms?: () => AlgoOption[] };
            const options = w.get_certificate_algorithms ? w.get_certificate_algorithms() : [];
            setAlgorithmOptions(options.filter((option) => !option.value.includes("kem") && option.value !== "rsa1024"));
        } catch (e) {
            console.error("Error loading certificate algorithms from WASM:", e);
        }
    }, []);

    const onFinish = async (values: GenerateCsrFormData) => {
        await execute(async () => {
            const generate = values.keySource === "generate";
            const privateKeyId = values.privateKeyId?.trim();
            // The CSR is signed server-side: the private key (possibly in an HSM) is never exported.
            const body = generate
                ? {
                      subject_name: values.subjectName.trim(),
                      algorithm: values.algorithm,
                      private_key_id: privateKeyId || undefined,
                      sensitive: values.inHsm === true || values.sensitive === true,
                  }
                : { subject_name: values.subjectName.trim(), private_key_id: privateKeyId };
            const { csr_pem, private_key_id, public_key_id } = (await postNoTTLVRequest(
                "/certificates/csr",
                body,
                serverUrl,
            )) as CsrResponse;
            downloadFile(csr_pem, "request.csr", "application/pkcs10");
            const downloaded = t("certificateGenerateCsr.success", { bytes: csr_pem.length });
            return generate
                ? `${downloaded}. ${t("certificateGenerateCsr.keyPairGenerated", {
                      privateKeyId: private_key_id,
                      publicKeyId: public_key_id,
                  })}`
                : downloaded;
        });
    };

    // The id is only optional for a generated database key pair.
    const privateKeyIdLabelKey = inHsm
        ? "certificateGenerateCsr.hsmPrivateKeyId"
        : keySource === "generate"
          ? "certificateGenerateCsr.newPrivateKeyId"
          : "certificateGenerateCsr.privateKeyId";

    return (
        <Card title={t("certificateGenerateCsr.title")}>
            <Alert
                type="info"
                showIcon
                className="mb-4"
                message={t("certificateGenerateCsr.alertMessage")}
                description={t("certificateGenerateCsr.alertDescription")}
            />
            <Form form={form} layout="vertical" onFinish={onFinish} initialValues={{ keySource: "existing" }}>
                <Form.Item label={t("certificateGenerateCsr.keySource")} name="keySource">
                    <Radio.Group
                        onChange={(e) => {
                            setKeySource(e.target.value as KeySource);
                            setInHsm(false);
                            form.resetFields(["privateKeyId", "algorithm", "inHsm", "sensitive"]);
                        }}
                        data-testid="csr-key-source"
                    >
                        <Radio value="existing" data-testid="csr-key-source-existing">
                            {t("certificateGenerateCsr.useExistingKey")}
                        </Radio>
                        <Radio value="generate" data-testid="csr-key-source-generate">
                            {t("certificateGenerateCsr.generateKeyPair")}
                        </Radio>
                    </Radio.Group>
                </Form.Item>

                {keySource === "generate" && (
                    <>
                        <Form.Item
                            label={t("certificateGenerateCsr.algorithm")}
                            name="algorithm"
                            rules={[{ required: true, message: t("certificateGenerateCsr.algorithmRequired") }]}
                        >
                            <Select
                                options={inHsm ? algorithmOptions.filter((option) => !option.value.includes("dsa")) : algorithmOptions}
                                data-testid="csr-algorithm-select"
                                virtual={false}
                            />
                        </Form.Item>

                        <Form.Item name="inHsm" valuePropName="checked">
                            <Checkbox
                                onChange={(e) => {
                                    setInHsm(e.target.checked);
                                    form.setFieldValue("sensitive", e.target.checked || undefined);
                                    // The HSM only generates RSA and elliptic-curve key pairs.
                                    if (e.target.checked && form.getFieldValue("algorithm")?.includes("dsa")) {
                                        form.setFieldValue("algorithm", undefined);
                                    }
                                }}
                                data-testid="csr-in-hsm"
                            >
                                {t("certificateGenerateCsr.inHsm")}
                            </Checkbox>
                        </Form.Item>

                        <Form.Item name="sensitive" valuePropName="checked" help={t("certificateGenerateCsr.sensitiveHelp")}>
                            <Checkbox disabled={inHsm} data-testid="csr-sensitive">
                                {t("certificateGenerateCsr.sensitive")}
                            </Checkbox>
                        </Form.Item>
                    </>
                )}

                <Form.Item
                    label={t(privateKeyIdLabelKey)}
                    name="privateKeyId"
                    rules={[
                        {
                            required: keySource === "existing" || inHsm,
                            whitespace: true,
                            message: t(inHsm ? "certificateGenerateCsr.hsmKeyIdRequired" : "certificateGenerateCsr.privateKeyIdRequired"),
                        },
                        {
                            validator: (_rule, value?: string) =>
                                inHsm && value?.trim() && !value.trim().startsWith("hsm::")
                                    ? Promise.reject(new Error(t("certificateGenerateCsr.hsmKeyIdFormat")))
                                    : Promise.resolve(),
                        },
                    ]}
                    help={
                        keySource === "generate"
                            ? t(inHsm ? "certificateGenerateCsr.hsmKeyIdHelp" : "certificateGenerateCsr.newPrivateKeyIdHelp")
                            : undefined
                    }
                >
                    <Input
                        placeholder={t(
                            inHsm ? "certificateGenerateCsr.hsmKeyIdPlaceholder" : "certificateGenerateCsr.privateKeyIdPlaceholder",
                        )}
                        data-testid="private-key-id"
                    />
                </Form.Item>

                <Form.Item
                    label={t("certificateGenerateCsr.subjectName")}
                    name="subjectName"
                    rules={[{ required: true, whitespace: true, message: t("certificateGenerateCsr.subjectNameRequired") }]}
                >
                    <Input placeholder="C=FR, O=Acme, CN=Acme Sub CA" data-testid="subject-name" />
                </Form.Item>

                <Form.Item>
                    <Space>
                        <Button type="primary" htmlType="submit" loading={isLoading} data-testid="submit-generate-csr">
                            {t("certificateGenerateCsr.submit")}
                        </Button>
                    </Space>
                </Form.Item>
            </Form>
            <ActionResponse title={t("certificateGenerateCsr.responseTitle")} res={res} responseRef={responseRef} />
        </Card>
    );
};

export default CertificateGenerateCsrForm;
