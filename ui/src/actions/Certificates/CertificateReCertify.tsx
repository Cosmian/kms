import { Button, Card, Form, Input, Select, Space } from "antd";
import React from "react";
import { Trans, useTranslation } from "react-i18next";
import { ActionResponse } from "../../components/common/ActionResponse";
import { useActionState } from "../../hooks/useActionState";
import { sendKmipRequest } from "../../utils/utils";
import * as wasm from "../../wasm/pkg";

interface CertificateReCertifyFormData {
    certificateIdToReCertify: string;
    issuerPrivateKeyId?: string;
    issuerCertificateId?: string;
    numberOfDays: number;
    tags: string[];
}

const CertificateReCertifyForm: React.FC = () => {
    const [form] = Form.useForm<CertificateReCertifyFormData>();
    const { res, isLoading, responseRef, serverUrl, execute } = useActionState();
    const { t } = useTranslation("actions");

    const onFinish = async (values: CertificateReCertifyFormData) => {
        const normalize = (v?: string) => (v?.trim() ? v.trim() : undefined);
        await execute(async () => {
            const request = wasm.re_certify_ttlv_request(
                values.certificateIdToReCertify.trim(),
                normalize(values.issuerPrivateKeyId),
                normalize(values.issuerCertificateId),
                values.numberOfDays,
                values.tags,
            );
            const result_str = await sendKmipRequest(request, serverUrl);
            if (result_str) {
                const response = await wasm.parse_re_certify_ttlv_response(result_str);
                return t("certificateReCertify.success", { newCertId: response.UniqueIdentifier });
            }
        });
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">{t("certificateReCertify.title")}</h1>

            <div className="mb-8 space-y-2">
                <Trans ns="actions" i18nKey="certificateReCertify.intro" components={{ strong: <strong />, code: <code />, em: <em /> }} />
            </div>

            <Form
                form={form}
                onFinish={onFinish}
                layout="vertical"
                initialValues={{
                    numberOfDays: 365,
                    tags: [],
                }}
            >
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <h3 className="text-m font-bold mb-4">{t("certificateReCertify.certificateToReCertify")}</h3>
                        <Form.Item
                            name="certificateIdToReCertify"
                            label={t("certificateReCertify.certificateId")}
                            rules={[{ required: true, message: t("certificateReCertify.pleaseEnterCertificateId") }]}
                            help={t("certificateReCertify.certificateIdHelp")}
                        >
                            <Input placeholder={t("certificateReCertify.enterCertificateId")} data-testid="certificate-id-input" />
                        </Form.Item>
                    </Card>

                    <Card>
                        <h3 className="text-m font-bold mb-4">{t("certificateReCertify.issuerInformation")}</h3>
                        <p className="text-sm mb-4">{t("certificateReCertify.issuerHint")}</p>

                        <Form.Item
                            name="issuerPrivateKeyId"
                            label={t("certificateReCertify.issuerPrivateKeyId")}
                            help={t("certificateReCertify.issuerPrivateKeyIdHelp")}
                        >
                            <Input placeholder={t("certificateReCertify.enterIssuerPrivateKeyId")} />
                        </Form.Item>

                        <Form.Item
                            name="issuerCertificateId"
                            label={t("certificateReCertify.issuerCertificateId")}
                            help={t("certificateReCertify.issuerCertificateIdHelp")}
                        >
                            <Input placeholder={t("certificateReCertify.enterIssuerCertificateId")} />
                        </Form.Item>
                    </Card>

                    <Card>
                        <h3 className="text-m font-bold mb-4">{t("certificateReCertify.certificateOptions")}</h3>
                        <Form.Item
                            name="numberOfDays"
                            label={t("certificateReCertify.validityPeriod")}
                            rules={[{ required: true, message: t("certificateReCertify.pleaseEnterDays") }]}
                            help={t("certificateReCertify.validityPeriodHelp")}
                        >
                            <Input type="number" min={1} data-testid="number-of-days-input" />
                        </Form.Item>

                        <Form.Item name="tags" label={t("common:tags")} help={t("certificateReCertify.tagsHelp")}>
                            <Select mode="tags" placeholder={t("common:enterTags")} open={false} data-testid="tags-select" />
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
                            {t("certificateReCertify.submit")}
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            <ActionResponse res={res} responseRef={responseRef} title={t("certificateReCertify.responseTitle")} />
        </div>
    );
};

export default CertificateReCertifyForm;
