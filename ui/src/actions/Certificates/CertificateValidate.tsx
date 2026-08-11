import { Button, Card, DatePicker, Form, Input, Space } from "antd";
import React from "react";
import { useTranslation } from "react-i18next";
import { sendKmipRequest } from "../../utils/utils";
import { parse_validate_ttlv_response, validate_certificate_ttlv_request } from "../../wasm/pkg";
import { useActionState } from "../../hooks/useActionState";
import { ActionResponse } from "../../components/common/ActionResponse";

interface ValidateCertificateFormData {
    uniqueIdentifier?: string;
    validityTime?: Date;
}

const CertificateValidateForm: React.FC = () => {
    const [form] = Form.useForm<ValidateCertificateFormData>();
    const { res, isLoading, responseRef, serverUrl, execute } = useActionState();
    const { t } = useTranslation("actions");

    const onFinish = async (values: ValidateCertificateFormData) => {
        await execute(async () => {
            const validityTime = values.validityTime ? values.validityTime.toISOString() : undefined;
            const request = validate_certificate_ttlv_request(values.uniqueIdentifier, validityTime);
            const result_str = await sendKmipRequest(request, serverUrl);
            if (result_str) {
                const response = await parse_validate_ttlv_response(result_str);
                return t("certificateValidate.success", { validity: response.ValidityIndicator });
            }
        });
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">{t("certificateValidate.title")}</h1>

            <div className="mb-8 space-y-2">
                <p>{t("certificateValidate.intro")}</p>
                <p>{t("certificateValidate.introKey")}</p>
            </div>

            <Form form={form} onFinish={onFinish} layout="vertical">
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <h3 className="text-m font-bold mb-4">{t("certificateValidate.certificateInput")}</h3>

                        <Form.Item
                            name="uniqueIdentifier"
                            label={t("certificateValidate.certificateUniqueIdentifier")}
                            help={t("certificateValidate.certificateIdHelp")}
                            rules={[{ required: true }]}
                        >
                            <Input placeholder={t("certificateValidate.enterCertificateId")} />
                        </Form.Item>
                    </Card>

                    <Card>
                        <h3 className="text-m font-bold mb-4">{t("certificateValidate.validationParameters")}</h3>

                        <Form.Item
                            name="validityTime"
                            label={t("certificateValidate.validityTime")}
                            help={t("certificateValidate.validityTimeHelp")}
                        >
                            <DatePicker showTime format="YYYY-MM-DD HH:mm:ss" />
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
                            {t("certificateValidate.submit")}
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            <ActionResponse res={res} responseRef={responseRef} title={t("certificateValidate.responseTitle")} />
        </div>
    );
};

export default CertificateValidateForm;
