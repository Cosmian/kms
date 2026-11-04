import { CheckCircleOutlined } from "@ant-design/icons";
import { Button, Card, Form, Input, Select, Space } from "antd";
import React from "react";
import { useTranslation } from "react-i18next";
import { getObjectLabel, ObjectType, sendKmipRequest } from "../../utils/utils";
import { activate_ttlv_request, parse_activate_ttlv_response } from "../../wasm/pkg/cosmian_kms_client_wasm";
import { useActionState } from "../../hooks/useActionState";
import LocateButton from "../../components/common/LocateButton";

interface ActivateFormData {
    objectId?: string;
    tags?: string[];
}

interface ActivateFormProps {
    objectType: ObjectType;
}

type ActivateResponse = {
    UniqueIdentifier: string;
};

const ActivateForm: React.FC<ActivateFormProps> = ({ objectType }) => {
    const [form] = Form.useForm<ActivateFormData>();
    const { res, isLoading, responseRef, serverUrl, execute } = useActionState();
    const { t } = useTranslation("actions");

    const objectLabel = getObjectLabel(objectType);
    const labelMap: Record<string, string> = {
        key: t("objectsActivate.labelKey"),
        certificate: t("objectsActivate.labelCertificate"),
        "secret data": t("objectsActivate.labelSecretData"),
        object: t("objectsActivate.labelObject"),
    };
    const label = labelMap[objectLabel] ?? t("objectsActivate.labelObject");
    const labelCap = label.charAt(0).toUpperCase() + label.slice(1);
    // Partial: pgp and opaque-object are never routed here (the server rejects them on Activate).
    const typeMap: Partial<Record<ObjectType, string>> = {
        rsa: t("objectsActivate.typeRsa"),
        ec: t("objectsActivate.typeEc"),
        covercrypt: t("objectsActivate.typeCoverCrypt"),
        symmetric: t("objectsActivate.typeSymmetric"),
        fpe: t("objectsActivate.typeFpe"),
        pqc: t("objectsActivate.typePqc"),
        certificate: t("objectsActivate.typeCertificate"),
        "secret-data": t("objectsActivate.typeSecretData"),
    };
    const typeString = typeMap[objectType] ?? t("objectsActivate.typeGeneric");

    const onFinish = async (values: ActivateFormData) => {
        const id = values.objectId ? values.objectId : values.tags?.length ? JSON.stringify(values.tags) : undefined;
        await execute(async () => {
            if (id == undefined) {
                throw new Error(t("objectsActivate.missingIdentifier", { label }));
            }
            const request = activate_ttlv_request(id);
            const result_str = await sendKmipRequest(request, serverUrl);
            if (result_str) {
                const result: ActivateResponse = await parse_activate_ttlv_response(result_str);
                return t("objectsActivate.success", { objectId: result.UniqueIdentifier });
            }
        });
    };

    return (
        <div className="p-6">
            <div className="flex items-center gap-3 mb-6">
                <CheckCircleOutlined className="text-2xl text-green-600 dark:text-green-400" />
                <h1 className="text-2xl font-bold">{t("objectsActivate.title", { typeString, label })}</h1>
            </div>

            <div className="mb-8 space-y-2">
                <p>{t("objectsActivate.intro", { label })}</p>
                <p>{t("objectsActivate.preActiveOnly")}</p>
            </div>

            <Form form={form} onFinish={onFinish} layout="vertical">
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <h3 className="text-m font-bold mb-4">{t("objectsActivate.identification", { labelCap })}</h3>

                        <Form.Item
                            label={t("objectsActivate.objectIdLabel", { labelCap })}
                            help={t("objectsActivate.objectIdHelp", { label })}
                        >
                            <div className="flex items-center gap-2">
                                {/* No `required` rule: tags are the alternative identifier. */}
                                <Form.Item noStyle name="objectId">
                                    <Input placeholder={t("objectsActivate.enterObjectId", { label })} style={{ flex: 1 }} />
                                </Form.Item>
                                <LocateButton onSelect={(uid: string) => form.setFieldValue("objectId", uid)} />
                            </div>
                        </Form.Item>

                        <Form.Item name="tags" label={t("common:tags")} help={t("objectsActivate.tagsHelp", { labelCap, label })}>
                            <Select mode="tags" placeholder={t("common:enterTags")} open={false} />
                        </Form.Item>
                    </Card>
                    <Form.Item>
                        <Button
                            type="primary"
                            htmlType="submit"
                            loading={isLoading}
                            disabled={isLoading}
                            className="w-full text-white font-medium"
                            data-testid="submit-btn"
                        >
                            {t("objectsActivate.submit", { labelCap })}
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            {res && (
                <div ref={responseRef} data-testid="response-output">
                    <Card title={t("objectsActivate.responseTitle", { labelCap })}>{res}</Card>
                </div>
            )}
        </div>
    );
};

export default ActivateForm;
