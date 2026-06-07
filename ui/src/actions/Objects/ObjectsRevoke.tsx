import { WarningFilled } from "@ant-design/icons";
import { Button, Card, Form, Input, Select, Space } from "antd";
import React from "react";
import { Trans, useTranslation } from "react-i18next";
import { getObjectLabel, ObjectType, sendKmipRequest } from "../../utils/utils";
import { parse_revoke_ttlv_response, revoke_ttlv_request } from "../../wasm/pkg/cosmian_kms_client_wasm";
import { useActionState } from "../../hooks/useActionState";
import LocateButton from "../../components/common/LocateButton";

interface RevokeFormData {
    revocationReasonMessage: string;
    revocationReasonCode: string;
    objectId?: string;
    tags?: string[];
}

interface RevokeFormProps {
    objectType: ObjectType;
}

type RevokeResponse = {
    UniqueIdentifier: string;
};

const RevokeForm: React.FC<RevokeFormProps> = ({ objectType }) => {
    const [form] = Form.useForm<RevokeFormData>();
    const { res, isLoading, responseRef, serverUrl, execute } = useActionState();
    const { t } = useTranslation("actions");

    const objectLabel = getObjectLabel(objectType);
    const labelMap: Record<string, string> = {
        key: t("objectsRevoke.labelKey"),
        certificate: t("objectsRevoke.labelCertificate"),
        "secret data": t("objectsRevoke.labelSecretData"),
        "opaque object": t("objectsRevoke.labelOpaqueObject"),
        object: t("objectsRevoke.labelObject"),
    };
    const label = labelMap[objectLabel] ?? t("objectsRevoke.labelObject");
    const labelCap = label.charAt(0).toUpperCase() + label.slice(1);
    const typeMap: Record<ObjectType, string> = {
        rsa: t("objectsRevoke.typeRsa"),
        ec: t("objectsRevoke.typeEc"),
        covercrypt: t("objectsRevoke.typeCoverCrypt"),
        symmetric: t("objectsRevoke.typeSymmetric"),
        fpe: t("objectsRevoke.typeFpe"),
        pqc: t("objectsRevoke.typePqc"),
        certificate: t("objectsRevoke.typeCertificate"),
        "secret-data": t("objectsRevoke.typeSecretData"),
        "opaque-object": t("objectsRevoke.typeOpaqueObject"),
    };
    const typeString = typeMap[objectType] ?? t("objectsRevoke.typeGeneric");

    const onFinish = async (values: RevokeFormData) => {
        const id = values.objectId || (values.tags ? JSON.stringify(values.tags) : undefined);
        await execute(async () => {
            if (!id) {
                throw new Error(t("objectsRevoke.missingIdentifier", { label }));
            }
            const request = revoke_ttlv_request(id, values.revocationReasonMessage, values.revocationReasonCode);
            const result_str = await sendKmipRequest(request, serverUrl);
            if (result_str) {
                const result: RevokeResponse = await parse_revoke_ttlv_response(result_str);
                return t("objectsRevoke.success", { objectId: result.UniqueIdentifier });
            }
        });
    };

    return (
        <div className="p-6">
            <div className="flex items-center gap-3 mb-6">
                <WarningFilled className="text-2xl text-red-500" />
                <h1 className="text-2xl font-bold">{t("objectsRevoke.title", { typeString, label })}</h1>
            </div>

            <div className="mb-8 space-y-2">
                <div className="bg-red-200 border-l-4 border-red-600 rounded-md p-4">
                    <div className="text-red-800 text-sm space-y-2">
                        <p>
                            <strong>{t("objectsRevoke.warningTitle")}</strong> {t("objectsRevoke.warningCannotUndo")}
                        </p>
                        <p>
                            <Trans ns="actions" i18nKey="objectsRevoke.warningOnceRevoked" values={{ label }} components={{ i: <i /> }} />
                        </p>
                        {(objectType === "rsa" || objectType === "ec") && <p>{t("objectsRevoke.warningKeyPair")}</p>}
                        {objectType === "certificate" && <p>{t("objectsRevoke.warningCertificate")}</p>}
                    </div>
                </div>
                <div>{t("objectsRevoke.irreversible", { label })}</div>
            </div>

            <Form form={form} onFinish={onFinish} layout="vertical">
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <Form.Item
                            name="revocationReasonCode"
                            label={t("objectsRevoke.reasonCode")}
                            initialValue="unspecified"
                            rules={[{ required: true, message: t("objectsRevoke.pleaseSelectReasonCode") }]}
                            help={t("objectsRevoke.reasonCodeHelp")}
                        >
                            <Select data-testid="revocation-reason-code">
                                <Select.Option value="unspecified">{t("objectsRevoke.optionUnspecified")}</Select.Option>
                                <Select.Option value="key-compromise">{t("objectsRevoke.optionKeyCompromise")}</Select.Option>
                                <Select.Option value="ca-compromise">{t("objectsRevoke.optionCaCompromise")}</Select.Option>
                                <Select.Option value="affiliation-changed">{t("objectsRevoke.optionAffiliationChanged")}</Select.Option>
                                <Select.Option value="superseded">{t("objectsRevoke.optionSuperseded")}</Select.Option>
                                <Select.Option value="cessation-of-operation">{t("objectsRevoke.optionCessation")}</Select.Option>
                                <Select.Option value="privilege-withdrawn">{t("objectsRevoke.optionPrivilegeWithdrawn")}</Select.Option>
                            </Select>
                        </Form.Item>
                        <Form.Item
                            name="revocationReasonMessage"
                            label={t("objectsRevoke.reasonMessage")}
                            rules={[
                                {
                                    required: true,
                                    message: t("objectsRevoke.pleaseSpecifyReason", { label }),
                                },
                            ]}
                            help={t("objectsRevoke.reasonMessageHelp", { label })}
                        >
                            <Input.TextArea placeholder={t("objectsRevoke.reasonMessagePlaceholder", { label })} rows={3} />
                        </Form.Item>
                    </Card>
                    <Card>
                        <h3 className="text-m font-bold mb-4">{t("objectsRevoke.identification", { labelCap })}</h3>

                        <Form.Item label={t("objectsRevoke.objectIdLabel", { labelCap })} help={t("objectsRevoke.objectIdHelp", { label })}>
                            <div className="flex items-center gap-2">
                                <Form.Item
                                    noStyle
                                    name="objectId"
                                    rules={[{ required: true, message: t("objectsRevoke.pleaseEnterObjectId", { label }) }]}
                                >
                                    <Input placeholder={t("objectsRevoke.enterObjectId", { label })} style={{ flex: 1 }} />
                                </Form.Item>
                                <LocateButton onSelect={(uid: string) => form.setFieldValue("objectId", uid)} />
                            </div>
                        </Form.Item>

                        <Form.Item name="tags" label={t("common:tags")} help={t("objectsRevoke.tagsHelp", { labelCap, label })}>
                            <Select mode="tags" placeholder={t("common:enterTags")} open={false} />
                        </Form.Item>
                    </Card>

                    <Form.Item>
                        <Button
                            type="primary"
                            htmlType="submit"
                            loading={isLoading}
                            danger
                            className="w-full text-white font-medium"
                            data-testid="submit-btn"
                        >
                            {t("objectsRevoke.submit", { labelCap })}
                        </Button>
                    </Form.Item>
                </Space>
            </Form>

            {res && (
                <div ref={responseRef} data-testid="response-output">
                    <Card title={t("objectsRevoke.responseTitle", { labelCap })}>{res}</Card>
                </div>
            )}
        </div>
    );
};

export default RevokeForm;
