import { WarningFilled } from "@ant-design/icons";
import { Button, Card, Checkbox, Form, Input, Select, Space } from "antd";
import React from "react";
import { useTranslation } from "react-i18next";
import { getObjectLabel, ObjectType, sendKmipRequest } from "../../utils/utils";
import { destroy_ttlv_request, parse_destroy_ttlv_response } from "../../wasm/pkg/cosmian_kms_client_wasm";
import { useActionState } from "../../hooks/useActionState";
import LocateButton from "../../components/common/LocateButton";
import LocateButton from "../../components/common/LocateButton";

interface DestroyFormData {
    objectId?: string;
    tags?: string[];
    remove: boolean;
}

interface DestroyFormProps {
    objectType: ObjectType;
}

type DestroyResponse = {
    UniqueIdentifier: string;
};

const DestroyForm: React.FC<DestroyFormProps> = ({ objectType }) => {
    const [form] = Form.useForm<DestroyFormData>();
    const { res, isLoading, responseRef, serverUrl, execute } = useActionState();
    const { t } = useTranslation("actions");

    const objectLabel = getObjectLabel(objectType);
    const labelMap: Record<string, string> = {
        key: t("objectsDestroy.labelKey"),
        certificate: t("objectsDestroy.labelCertificate"),
        "secret data": t("objectsDestroy.labelSecretData"),
        "opaque object": t("objectsDestroy.labelOpaqueObject"),
        object: t("objectsDestroy.labelObject"),
    };
    const label = labelMap[objectLabel] ?? t("objectsDestroy.labelObject");
    const labelCap = label.charAt(0).toUpperCase() + label.slice(1);
    const typeMap: Record<ObjectType, string> = {
        rsa: t("objectsDestroy.typeRsa"),
        ec: t("objectsDestroy.typeEc"),
        covercrypt: t("objectsDestroy.typeCoverCrypt"),
        symmetric: t("objectsDestroy.typeSymmetric"),
        fpe: t("objectsDestroy.typeFpe"),
        pqc: t("objectsDestroy.typePqc"),
        certificate: t("objectsDestroy.typeCertificate"),
        "secret-data": t("objectsDestroy.typeSecretData"),
        "opaque-object": t("objectsDestroy.typeOpaqueObject"),
    };
    const typeString = typeMap[objectType] ?? t("objectsDestroy.typeGeneric");
    const isKeyLike =
        objectType === "rsa" || objectType === "ec" || objectType === "covercrypt" || objectType === "symmetric" || objectType === "fpe";

    const onFinish = async (values: DestroyFormData) => {
        const id = values.objectId ? values.objectId : values.tags ? JSON.stringify(values.tags) : undefined;
        await execute(async () => {
            if (id == undefined) {
                throw new Error(t("objectsDestroy.missingIdentifier", { label }));
            }
            const request = destroy_ttlv_request(id, values.remove);
            const result_str = await sendKmipRequest(request, serverUrl);
            if (result_str) {
                const result: DestroyResponse = await parse_destroy_ttlv_response(result_str);
                return t("objectsDestroy.success", { objectId: result.UniqueIdentifier });
            }
        });
    };

    return (
        <div className="p-6">
            <div className="flex items-center gap-3 mb-6">
                <WarningFilled className="text-2xl text-red-600 dark:text-red-400" />
                <h1 className="text-2xl font-bold">{t("objectsDestroy.title", { typeString, label })}</h1>
            </div>

            <div className="mb-8 space-y-2">
                <div className="bg-red-200 dark:bg-red-900/40 border-l-4 border-red-600 dark:border-red-500 rounded-md p-4">
                    <div className="text-red-800 dark:text-red-300 text-sm space-y-2">
                        <p className="font-bold">{t("objectsDestroy.warningTitle")}</p>
                        <ul className="list-disc pl-5 space-y-1">
                            <li>{t("objectsDestroy.mustRevoked", { label })}</li>
                            {isKeyLike && (
                                <>
                                    <li>{t("objectsDestroy.destroyKeyPair")}</li>
                                    <li>{t("objectsDestroy.hsmRemoved")}</li>
                                </>
                            )}
                            {objectType === "certificate" && <li>{t("objectsDestroy.certNotDestroy")}</li>}
                            <li>{t("objectsDestroy.destroyedExport", { label })}</li>
                        </ul>
                    </div>
                </div>
                <div>{t("objectsDestroy.irreversible", { label })}</div>
            </div>

            <Form
                form={form}
                onFinish={onFinish}
                layout="vertical"
                initialValues={{
                    remove: false,
                }}
            >
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <h3 className="text-m font-bold mb-4">{t("objectsDestroy.identification", { labelCap })}</h3>

                        <Form.Item
                            label={t("objectsDestroy.objectIdLabel", { labelCap })}
                            help={t("objectsDestroy.objectIdHelp", { label })}
                        >
                            <div className="flex items-center gap-2">
                                <Form.Item
                                    noStyle
                                    name="objectId"
                                    rules={[{ required: true, message: t("objectsDestroy.pleaseEnterObjectId", { label }) }]}
                                >
                                    <Input placeholder={t("objectsDestroy.enterObjectId", { label })} style={{ flex: 1 }} />
                                </Form.Item>
                                <LocateButton onSelect={(uid: string) => form.setFieldValue("objectId", uid)} />
                            </div>
                        </Form.Item>

                        <Form.Item name="tags" label={t("common:tags")} help={t("objectsDestroy.tagsHelp", { labelCap, label })}>
                            <Select mode="tags" placeholder={t("common:enterTags")} open={false} />
                        </Form.Item>
                    </Card>
                    <Card>
                        <Form.Item name="remove" valuePropName="checked" help={t("objectsDestroy.removeHelp", { label })}>
                            <Checkbox>{t("objectsDestroy.removeLabel")}</Checkbox>
                        </Form.Item>
                    </Card>
                    <Form.Item>
                        <Button
                            type="primary"
                            htmlType="submit"
                            loading={isLoading}
                            danger
                            disabled={isLoading}
                            className="w-full text-white font-medium"
                            data-testid="submit-btn"
                        >
                            {t("objectsDestroy.submit", { labelCap })}
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            {res && (
                <div ref={responseRef} data-testid="response-output">
                    <Card title={t("objectsDestroy.responseTitle", { labelCap })}>{res}</Card>
                </div>
            )}
        </div>
    );
};

export default DestroyForm;
