import { Button, Card, Checkbox, Form, Input, Select, Space } from "antd";
import React, { useEffect } from "react";
import { useTranslation } from "react-i18next";
import { sendKmipRequest } from "../../utils/utils";
import { create_opaque_object_ttlv_request, parse_import_ttlv_response } from "../../wasm/pkg";
import { useActionState } from "../../hooks/useActionState";
import { ActionResponse } from "../../components/common/ActionResponse";
import KeyIdInput from "../../components/common/KeyIdInput";

interface OpaqueObjectFormData {
    objectId?: string;
    objectValue?: string;
    objectType: "Opaque";
    tags: string[];
    sensitive: boolean;
    wrappingKeyId?: string;
}

type ImportResponse = {
    UniqueIdentifier: string;
};

const OpaqueObjectForm: React.FC = () => {
    const [form] = Form.useForm<OpaqueObjectFormData>();
    const { res, isLoading, responseRef, serverUrl, execute } = useActionState();
    const { t } = useTranslation("actions");
    const objectValue = Form.useWatch("objectValue", form);

    useEffect(() => {
        if (!objectValue) {
            form.setFieldsValue({ objectType: "Opaque" });
        }
    }, [objectValue, form]);

    const onFinish = async (values: OpaqueObjectFormData) => {
        await execute(async () => {
            const request = create_opaque_object_ttlv_request(
                values.objectValue,
                values.objectId,
                values.tags,
                values.sensitive,
                values.wrappingKeyId,
            );
            const result_str = await sendKmipRequest(request, serverUrl);
            if (result_str) {
                const result: ImportResponse = await parse_import_ttlv_response(result_str);
                return t("opaqueObject.success", { objectId: result.UniqueIdentifier });
            }
        });
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">{t("opaqueObject.title")}</h1>

            <div className="mb-8 space-y-2">
                <p>{t("opaqueObject.intro")}</p>
                <ul className="list-disc pl-5 space-y-1">
                    <li>{t("opaqueObject.introValue")}</li>
                    <li>{t("opaqueObject.introEmpty")}</li>
                    <li>{t("opaqueObject.introTags")}</li>
                </ul>
            </div>

            <Form
                form={form}
                onFinish={onFinish}
                layout="vertical"
                initialValues={{
                    objectType: "Opaque",
                    tags: [],
                    sensitive: false,
                }}
            >
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <Form.Item name="objectValue" label={t("opaqueObject.opaqueData")} help={t("opaqueObject.opaqueDataHelp")}>
                            <Input.TextArea placeholder={t("opaqueObject.enterOpaqueData")} rows={2} />
                        </Form.Item>

                        <Form.Item
                            name="objectType"
                            label={t("common:objectType")}
                            help={t("opaqueObject.objectTypeHelp")}
                            rules={[{ required: true, message: t("opaqueObject.pleaseConfirmObjectType") }]}
                        >
                            <Select disabled>
                                <Select.Option value="Opaque">Opaque</Select.Option>
                            </Select>
                        </Form.Item>

                        <Form.Item name="objectId" label={t("common:objectId")} help={t("opaqueObject.objectIdHelp")}>
                            <Input placeholder={t("common:enterObjectId")} />
                        </Form.Item>

                        <Form.Item name="tags" label={t("common:tags")} help={t("opaqueObject.tagsHelp")}>
                            <Select mode="tags" placeholder={t("common:enterTags")} open={false} />
                        </Form.Item>

                        <KeyIdInput
                            form={form}
                            fieldName="wrappingKeyId"
                            label={t("opaqueObject.wrappingKeyId")}
                            help={t("opaqueObject.wrappingKeyIdHelp")}
                            placeholder={t("opaqueObject.enterWrappingKeyId")}
                            objectType="SymmetricKey"
                        />

                        <Form.Item name="sensitive" valuePropName="checked" help={t("opaqueObject.sensitiveHelp")}>
                            <Checkbox>{t("opaqueObject.sensitive")}</Checkbox>
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
                            {t("opaqueObject.submit")}
                        </Button>
                    </Form.Item>
                </Space>
                <ActionResponse res={res} responseRef={responseRef} title={t("opaqueObject.responseTitle")} />
            </Form>
        </div>
    );
};

export default OpaqueObjectForm;
