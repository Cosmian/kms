import { Button, Card, Checkbox, Form, Input, Select, Space } from "antd";
import React, { useEffect } from "react";
import { useTranslation } from "react-i18next";
import { sendKmipRequest } from "../../utils/utils";
import { create_secret_data_ttlv_request, parse_create_ttlv_response, parse_import_ttlv_response } from "../../wasm/pkg";
import { useActionState } from "../../hooks/useActionState";
import { ActionResponse } from "../../components/common/ActionResponse";

interface SecretDataCreateFormData {
    secretId?: string;
    secretValue?: string;
    secretType: "Seed" | "Password";
    tags: string[];
    sensitive: boolean;
    wrappingKeyId?: string;
}

type CreateResponse = {
    ObjectType: string;
    UniqueIdentifier: string;
};

type ImportResponse = {
    UniqueIdentifier: string;
};

const SecretDataCreateForm: React.FC = () => {
    const [form] = Form.useForm<SecretDataCreateFormData>();
    const { res, isLoading, responseRef, serverUrl, execute } = useActionState();
    const { t } = useTranslation("actions");
    const secretValue = Form.useWatch("secretValue", form);

    useEffect(() => {
        if (!secretValue) {
            form.setFieldsValue({ secretType: "Seed" });
        }
    }, [secretValue, form]);

    const onFinish = async (values: SecretDataCreateFormData) => {
        await execute(async () => {
            const request = create_secret_data_ttlv_request(
                values.secretType,
                values.secretValue,
                values.secretId,
                values.tags,
                values.sensitive,
                values.wrappingKeyId,
            );
            const result_str = await sendKmipRequest(request, serverUrl);
            if (result_str) {
                if (values.secretValue) {
                    const result: ImportResponse = await parse_import_ttlv_response(result_str);
                    return t("secretDataCreate.success", { secretId: result.UniqueIdentifier });
                } else {
                    const result: CreateResponse = await parse_create_ttlv_response(result_str);
                    return t("secretDataCreate.success", { secretId: result.UniqueIdentifier });
                }
            }
        });
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">{t("secretDataCreate.title")}</h1>

            <div className="mb-8 space-y-2">
                <p>{t("secretDataCreate.intro")}</p>
                <ul className="list-disc pl-5 space-y-1">
                    <li>{t("secretDataCreate.introValue")}</li>
                    <li>{t("secretDataCreate.introRandom")}</li>
                    <li>{t("secretDataCreate.introTags")}</li>
                </ul>
            </div>

            <Form
                form={form}
                onFinish={onFinish}
                layout="vertical"
                initialValues={{
                    secretType: "Seed",
                    tags: [],
                    sensitive: false,
                }}
            >
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <Form.Item
                            name="secretValue"
                            label={t("secretDataCreate.secretValue")}
                            help={t("secretDataCreate.secretValueHelp")}
                        >
                            <Input.TextArea placeholder={t("secretDataCreate.enterSecretValue")} rows={2} />
                        </Form.Item>

                        <Form.Item
                            name="secretType"
                            label={t("secretDataCreate.secretType")}
                            help={t("secretDataCreate.secretTypeHelp")}
                            rules={[{ required: true, message: t("secretDataCreate.pleaseSelectSecretType") }]}
                        >
                            <Select disabled={!secretValue} data-testid="secret-type-select">
                                <Select.Option value="Seed">Seed</Select.Option>
                                <Select.Option value="Password">Password</Select.Option>
                            </Select>
                        </Form.Item>

                        <Form.Item name="secretId" label={t("secretDataCreate.secretId")} help={t("secretDataCreate.secretIdHelp")}>
                            <Input placeholder={t("secretDataCreate.enterSecretId")} />
                        </Form.Item>

                        <Form.Item name="tags" label={t("common:tags")} help={t("secretDataCreate.tagsHelp")}>
                            <Select mode="tags" placeholder={t("common:enterTags")} open={false} />
                        </Form.Item>

                        <Form.Item
                            name="wrappingKeyId"
                            label={t("secretDataCreate.wrappingKeyId")}
                            help={t("secretDataCreate.wrappingKeyIdHelp")}
                        >
                            <Input placeholder={t("secretDataCreate.enterWrappingKeyId")} />
                        </Form.Item>

                        <Form.Item name="sensitive" valuePropName="checked" help={t("secretDataCreate.sensitiveHelp")}>
                            <Checkbox>{t("secretDataCreate.sensitive")}</Checkbox>
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
                            {t("secretDataCreate.submit")}
                        </Button>
                    </Form.Item>
                </Space>
                <ActionResponse res={res} responseRef={responseRef} title={t("secretDataCreate.responseTitle")} />
            </Form>
        </div>
    );
};

export default SecretDataCreateForm;
