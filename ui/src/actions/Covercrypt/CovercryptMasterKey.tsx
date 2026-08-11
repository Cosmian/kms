import { Button, Card, Checkbox, Form, Input, Select, Space } from "antd";
import React from "react";
import { Trans, useTranslation } from "react-i18next";
import { FormUploadDragger } from "../../components/common/FormUpload";
import { sendKmipRequest } from "../../utils/utils";
import { create_cc_master_keypair_ttlv_request, parse_create_keypair_ttlv_response } from "../../wasm/pkg";
import { useActionState } from "../../hooks/useActionState";
import { ActionResponse } from "../../components/common/ActionResponse";

interface CovercryptMasterKeyFormData {
    specification: string;
    tags: string[];
    sensitive: boolean;
    wrappingKeyId?: string;
}

const SPECIFICATION_EXAMPLE = `{
    "Security Level::<": [
        "Protected",
        "Confidential",
        "Top Secret::+"
    ],
    "Department": [
        "R&D",
        "HR",
        "MKG",
        "FIN"
    ]
}`;

const CovercryptMasterKeyForm: React.FC = () => {
    const [form] = Form.useForm<CovercryptMasterKeyFormData>();
    const { res, isLoading, responseRef, serverUrl, execute } = useActionState();
    const { t } = useTranslation("actions");
    const [specificationType, setSpecificationType] = React.useState<"json-file" | "json-text">("json-file");

    const onFinish = async (values: CovercryptMasterKeyFormData) => {
        await execute(async () => {
            const request = create_cc_master_keypair_ttlv_request(
                values.specification,
                values.tags,
                values.sensitive,
                values.wrappingKeyId,
            );
            const result_str = await sendKmipRequest(request, serverUrl);
            if (result_str) {
                const result = await parse_create_keypair_ttlv_response(result_str);
                return t("covercryptMasterKey.success", {
                    privateKeyId: result.PrivateKeyUniqueIdentifier,
                    publicKeyId: result.PublicKeyUniqueIdentifier,
                });
            }
        });
    };

    const SpecificationExplanation = () => (
        <div className="mt-2 space-y-1">
            <p className="font-medium">{t("covercryptMasterKey.exampleIntro")}</p>
            <ul className="list-disc pl-5 space-y-1">
                <li>
                    <Trans ns="actions" i18nKey="covercryptMasterKey.exampleAxes" components={{ code: <code /> }} />
                </li>
                <li>
                    <Trans ns="actions" i18nKey="covercryptMasterKey.exampleHierarchy" components={{ code: <code /> }} />
                </li>
                <li>{t("covercryptMasterKey.exampleLevels")}</li>
                <li>{t("covercryptMasterKey.exampleDepartments")}</li>
                <li>
                    <Trans ns="actions" i18nKey="covercryptMasterKey.examplePq" components={{ code: <code /> }} />
                </li>
                <li>{t("covercryptMasterKey.exampleClassic")}</li>
            </ul>
        </div>
    );

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold  mb-6">{t("covercryptMasterKey.title")}</h1>

            <div className="mb-8 space-y-2">
                <p>{t("covercryptMasterKey.intro")}</p>
                <ul className="list-disc pl-5 space-y-1">
                    <li>{t("covercryptMasterKey.introPublicKey")}</li>
                    <li>{t("covercryptMasterKey.introSecretKey")}</li>
                </ul>
            </div>

            <Form
                form={form}
                onFinish={onFinish}
                layout="vertical"
                initialValues={{
                    sensitive: false,
                    tags: [],
                }}
            >
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <div className="p-4 rounded-lg space-y-4">
                            <h3 className="text-m font-bold mb-4">{t("covercryptMasterKey.specificationConfig")}</h3>

                            <Form.Item>
                                <Select
                                    value={specificationType}
                                    onChange={(value) => setSpecificationType(value)}
                                    data-testid="spec-type-select"
                                    options={[
                                        { label: t("covercryptMasterKey.uploadJsonFile"), value: "json-file" },
                                        { label: t("covercryptMasterKey.enterJson"), value: "json-text" },
                                    ]}
                                />
                            </Form.Item>

                            {specificationType === "json-file" && (
                                <Form.Item
                                    name="specificationFile"
                                    rules={[{ required: true, message: t("covercryptMasterKey.pleaseProvideSpecifications") }]}
                                >
                                    <FormUploadDragger
                                        accept=".json"
                                        beforeUpload={(file) => {
                                            const reader = new FileReader();
                                            reader.onload = (e) => {
                                                const text = e.target?.result as string;
                                                if (text) {
                                                    form.setFieldsValue({ specification: text });
                                                }
                                            };
                                            reader.readAsText(file);
                                            return false;
                                        }}
                                        maxCount={1}
                                    >
                                        <p className="ant-upload-text">{t("covercryptMasterKey.uploadText")}</p>
                                    </FormUploadDragger>
                                </Form.Item>
                            )}

                            {specificationType === "json-text" && (
                                <Form.Item
                                    name="specification"
                                    rules={[
                                        { required: true, message: t("covercryptMasterKey.pleaseEnterSpecJson") },
                                        {
                                            validator: async (_, value) => {
                                                if (value) {
                                                    try {
                                                        JSON.parse(value);
                                                    } catch (e) {
                                                        throw new Error(t("covercryptMasterKey.invalidJson", { error: e }));
                                                    }
                                                }
                                            },
                                        },
                                    ]}
                                >
                                    <Input.TextArea
                                        data-testid="spec-json-textarea"
                                        placeholder={t("covercryptMasterKey.placeholderSpec")}
                                        rows={10}
                                        className="font-mono text-sm"
                                    />
                                </Form.Item>
                            )}
                        </div>

                        <div className="p-4 rounded mb-4">
                            <p className="text-sm mb-2">{t("covercryptMasterKey.exampleFormat")}</p>
                            <pre className="p-2 rounded text-xs overflow-auto">{SPECIFICATION_EXAMPLE}</pre>
                            <SpecificationExplanation />
                        </div>

                        <Form.Item name="tags" label={t("common:tags")} help={t("covercryptMasterKey.tagsHelp")}>
                            <Select mode="tags" placeholder={t("common:enterTags")} open={false} />
                        </Form.Item>

                        <Form.Item
                            name="wrappingKeyId"
                            label={t("covercryptMasterKey.wrappingKeyId")}
                            help={t("covercryptMasterKey.wrappingKeyIdHelp")}
                        >
                            <Input placeholder={t("covercryptMasterKey.enterWrappingKeyId")} />
                        </Form.Item>

                        <Form.Item name="sensitive" valuePropName="checked" help={t("covercryptMasterKey.sensitiveHelp")}>
                            <Checkbox>
                                <span>{t("covercryptMasterKey.sensitive")}</span>
                            </Checkbox>
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
                            {t("covercryptMasterKey.submit")}
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            <ActionResponse res={res} responseRef={responseRef} title={t("covercryptMasterKey.responseTitle")} />
        </div>
    );
};

export default CovercryptMasterKeyForm;
