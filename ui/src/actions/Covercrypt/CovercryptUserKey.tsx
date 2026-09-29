import { Button, Card, Checkbox, Form, Input, Select, Space } from "antd";
import React from "react";
import { Trans, useTranslation } from "react-i18next";
import { sendKmipRequest } from "../../utils/utils";
import { create_cc_user_key_ttlv_request, parse_create_ttlv_response } from "../../wasm/pkg";
import { useActionState } from "../../hooks/useActionState";
import { ActionResponse } from "../../components/common/ActionResponse";
import KeyIdInput from "../../components/common/KeyIdInput";

interface CovercryptUserKeyFormData {
    masterPrivateKeyId: string;
    accessPolicy: string;
    tags: string[];
    sensitive: boolean;
    wrappingKeyId?: string;
}

const POLICY_EXAMPLE = `Department::HR && Security Level::Confidential

More examples:
(Department::MKG && Security Level::Confidential) || (Department::HR && Security Level::Protected)`;

const CovercryptUserKeyForm: React.FC = () => {
    const [form] = Form.useForm<CovercryptUserKeyFormData>();
    const { res, isLoading, responseRef, serverUrl, execute } = useActionState();
    const { t } = useTranslation("actions");

    const onFinish = async (values: CovercryptUserKeyFormData) => {
        await execute(async () => {
            const request = create_cc_user_key_ttlv_request(
                values.masterPrivateKeyId,
                values.accessPolicy,
                values.tags,
                values.sensitive,
                values.wrappingKeyId,
            );
            const result_str = await sendKmipRequest(request, serverUrl);
            if (result_str) {
                const result = await parse_create_ttlv_response(result_str);
                return t("covercryptUserKey.success", { keyId: result.UniqueIdentifier });
            }
        });
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">{t("covercryptUserKey.title")}</h1>

            <div className="mb-8 space-y-2">
                <p>{t("covercryptUserKey.intro")}</p>
                <p>{t("covercryptUserKey.introPolicy")}</p>
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
                            <h3 className="text-m font-bold mb-4">{t("covercryptUserKey.keyConfiguration")}</h3>

                            <KeyIdInput
                                form={form}
                                fieldName="masterPrivateKeyId"
                                label={t("covercryptUserKey.masterPrivateKeyId")}
                                help={t("covercryptUserKey.masterPrivateKeyIdHelp")}
                                rules={[{ required: true, message: t("covercryptUserKey.pleaseEnterMasterPrivateKeyId") }]}
                                placeholder={t("covercryptUserKey.enterMasterPrivateKeyId")}
                                objectType="PrivateKey"
                            />

                            <Form.Item
                                name="accessPolicy"
                                label={t("covercryptUserKey.accessPolicy")}
                                help={
                                    <div className="text-sm space-y-2">
                                        <p>{t("covercryptUserKey.policyHelp")}</p>
                                        <div className="p-3 rounded">
                                            <p className="font-medium mb-2">{t("covercryptUserKey.exampleFormats")}</p>
                                            <pre className="text-xs whitespace-pre-wrap">{POLICY_EXAMPLE}</pre>
                                            <p className="mt-2 text-xs">{t("covercryptUserKey.hierarchyNote")}</p>
                                        </div>
                                        <ul className="list-disc pl-5 mt-2 space-y-1">
                                            <li>
                                                <Trans
                                                    ns="actions"
                                                    i18nKey="covercryptUserKey.andOrOperators"
                                                    components={{ code: <code /> }}
                                                />
                                            </li>
                                            <li>{t("covercryptUserKey.groupExpressions")}</li>
                                            <li>{t("covercryptUserKey.useExactAttributes")}</li>
                                        </ul>
                                    </div>
                                }
                                rules={[{ required: true, message: t("covercryptUserKey.pleaseEnterAccessPolicy") }]}
                            >
                                <Input.TextArea
                                    placeholder={t("covercryptUserKey.enterAccessPolicy")}
                                    rows={4}
                                    className="font-mono text-sm"
                                />
                            </Form.Item>
                        </div>
                    </Card>
                    <Card>
                        <Form.Item name="tags" label={t("common:tags")} help={t("covercryptUserKey.tagsHelp")}>
                            <Select mode="tags" placeholder={t("common:enterTags")} open={false} />
                        </Form.Item>

                        <KeyIdInput
                            form={form}
                            fieldName="wrappingKeyId"
                            label={t("covercryptUserKey.wrappingKeyId")}
                            help={t("covercryptUserKey.wrappingKeyIdHelp")}
                            placeholder={t("covercryptUserKey.enterWrappingKeyId")}
                            objectType="SymmetricKey"
                        />

                        <Form.Item name="sensitive" valuePropName="checked" help={t("covercryptUserKey.sensitiveHelp")}>
                            <Checkbox>
                                <span>{t("covercryptUserKey.sensitive")}</span>
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
                            {t("covercryptUserKey.submit")}
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            <ActionResponse res={res} responseRef={responseRef} title={t("covercryptUserKey.responseTitle")} />
        </div>
    );
};

export default CovercryptUserKeyForm;
