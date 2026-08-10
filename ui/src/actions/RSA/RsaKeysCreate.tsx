import { Button, Card, Checkbox, Divider, Form, Input, InputNumber, Select, Space } from "antd";
import React from "react";
import { useTranslation } from "react-i18next";
import { sendKmipRequest } from "../../utils/utils";
import { create_rsa_key_pair_ttlv_request, parse_create_keypair_ttlv_response } from "../../wasm/pkg";
import * as wasm from "../../wasm/pkg";
import { useActionState } from "../../hooks/useActionState";
import { ActionResponse } from "../../components/common/ActionResponse";

interface RsaKeyCreateFormData {
    privateKeyId?: string;
    sizeInBits: number;
    tags: string[];
    sensitive: boolean;
    wrappingKeyId?: string;
    enrollKeyset: boolean;
    rotateInterval?: number;
    rotateOffset?: number;
}

type CreateKeyPairResponse = {
    PrivateKeyUniqueIdentifier: string;
    PublicKeyUniqueIdentifier: string;
};

const RsaKeyCreateForm: React.FC = () => {
    const [form] = Form.useForm<RsaKeyCreateFormData>();
    const { res, isLoading, responseRef, serverUrl, execute } = useActionState();
    const { t } = useTranslation("actions");

    const onFinish = async (values: RsaKeyCreateFormData) => {
        await execute(async () => {
            const request = create_rsa_key_pair_ttlv_request(
                values.privateKeyId,
                values.tags,
                values.sizeInBits,
                values.sensitive,
                values.wrappingKeyId,
            );
            const result_str = await sendKmipRequest(request, serverUrl);
            if (result_str) {
                const result: CreateKeyPairResponse = await parse_create_keypair_ttlv_response(result_str);
                const skId = result.PrivateKeyUniqueIdentifier;

                // Apply rotation policy on the private key (keyset anchor)
                if (values.enrollKeyset || values.rotateInterval !== undefined || values.rotateOffset !== undefined) {
                    if (values.rotateInterval !== undefined) {
                        const req = wasm.set_rotate_interval_ttlv_request(skId, BigInt(values.rotateInterval));
                        await sendKmipRequest(req, serverUrl);
                    }
                    if (values.rotateOffset !== undefined) {
                        const req = wasm.set_rotate_offset_ttlv_request(skId, BigInt(values.rotateOffset));
                        await sendKmipRequest(req, serverUrl);
                    }
                    if (values.enrollKeyset) {
                        // rotation name must equal the private key ID
                        const req = wasm.set_rotate_name_ttlv_request(skId, skId);
                        await sendKmipRequest(req, serverUrl);
                    }
                }

                return t("rsaKeysCreate.success", {
                    privateKeyId: skId,
                    publicKeyId: result.PublicKeyUniqueIdentifier,
                });
            }
        });
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">{t("rsaKeysCreate.title")}</h1>

            <div className="mb-8 space-y-2">
                <p>{t("rsaKeysCreate.intro")}</p>
                <ul className="list-disc pl-5 space-y-1">
                    <li>{t("rsaKeysCreate.introPublicKey")}</li>
                    <li>{t("rsaKeysCreate.introPrivateKey")}</li>
                </ul>
                <p>{t("rsaKeysCreate.introTags")}</p>
            </div>

            <Form
                form={form}
                onFinish={onFinish}
                layout="vertical"
                initialValues={{
                    sizeInBits: 4096,
                    tags: [],
                    sensitive: false,
                    enrollKeyset: false,
                }}
            >
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <Form.Item name="privateKeyId" label={t("rsaKeysCreate.privateKeyId")} help={t("rsaKeysCreate.privateKeyIdHelp")}>
                            <Input placeholder={t("rsaKeysCreate.enterPrivateKeyId")} />
                        </Form.Item>

                        <Form.Item
                            name="sizeInBits"
                            label={t("rsaKeysCreate.sizeInBits")}
                            help={t("rsaKeysCreate.sizeInBitsHelp")}
                            rules={[{ required: true, message: t("rsaKeysCreate.pleaseSpecifySize") }]}
                        >
                            <InputNumber className="w-[200px]" min={1024} step={1024} max={8192} />
                        </Form.Item>

                        <Form.Item name="tags" label={t("common:tags")} help={t("rsaKeysCreate.tagsHelp")}>
                            <Select mode="tags" placeholder={t("common:enterTags")} open={false} />
                        </Form.Item>

                        <Form.Item
                            name="wrappingKeyId"
                            label={t("rsaKeysCreate.wrappingKeyId")}
                            help={t("rsaKeysCreate.wrappingKeyIdHelp")}
                        >
                            <Input placeholder={t("rsaKeysCreate.enterWrappingKeyId")} />
                        </Form.Item>

                        <Form.Item name="sensitive" valuePropName="checked" help={t("rsaKeysCreate.sensitiveHelp")}>
                            <Checkbox>{t("rsaKeysCreate.sensitive")}</Checkbox>
                        </Form.Item>

                        <Divider orientation="left" plain>
                            {t("rsaKeysCreate.rotationPolicy")}
                        </Divider>

                        <Form.Item name="enrollKeyset" valuePropName="checked" help={t("rsaKeysCreate.enrollKeysetHelp")}>
                            <Checkbox data-testid="rsa-enroll-keyset">{t("rsaKeysCreate.enrollKeyset")}</Checkbox>
                        </Form.Item>

                        <Form.Item noStyle shouldUpdate={(prev, curr) => prev.enrollKeyset !== curr.enrollKeyset}>
                            {({ getFieldValue }) =>
                                getFieldValue("enrollKeyset") ? (
                                    <>
                                        <Form.Item
                                            name="rotateInterval"
                                            label={t("rsaKeysCreate.rotateInterval")}
                                            help={t("rsaKeysCreate.rotateIntervalHelp")}
                                        >
                                            <InputNumber
                                                className="w-[200px]"
                                                min={0}
                                                placeholder={t("rsaKeysCreate.rotateIntervalPlaceholder")}
                                                data-testid="rsa-rotation-interval"
                                            />
                                        </Form.Item>

                                        <Form.Item
                                            name="rotateOffset"
                                            label={t("rsaKeysCreate.rotateOffset")}
                                            help={t("rsaKeysCreate.rotateOffsetHelp")}
                                        >
                                            <InputNumber
                                                className="w-[200px]"
                                                min={0}
                                                placeholder={t("rsaKeysCreate.rotateOffsetPlaceholder")}
                                                data-testid="rsa-rotation-offset"
                                            />
                                        </Form.Item>
                                    </>
                                ) : null
                            }
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
                            {t("rsaKeysCreate.submit")}
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            <ActionResponse res={res} responseRef={responseRef} title={t("rsaKeysCreate.responseTitle")} />
        </div>
    );
};

export default RsaKeyCreateForm;
