import { Button, Card, Checkbox, Divider, Form, Input, InputNumber, Select, Space } from "antd";
import React, { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { sendKmipRequest } from "../../utils/utils";
import * as wasm from "../../wasm/pkg";
import { useActionState } from "../../hooks/useActionState";
import { ActionResponse } from "../../components/common/ActionResponse";
import KeyIdInput from "../../components/common/KeyIdInput";

interface ECKeyCreateFormData {
    privateKeyId?: string;
    curve: string;
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

const ECKeyCreateForm: React.FC = () => {
    const [form] = Form.useForm<ECKeyCreateFormData>();
    const { res, isLoading, responseRef, serverUrl, execute } = useActionState();
    const { t } = useTranslation("actions");
    const [curveOptions, setCurveOptions] = useState<{ value: string; label: string }[]>([]);

    useEffect(() => {
        try {
            const w = wasm as unknown as { get_ec_algorithms?: () => { value: string; label: string }[] };
            const opts = w.get_ec_algorithms ? w.get_ec_algorithms() : [];
            setCurveOptions(opts);
        } catch (e) {
            console.error("Error loading EC algorithms from WASM:", e);
        }
    }, []);

    // When curve options load, set the default curve automatically
    useEffect(() => {
        if (curveOptions.length > 0) {
            const current = form.getFieldValue("curve");
            if (!current) {
                form.setFieldsValue({ curve: curveOptions[0].value });
            }
        }
    }, [curveOptions, form]);

    const onFinish = async (values: ECKeyCreateFormData) => {
        await execute(async () => {
            const request = wasm.create_ec_key_pair_ttlv_request(
                values.privateKeyId,
                values.tags,
                values.curve,
                values.sensitive,
                values.wrappingKeyId,
            );
            const result_str = await sendKmipRequest(request, serverUrl);
            if (result_str) {
                const result: CreateKeyPairResponse = await wasm.parse_create_keypair_ttlv_response(result_str);
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

                return t("ecKeysCreate.success", {
                    privateKeyId: skId,
                    publicKeyId: result.PublicKeyUniqueIdentifier,
                });
            }
        });
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">{t("ecKeysCreate.title")}</h1>
            <div className="mb-8 space-y-2">
                <p>{t("ecKeysCreate.intro")}</p>
                <ul className="list-disc pl-5 space-y-1">
                    <li>{t("ecKeysCreate.introPublicKey")}</li>
                    <li>{t("ecKeysCreate.introPrivateKey")}</li>
                </ul>
                <p>{t("ecKeysCreate.introTags")}</p>
            </div>

            <Form
                form={form}
                onFinish={onFinish}
                layout="vertical"
                initialValues={{
                    // curve set via useEffect when options are available
                    tags: [],
                    sensitive: false,
                    enrollKeyset: false,
                }}
            >
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <Form.Item
                            name="curve"
                            label={t("ecKeysCreate.curve")}
                            help={t("ecKeysCreate.curveHelp")}
                            rules={[{ required: true, message: t("ecKeysCreate.pleaseSelectCurve") }]}
                        >
                            <Select options={curveOptions} data-testid="ec-curve-select" />
                        </Form.Item>

                        <Form.Item name="privateKeyId" label={t("ecKeysCreate.privateKeyId")} help={t("ecKeysCreate.privateKeyIdHelp")}>
                            <Input placeholder={t("ecKeysCreate.enterPrivateKeyId")} />
                        </Form.Item>

                        <Form.Item name="tags" label={t("common:tags")} help={t("ecKeysCreate.tagsHelp")}>
                            <Select mode="tags" placeholder={t("common:enterTags")} open={false} />
                        </Form.Item>

                        <KeyIdInput
                            form={form}
                            fieldName="wrappingKeyId"
                            label={t("ecKeysCreate.wrappingKeyId")}
                            help={t("ecKeysCreate.wrappingKeyIdHelp")}
                            placeholder={t("ecKeysCreate.enterWrappingKeyId")}
                            objectType="SymmetricKey"
                        />

                        <Form.Item name="sensitive" valuePropName="checked" help={t("ecKeysCreate.sensitiveHelp")}>
                            <Checkbox>{t("ecKeysCreate.sensitive")}</Checkbox>
                        </Form.Item>

                        <Divider orientation="left" plain>
                            {t("ecKeysCreate.rotationPolicy")}
                        </Divider>

                        <Form.Item name="enrollKeyset" valuePropName="checked" help={t("ecKeysCreate.enrollKeysetHelp")}>
                            <Checkbox data-testid="ec-enroll-keyset">{t("ecKeysCreate.enrollKeyset")}</Checkbox>
                        </Form.Item>

                        <Form.Item noStyle shouldUpdate={(prev, curr) => prev.enrollKeyset !== curr.enrollKeyset}>
                            {({ getFieldValue }) =>
                                getFieldValue("enrollKeyset") ? (
                                    <>
                                        <Form.Item
                                            name="rotateInterval"
                                            label={t("ecKeysCreate.rotateInterval")}
                                            help={t("ecKeysCreate.rotateIntervalHelp")}
                                        >
                                            <InputNumber
                                                className="w-[200px]"
                                                min={0}
                                                placeholder={t("ecKeysCreate.rotateIntervalPlaceholder")}
                                                data-testid="ec-rotation-interval"
                                            />
                                        </Form.Item>

                                        <Form.Item
                                            name="rotateOffset"
                                            label={t("ecKeysCreate.rotateOffset")}
                                            help={t("ecKeysCreate.rotateOffsetHelp")}
                                        >
                                            <InputNumber
                                                className="w-[200px]"
                                                min={0}
                                                placeholder={t("ecKeysCreate.rotateOffsetPlaceholder")}
                                                data-testid="ec-rotation-offset"
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
                            {t("ecKeysCreate.submit")}
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            <ActionResponse res={res} responseRef={responseRef} title={t("ecKeysCreate.responseTitle")} />
        </div>
    );
};

export default ECKeyCreateForm;
