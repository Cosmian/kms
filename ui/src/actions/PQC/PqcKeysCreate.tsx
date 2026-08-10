import { Button, Card, Checkbox, Divider, Form, Input, InputNumber, Select, Space } from "antd";
import React, { useEffect, useState } from "react";
import { Trans, useTranslation } from "react-i18next";
import { useBranding } from "../../contexts/useBranding";
import { sendKmipRequest } from "../../utils/utils";
import * as wasm from "../../wasm/pkg";
import { useActionState } from "../../hooks/useActionState";
import { ActionResponse } from "../../components/common/ActionResponse";

interface PqcKeyCreateFormData {
    algorithm: string;
    tags: string[];
    sensitive: boolean;
    enrollKeyset: boolean;
    rotateInterval?: number;
    rotateOffset?: number;
}

type CreateKeyPairResponse = {
    PrivateKeyUniqueIdentifier: string;
    PublicKeyUniqueIdentifier: string;
};

const PqcKeysCreateForm: React.FC = () => {
    const [form] = Form.useForm<PqcKeyCreateFormData>();
    const { res, isLoading, responseRef, serverUrl, execute } = useActionState();
    const { t } = useTranslation("actions");
    const branding = useBranding();
    const [algorithmOptions, setAlgorithmOptions] = useState<{ value: string; label: string }[]>([]);

    useEffect(() => {
        try {
            const w = wasm as unknown as { get_pqc_algorithms?: () => { value: string; label: string }[] };
            const opts = w.get_pqc_algorithms ? w.get_pqc_algorithms() : [];
            const hidden = branding.hiddenPqcAlgorithms ?? [];
            setAlgorithmOptions(opts.filter((o) => !hidden.includes(o.value)));
        } catch (e) {
            console.error("Error loading PQC algorithms from WASM:", e);
        }
    }, [branding.hiddenPqcAlgorithms]);

    useEffect(() => {
        if (algorithmOptions.length > 0) {
            const current = form.getFieldValue("algorithm");
            if (!current) {
                form.setFieldsValue({ algorithm: algorithmOptions[0].value });
            }
        }
    }, [algorithmOptions, form]);

    const onFinish = async (values: PqcKeyCreateFormData) => {
        await execute(async () => {
            const request = wasm.create_pqc_key_pair_ttlv_request(values.tags, values.algorithm, values.sensitive);
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
                        // rotation name is set to the private key ID (server-generated for PQC)
                        const req = wasm.set_rotate_name_ttlv_request(skId, skId);
                        await sendKmipRequest(req, serverUrl);
                    }
                }

                return t("pqcKeysCreate.success", {
                    privateKeyId: skId,
                    publicKeyId: result.PublicKeyUniqueIdentifier,
                });
            }
        });
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">{t("pqcKeysCreate.title")}</h1>
            <div className="mb-8 space-y-2">
                <p>{t("pqcKeysCreate.intro")}</p>
                <ul className="list-disc pl-5 space-y-1">
                    <li>
                        <Trans ns="actions" i18nKey="pqcKeysCreate.introMlKem" components={{ strong: <strong /> }} />
                    </li>
                    <li>
                        <Trans ns="actions" i18nKey="pqcKeysCreate.introHybridKem" components={{ strong: <strong /> }} />
                    </li>
                    <li>
                        <Trans ns="actions" i18nKey="pqcKeysCreate.introMlDsa" components={{ strong: <strong /> }} />
                    </li>
                    <li>
                        <Trans ns="actions" i18nKey="pqcKeysCreate.introSlhDsa" components={{ strong: <strong /> }} />
                    </li>
                </ul>
                <p>{t("pqcKeysCreate.introTags")}</p>
            </div>

            <Form
                form={form}
                onFinish={onFinish}
                layout="vertical"
                initialValues={{
                    tags: [],
                    sensitive: false,
                    enrollKeyset: false,
                }}
            >
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <Form.Item
                            name="algorithm"
                            label={t("common:algorithm")}
                            help={t("pqcKeysCreate.algorithmHelp")}
                            rules={[{ required: true, message: t("pqcKeysCreate.pleaseSelectAlgorithm") }]}
                        >
                            <Select options={algorithmOptions} data-testid="pqc-algorithm-select" />
                        </Form.Item>

                        <Form.Item name="tags" label={t("common:tags")} help={t("pqcKeysCreate.tagsHelp")}>
                            <Select mode="tags" placeholder={t("common:enterTags")} open={false} />
                        </Form.Item>

                        <Form.Item name="sensitive" valuePropName="checked" help={t("pqcKeysCreate.sensitiveHelp")}>
                            <Checkbox>{t("pqcKeysCreate.sensitive")}</Checkbox>
                        </Form.Item>

                        <Divider orientation="left" plain>
                            {t("pqcKeysCreate.rotationPolicy")}
                        </Divider>

                        <Form.Item name="rotateName" label={t("pqcKeysCreate.rotateName")} help={t("pqcKeysCreate.rotateNameHelp")}>
                            <Input placeholder={t("pqcKeysCreate.rotateNamePlaceholder")} data-testid="pqc-rotation-name" />
                        </Form.Item>

                        <Form.Item
                            name="rotateInterval"
                            label={t("pqcKeysCreate.rotateInterval")}
                            help={t("pqcKeysCreate.rotateIntervalHelp")}
                        >
                            <InputNumber
                                className="w-[200px]"
                                min={0}
                                placeholder={t("pqcKeysCreate.rotateIntervalPlaceholder")}
                                data-testid="pqc-rotation-interval"
                            />
                        </Form.Item>

                        <Form.Item name="rotateOffset" label={t("pqcKeysCreate.rotateOffset")} help={t("pqcKeysCreate.rotateOffsetHelp")}>
                            <InputNumber
                                className="w-[200px]"
                                min={0}
                                placeholder={t("pqcKeysCreate.rotateOffsetPlaceholder")}
                                data-testid="pqc-rotation-offset"
                            />
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
                            {t("pqcKeysCreate.submit")}
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            <ActionResponse res={res} responseRef={responseRef} title={t("pqcKeysCreate.responseTitle")} />
        </div>
    );
};

export default PqcKeysCreateForm;
