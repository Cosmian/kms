import { Button, Card, Checkbox, Divider, Form, Input, InputNumber, Select, Space } from "antd";
import React, { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { sendKmipRequest } from "../../utils/utils";
import * as wasm from "../../wasm/pkg";
import { useActionState } from "../../hooks/useActionState";
import { ActionResponse } from "../../components/common/ActionResponse";

interface SymKeyCreateFormData {
    keyId?: string;
    algorithm: string; // options provided by WASM get_symmetric_algorithms()
    numberOfBits?: number;
    bytesB64?: string;
    tags: string[];
    sensitive: boolean;
    wrappingKeyId?: string;
    enrollKeyset: boolean;
    rotateInterval?: number;
    rotateOffset?: number;
}

type CreateResponse = {
    ObjectType: string;
    UniqueIdentifier: string;
};

const SymKeyCreateForm: React.FC = () => {
    const [form] = Form.useForm<SymKeyCreateFormData>();
    const { res, isLoading, responseRef, serverUrl, execute } = useActionState();
    const [algoOptions, setAlgoOptions] = useState<{ value: string; label: string }[]>([]);
    const { t } = useTranslation("actions");

    useEffect(() => {
        try {
            const w = wasm as unknown as { get_symmetric_algorithms?: () => { value: string; label: string }[] };
            const opts = w.get_symmetric_algorithms ? w.get_symmetric_algorithms() : [];
            setAlgoOptions(opts);
        } catch (e) {
            console.error("Error loading symmetric algorithms from WASM:", e);
        }
    }, []);

    const onFinish = async (values: SymKeyCreateFormData) => {
        await execute(async () => {
            const request = wasm.create_sym_key_ttlv_request(
                values.keyId,
                values.tags,
                values.numberOfBits,
                values.algorithm,
                values.sensitive,
                values.wrappingKeyId,
                values.bytesB64,
            );
            const result_str = await sendKmipRequest(request, serverUrl);
            if (result_str) {
                const result: CreateResponse = await wasm.parse_create_ttlv_response(result_str);
                const keyId = result.UniqueIdentifier;

                // Apply rotation policy if any fields were provided
                if (values.enrollKeyset || values.rotateInterval !== undefined || values.rotateOffset !== undefined) {
                    if (values.rotateInterval !== undefined) {
                        const req = wasm.set_rotate_interval_ttlv_request(keyId, BigInt(values.rotateInterval));
                        await sendKmipRequest(req, serverUrl);
                    }
                    if (values.rotateOffset !== undefined) {
                        const req = wasm.set_rotate_offset_ttlv_request(keyId, BigInt(values.rotateOffset));
                        await sendKmipRequest(req, serverUrl);
                    }
                    if (values.enrollKeyset) {
                        // rotation name must equal the key ID for SQL-backed keys
                        const req = wasm.set_rotate_name_ttlv_request(keyId, keyId);
                        await sendKmipRequest(req, serverUrl);
                    }
                }

                return t("symKeysCreate.success", { keyId });
            }
        });
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">{t("symKeysCreate.title")}</h1>

            <div className="mb-8 space-y-2">
                <p>{t("symKeysCreate.intro")}</p>
                <ul className="list-disc pl-5 space-y-1">
                    <li>{t("symKeysCreate.introBytes")}</li>
                    <li>{t("symKeysCreate.introRandom")}</li>
                    <li>{t("symKeysCreate.introDefault")}</li>
                </ul>
            </div>

            <Form
                form={form}
                onFinish={onFinish}
                layout="vertical"
                initialValues={{
                    algorithm: "Aes",
                    numberOfBits: 256,
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
                            rules={[{ required: true, message: t("symKeysCreate.pleaseSelectAlgorithm") }]}
                        >
                            <Select options={algoOptions} />
                        </Form.Item>

                        <Form.Item name="numberOfBits" label={t("symKeysCreate.numberOfBits")} help={t("symKeysCreate.numberOfBitsHelp")}>
                            <InputNumber className="w-[200px]" min={128} step={128} max={512} />
                        </Form.Item>

                        <Form.Item name="bytesB64" label={t("symKeysCreate.keyBytes")} help={t("symKeysCreate.keyBytesHelp")}>
                            <Input.TextArea placeholder={t("symKeysCreate.enterKeyBytes")} rows={4} />
                        </Form.Item>

                        <Form.Item name="keyId" label={t("common:keyId")} help={t("symKeysCreate.keyIdHelp")}>
                            <Input placeholder={t("common:enterKeyId")} />
                        </Form.Item>

                        <Form.Item name="tags" label={t("common:tags")} help={t("symKeysCreate.tagsHelp")}>
                            <Select mode="tags" placeholder={t("common:enterTags")} open={false} />
                        </Form.Item>

                        <Form.Item
                            name="wrappingKeyId"
                            label={t("symKeysCreate.wrappingKeyId")}
                            help={t("symKeysCreate.wrappingKeyIdHelp")}
                        >
                            <Input placeholder={t("symKeysCreate.enterWrappingKeyId")} />
                        </Form.Item>

                        <Form.Item name="sensitive" valuePropName="checked" help={t("symKeysCreate.sensitiveHelp")}>
                            <Checkbox>{t("symKeysCreate.sensitive")}</Checkbox>
                        </Form.Item>

                        <Divider orientation="left" plain>
                            {t("symKeysCreate.rotationPolicy")}
                        </Divider>

                        <Form.Item name="enrollKeyset" valuePropName="checked" help={t("symKeysCreate.enrollKeysetHelp")}>
                            <Checkbox data-testid="sym-enroll-keyset">{t("symKeysCreate.enrollKeyset")}</Checkbox>
                        </Form.Item>

                        <Form.Item noStyle shouldUpdate={(prev, curr) => prev.enrollKeyset !== curr.enrollKeyset}>
                            {({ getFieldValue }) =>
                                getFieldValue("enrollKeyset") ? (
                                    <>
                                        <Form.Item
                                            name="rotateInterval"
                                            label={t("symKeysCreate.rotateInterval")}
                                            help={t("symKeysCreate.rotateIntervalHelp")}
                                        >
                                            <InputNumber
                                                className="w-[200px]"
                                                min={0}
                                                placeholder={t("symKeysCreate.rotateIntervalPlaceholder")}
                                                data-testid="sym-rotation-interval"
                                            />
                                        </Form.Item>

                                        <Form.Item
                                            name="rotateOffset"
                                            label={t("symKeysCreate.rotateOffset")}
                                            help={t("symKeysCreate.rotateOffsetHelp")}
                                        >
                                            <InputNumber
                                                className="w-[200px]"
                                                min={0}
                                                placeholder={t("symKeysCreate.rotateOffsetPlaceholder")}
                                                data-testid="sym-rotation-offset"
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
                            {t("symKeysCreate.submit")}
                        </Button>
                    </Form.Item>
                </Space>
                <ActionResponse res={res} responseRef={responseRef} title={t("symKeysCreate.responseTitle")} />
            </Form>
        </div>
    );
};

export default SymKeyCreateForm;
