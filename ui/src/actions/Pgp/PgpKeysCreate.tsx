import { Button, Card, Checkbox, Form, Input, InputNumber, Select, Space } from "antd";
import React, { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { sendKmipRequest } from "../../utils/utils";
import * as wasm from "../../wasm/pkg";
import { useActionState } from "../../hooks/useActionState";
import { ActionResponse } from "../../components/common/ActionResponse";

interface PgpKeyCreateFormData {
    keyId?: string;
    algorithm: string;
    keySize?: number;
    userId?: string;
    tags: string[];
    sensitive: boolean;
    wrappingKeyId?: string;
}

type CreateResponse = {
    ObjectType: string;
    UniqueIdentifier: string;
};

const PgpKeyCreateForm: React.FC = () => {
    const [form] = Form.useForm<PgpKeyCreateFormData>();
    const { res, isLoading, responseRef, serverUrl, execute } = useActionState();
    const [algoOptions, setAlgoOptions] = useState<{ value: string; label: string }[]>([]);
    const { t } = useTranslation("actions");

    useEffect(() => {
        try {
            const w = wasm as unknown as { get_pgp_algorithms?: () => { value: string; label: string }[] };
            const opts = w.get_pgp_algorithms ? w.get_pgp_algorithms() : [];
            setAlgoOptions(opts);
        } catch (e) {
            console.error("Error loading OpenPGP algorithms from WASM:", e);
        }
    }, []);

    const onFinish = async (values: PgpKeyCreateFormData) => {
        await execute(async () => {
            const request = wasm.create_pgp_key_ttlv_request(
                values.keyId,
                values.tags,
                values.algorithm,
                values.algorithm === "RSA" ? values.keySize : undefined,
                values.userId,
                values.sensitive,
                values.wrappingKeyId,
            );
            const result_str = await sendKmipRequest(request, serverUrl);
            if (result_str) {
                const result: CreateResponse = await wasm.parse_create_ttlv_response(result_str);
                const keyId = result.UniqueIdentifier;
                return t("pgpKeysCreate.success", { keyId });
            }
        });
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">{t("pgpKeysCreate.title")}</h1>

            <div className="mb-8 space-y-2">
                <p>{t("pgpKeysCreate.intro")}</p>
            </div>

            <Form
                form={form}
                onFinish={onFinish}
                layout="vertical"
                initialValues={{
                    algorithm: "Ed25519",
                    keySize: 3072,
                    sensitive: false,
                    tags: [],
                }}
            >
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <Form.Item
                            name="algorithm"
                            label={t("pgpKeysCreate.algorithm")}
                            rules={[{ required: true, message: t("pgpKeysCreate.algorithmRequired") }]}
                            help={t("pgpKeysCreate.algorithmHelp")}
                        >
                            <Select options={algoOptions} />
                        </Form.Item>

                        <Form.Item noStyle shouldUpdate={(prev, curr) => prev.algorithm !== curr.algorithm}>
                            {({ getFieldValue }) =>
                                getFieldValue("algorithm") === "RSA" ? (
                                    <Form.Item
                                        name="keySize"
                                        label={t("pgpKeysCreate.keySize")}
                                        rules={[{ required: true, message: t("pgpKeysCreate.keySizeRequired") }]}
                                        help={t("pgpKeysCreate.keySizeHelp")}
                                    >
                                        <InputNumber min={2048} max={4096} step={1024} style={{ width: "100%" }} />
                                    </Form.Item>
                                ) : null
                            }
                        </Form.Item>

                        <Form.Item name="userId" label={t("pgpKeysCreate.userId")} help={t("pgpKeysCreate.userIdHelp")}>
                            <Input placeholder="Alice <alice@example.com>" />
                        </Form.Item>

                        <Form.Item name="keyId" label={t("pgpKeysCreate.keyId")} help={t("pgpKeysCreate.keyIdHelp")}>
                            <Input placeholder={t("pgpKeysCreate.keyIdPlaceholder")} />
                        </Form.Item>

                        <Form.Item name="tags" label={t("pgpKeysCreate.tags")} help={t("pgpKeysCreate.tagsHelp")}>
                            <Select mode="tags" style={{ width: "100%" }} placeholder={t("pgpKeysCreate.tagsPlaceholder")} />
                        </Form.Item>

                        <Form.Item name="sensitive" valuePropName="checked" help={t("pgpKeysCreate.sensitiveHelp")}>
                            <Checkbox>{t("pgpKeysCreate.sensitive")}</Checkbox>
                        </Form.Item>

                        <Form.Item
                            name="wrappingKeyId"
                            label={t("pgpKeysCreate.wrappingKeyId")}
                            help={t("pgpKeysCreate.wrappingKeyIdHelp")}
                        >
                            <Input placeholder={t("pgpKeysCreate.wrappingKeyIdPlaceholder")} />
                        </Form.Item>
                    </Card>

                    <Form.Item>
                        <Button type="primary" htmlType="submit" loading={isLoading} data-testid="submit-btn">
                            {t("pgpKeysCreate.submit")}
                        </Button>
                    </Form.Item>
                </Space>
            </Form>

            <ActionResponse res={res} responseRef={responseRef} title={t("pgpKeysCreate.responseTitle")} />
        </div>
    );
};

export default PgpKeyCreateForm;
