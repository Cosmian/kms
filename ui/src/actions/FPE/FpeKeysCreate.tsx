import { Button, Card, Checkbox, Form, Input, Select, Space } from "antd";
import React, { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { useAuth } from "../../contexts/useAuth";
import { sendKmipRequest } from "../../utils/utils";
import * as wasm from "../../wasm/pkg";

interface FpeKeyCreateFormData {
    keyId?: string;
    tags: string[];
    sensitive: boolean;
}

type CreateResponse = {
    ObjectType: string;
    UniqueIdentifier: string;
};

const FpeKeyCreateForm: React.FC = () => {
    const [form] = Form.useForm<FpeKeyCreateFormData>();
    const [res, setRes] = useState<undefined | string>(undefined);
    const [isLoading, setIsLoading] = useState(false);
    const { serverUrl } = useAuth();
    const { t } = useTranslation("actions");
    const responseRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        if (res && responseRef.current) {
            responseRef.current.scrollIntoView({ behavior: "smooth" });
        }
    }, [res]);

    const onFinish = async (values: FpeKeyCreateFormData) => {
        setIsLoading(true);
        setRes(undefined);
        try {
            const w = wasm as unknown as {
                create_fpe_key_ttlv_request?: (keyId: string | undefined, tags: string[], sensitive: boolean) => object;
            };
            if (!w.create_fpe_key_ttlv_request) {
                setRes(`${t("common:errorPrefix")}${t("fpeKeysCreate.wasmUnavailable")}`);
                return;
            }
            const request = w.create_fpe_key_ttlv_request(values.keyId, values.tags, values.sensitive);
            const result_str = await sendKmipRequest(request, serverUrl);
            if (result_str) {
                const result: CreateResponse = await wasm.parse_create_ttlv_response(result_str);
                setRes(t("fpeKeysCreate.created", { id: result.UniqueIdentifier }));
            }
        } catch (e) {
            setRes(`${t("common:errorPrefix")}${t("fpeKeysCreate.createError", { error: e })}`);
            console.error("Error creating FPE key:", e);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">{t("fpeKeysCreate.title")}</h1>

            <div className="mb-8 space-y-2">
                <p>{t("fpeKeysCreate.intro")}</p>
                <ul className="list-disc pl-5 space-y-1">
                    <li>{t("fpeKeysCreate.bullet1")}</li>
                    <li>{t("fpeKeysCreate.bullet2")}</li>
                    <li>{t("fpeKeysCreate.bullet3")}</li>
                </ul>
            </div>

            <Form
                form={form}
                onFinish={onFinish}
                layout="vertical"
                initialValues={{
                    tags: [],
                    sensitive: false,
                }}
            >
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <Form.Item name="keyId" label={t("common:keyId")} help={t("fpeKeysCreate.keyIdHelp")}>
                            <Input placeholder={t("common:enterKeyId")} />
                        </Form.Item>

                        <Form.Item name="tags" label={t("common:tags")} help={t("fpeKeysCreate.tagsHelp")}>
                            <Select mode="tags" placeholder={t("common:enterTags")} open={false} />
                        </Form.Item>

                        <Form.Item name="sensitive" valuePropName="checked" help={t("fpeKeysCreate.sensitiveHelp")}>
                            <Checkbox>{t("fpeKeysCreate.sensitive")}</Checkbox>
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
                            {t("fpeKeysCreate.submit")}
                        </Button>
                    </Form.Item>
                </Space>
                {res && (
                    <div ref={responseRef} data-testid="response-output">
                        <Card title={t("fpeKeysCreate.responseTitle")}>{res}</Card>
                    </div>
                )}
            </Form>
        </div>
    );
};

export default FpeKeyCreateForm;
