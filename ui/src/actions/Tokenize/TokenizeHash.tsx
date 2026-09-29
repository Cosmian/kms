import { Alert } from "antd";
import { Button, Card, Form, Input, Select, Space } from "antd";
import React, { useEffect, useRef, useState } from "react";
import { Trans, useTranslation } from "react-i18next";
import { useAuth } from "../../contexts/useAuth";
import { postNoTTLVRequest } from "../../utils/utils";

interface HashFormData {
    data: string;
    method: string;
    salt?: string;
}

const TokenizeHashForm: React.FC = () => {
    const [form] = Form.useForm<HashFormData>();
    const [res, setRes] = useState<string | undefined>(undefined);
    const [isLoading, setIsLoading] = useState(false);
    const { serverUrl } = useAuth();
    const { t } = useTranslation("actions");
    const responseRef = useRef<HTMLDivElement>(null);
    const HASH_METHODS = [
        { label: t("tokenizeHash.hashMethodSha2"), value: "SHA2" },
        { label: t("tokenizeHash.hashMethodSha3"), value: "SHA3" },
        { label: t("tokenizeHash.hashMethodArgon2"), value: "Argon2" },
    ];

    useEffect(() => {
        if (res && responseRef.current) {
            responseRef.current.scrollIntoView({ behavior: "smooth" });
        }
    }, [res]);

    const onFinish = async (values: HashFormData) => {
        setIsLoading(true);
        setRes(undefined);
        try {
            const body: Record<string, string> = {
                data: values.data,
                method: values.method,
            };
            if (values.salt) {
                body.salt = values.salt;
            }
            const response = await postNoTTLVRequest("/tokenize/hash", body, serverUrl);
            const typed = response as { result?: string; code?: number; message?: string };
            if (typed.result !== undefined) {
                setRes(t("tokenizeHash.resultPrefix", { value: typed.result }));
            } else {
                setRes(`${t("common:errorPrefix")}${typed.message ?? t("tokenizeHash.unknownError")}`);
            }
        } catch (e) {
            setRes(`${t("common:errorPrefix")}${e}`);
            console.error("Hash tokenize error:", e);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="rounded-lg p-6 m-4">
            <h1 className="text-2xl font-bold mb-6">{t("tokenizeHash.title")}</h1>

            <div className="mb-8 space-y-2">
                <p>{t("tokenizeHash.intro")}</p>
                <p>
                    <Trans ns="actions" i18nKey="tokenizeHash.introArgon2" components={{ strong: <strong /> }} />
                </p>
            </div>

            <Form form={form} onFinish={onFinish} layout="vertical" initialValues={{ method: "SHA2" }}>
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <Form.Item
                            name="data"
                            label={t("tokenizeHash.inputData")}
                            rules={[{ required: true, message: t("tokenizeHash.pleaseEnterData") }]}
                            help={t("tokenizeHash.inputDataHelp")}
                        >
                            <Input placeholder={t("tokenizeHash.inputDataPlaceholder")} />
                        </Form.Item>
                    </Card>

                    <Card>
                        <Form.Item
                            name="method"
                            label={t("tokenizeHash.hashMethod")}
                            rules={[{ required: true, message: t("tokenizeHash.pleaseSelectHashMethod") }]}
                        >
                            <Select data-testid="hash-method-select" options={HASH_METHODS} />
                        </Form.Item>

                        <Form.Item name="salt" label={t("tokenizeHash.salt")} help={t("tokenizeHash.saltHelp")}>
                            <Input placeholder={t("tokenizeHash.saltPlaceholder")} />
                        </Form.Item>
                    </Card>

                    <Button type="primary" htmlType="submit" loading={isLoading} data-testid="submit-btn">
                        {t("tokenizeHash.submit")}
                    </Button>
                </Space>
            </Form>

            {res && (
                <div ref={responseRef} className="mt-6">
                    <Alert
                        message={res.startsWith(t("common:errorPrefix")) ? t("common:error") : t("tokenizeHash.success")}
                        description={
                            <div data-testid="response-output" className="break-all font-mono text-sm whitespace-pre-wrap">
                                {res}
                            </div>
                        }
                        type={res.startsWith(t("common:errorPrefix")) ? "error" : "success"}
                        showIcon
                    />
                </div>
            )}
        </div>
    );
};

export default TokenizeHashForm;
