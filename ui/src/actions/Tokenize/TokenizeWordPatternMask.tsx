import { Alert, Button, Card, Form, Input, Space } from "antd";
import React, { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { useAuth } from "../../contexts/useAuth";
import { postNoTTLVRequest } from "../../utils/utils";

interface WordPatternFormData {
    data: string;
    pattern: string;
    replace: string;
}

const TokenizeWordPatternMaskForm: React.FC = () => {
    const [form] = Form.useForm<WordPatternFormData>();
    const [res, setRes] = useState<string | undefined>(undefined);
    const [isLoading, setIsLoading] = useState(false);
    const { serverUrl } = useAuth();
    const { t } = useTranslation("actions");
    const responseRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        if (res && responseRef.current) {
            responseRef.current.scrollIntoView({ behavior: "smooth" });
        }
    }, [res]);

    const onFinish = async (values: WordPatternFormData) => {
        setIsLoading(true);
        setRes(undefined);
        try {
            const response = await postNoTTLVRequest(
                "/tokenize/word-pattern-mask",
                { data: values.data, pattern: values.pattern, replace: values.replace },
                serverUrl,
            );
            const typed = response as { result?: string; code?: number; message?: string };
            if (typed.result !== undefined) {
                setRes(t("tokenizeWordPatternMask.resultPrefix", { value: typed.result }));
            } else {
                setRes(`${t("common:errorPrefix")}${typed.message ?? t("tokenizeWordPatternMask.unknownError")}`);
            }
        } catch (e) {
            setRes(`${t("common:errorPrefix")}${e}`);
            console.error("Word pattern mask error:", e);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="rounded-lg p-6 m-4">
            <h1 className="text-2xl font-bold mb-6">{t("tokenizeWordPatternMask.title")}</h1>

            <div className="mb-8 space-y-2">
                <p>{t("tokenizeWordPatternMask.intro")}</p>
                <p>{t("tokenizeWordPatternMask.introRegex")}</p>
            </div>

            <Form form={form} onFinish={onFinish} layout="vertical">
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <Form.Item
                            name="data"
                            label={t("tokenizeWordPatternMask.inputText")}
                            rules={[{ required: true, message: t("tokenizeWordPatternMask.pleaseEnterText") }]}
                            help={t("tokenizeWordPatternMask.inputTextHelp")}
                        >
                            <Input.TextArea rows={4} placeholder={t("tokenizeWordPatternMask.inputTextPlaceholder")} />
                        </Form.Item>
                    </Card>

                    <Card>
                        <Form.Item
                            name="pattern"
                            label={t("tokenizeWordPatternMask.pattern")}
                            rules={[{ required: true, message: t("tokenizeWordPatternMask.pleaseEnterPattern") }]}
                            help={t("tokenizeWordPatternMask.patternHelp")}
                        >
                            <Input data-testid="pattern-input" placeholder={t("tokenizeWordPatternMask.patternPlaceholder")} />
                        </Form.Item>

                        <Form.Item
                            name="replace"
                            label={t("tokenizeWordPatternMask.replacement")}
                            rules={[{ required: true, message: t("tokenizeWordPatternMask.pleaseEnterReplacement") }]}
                            help={t("tokenizeWordPatternMask.replacementHelp")}
                        >
                            <Input placeholder={t("tokenizeWordPatternMask.replacementPlaceholder")} />
                        </Form.Item>
                    </Card>

                    <Button type="primary" htmlType="submit" loading={isLoading} data-testid="submit-btn">
                        {t("tokenizeWordPatternMask.submit")}
                    </Button>
                </Space>
            </Form>

            {res && (
                <div ref={responseRef} className="mt-6">
                    <Alert
                        message={res.startsWith(t("common:errorPrefix")) ? t("common:error") : t("tokenizeWordPatternMask.success")}
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

export default TokenizeWordPatternMaskForm;
