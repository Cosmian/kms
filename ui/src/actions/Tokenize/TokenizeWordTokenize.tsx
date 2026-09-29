import { Alert, Button, Card, Form, Input, Select, Space } from "antd";
import React, { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { useAuth } from "../../contexts/useAuth";
import { postNoTTLVRequest } from "../../utils/utils";

interface WordListFormData {
    data: string;
    words: string[];
}

const TokenizeWordTokenizeForm: React.FC = () => {
    const [form] = Form.useForm<WordListFormData>();
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

    const onFinish = async (values: WordListFormData) => {
        setIsLoading(true);
        setRes(undefined);
        try {
            const response = await postNoTTLVRequest(
                "/tokenize/word-tokenize",
                { data: values.data, words: values.words ?? [] },
                serverUrl,
            );
            const typed = response as { result?: string; code?: number; message?: string };
            if (typed.result !== undefined) {
                setRes(t("tokenizeWordTokenize.resultPrefix", { value: typed.result }));
            } else {
                setRes(`${t("common:errorPrefix")}${typed.message ?? t("tokenizeWordTokenize.unknownError")}`);
            }
        } catch (e) {
            setRes(`${t("common:errorPrefix")}${e}`);
            console.error("Word tokenize error:", e);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="rounded-lg p-6 m-4">
            <h1 className="text-2xl font-bold mb-6">{t("tokenizeWordTokenize.title")}</h1>

            <div className="mb-8 space-y-2">
                <p>{t("tokenizeWordTokenize.intro")}</p>
                <p>{t("tokenizeWordTokenize.introConsistency")}</p>
            </div>

            <Form form={form} onFinish={onFinish} layout="vertical">
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <Form.Item
                            name="data"
                            label={t("tokenizeWordTokenize.inputText")}
                            rules={[{ required: true, message: t("tokenizeWordTokenize.pleaseEnterText") }]}
                            help={t("tokenizeWordTokenize.inputTextHelp")}
                        >
                            <Input.TextArea rows={4} placeholder={t("tokenizeWordTokenize.inputTextPlaceholder")} />
                        </Form.Item>
                    </Card>

                    <Card>
                        <Form.Item
                            name="words"
                            label={t("tokenizeWordTokenize.wordsToTokenize")}
                            rules={[{ required: true, message: t("tokenizeWordTokenize.pleaseEnterWords") }]}
                            help={t("tokenizeWordTokenize.wordsHelp")}
                        >
                            <Select
                                mode="tags"
                                placeholder={t("tokenizeWordTokenize.wordsPlaceholder")}
                                open={false}
                                data-testid="tags-select"
                            />
                        </Form.Item>
                    </Card>

                    <Button type="primary" htmlType="submit" loading={isLoading} data-testid="submit-btn">
                        {t("tokenizeWordTokenize.submit")}
                    </Button>
                </Space>
            </Form>

            {res && (
                <div ref={responseRef} className="mt-6">
                    <Alert
                        message={res.startsWith(t("common:errorPrefix")) ? t("common:error") : t("tokenizeWordTokenize.success")}
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

export default TokenizeWordTokenizeForm;
