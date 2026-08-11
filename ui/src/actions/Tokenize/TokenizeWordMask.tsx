import { Alert, Button, Card, Form, Input, Select, Space } from "antd";
import React, { useEffect, useRef, useState } from "react";
import { Trans, useTranslation } from "react-i18next";
import { useAuth } from "../../contexts/useAuth";
import { postNoTTLVRequest } from "../../utils/utils";

interface WordListFormData {
    data: string;
    words: string[];
}

const TokenizeWordMaskForm: React.FC = () => {
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
            const response = await postNoTTLVRequest("/tokenize/word-mask", { data: values.data, words: values.words ?? [] }, serverUrl);
            const typed = response as { result?: string; code?: number; message?: string };
            if (typed.result !== undefined) {
                setRes(t("tokenizeWordMask.resultPrefix", { value: typed.result }));
            } else {
                setRes(`${t("common:errorPrefix")}${typed.message ?? t("tokenizeWordMask.unknownError")}`);
            }
        } catch (e) {
            setRes(`${t("common:errorPrefix")}${e}`);
            console.error("Word mask error:", e);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="rounded-lg p-6 m-4">
            <h1 className="text-2xl font-bold mb-6">{t("tokenizeWordMask.title")}</h1>

            <div className="mb-8 space-y-2">
                <p>
                    <Trans ns="actions" i18nKey="tokenizeWordMask.intro" components={{ code: <code /> }} />
                </p>
                <p>{t("tokenizeWordMask.introCaseInsensitive")}</p>
            </div>

            <Form form={form} onFinish={onFinish} layout="vertical">
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <Form.Item
                            name="data"
                            label={t("tokenizeWordMask.inputText")}
                            rules={[{ required: true, message: t("tokenizeWordMask.pleaseEnterText") }]}
                            help={t("tokenizeWordMask.inputTextHelp")}
                        >
                            <Input.TextArea rows={4} placeholder={t("tokenizeWordMask.inputTextPlaceholder")} />
                        </Form.Item>
                    </Card>

                    <Card>
                        <Form.Item
                            name="words"
                            label={t("tokenizeWordMask.wordsToMask")}
                            rules={[{ required: true, message: t("tokenizeWordMask.pleaseEnterWords") }]}
                            help={t("tokenizeWordMask.wordsHelp")}
                        >
                            <Select
                                mode="tags"
                                placeholder={t("tokenizeWordMask.wordsPlaceholder")}
                                open={false}
                                data-testid="tags-select"
                            />
                        </Form.Item>
                    </Card>

                    <Button type="primary" htmlType="submit" loading={isLoading} data-testid="submit-btn">
                        {t("tokenizeWordMask.submit")}
                    </Button>
                </Space>
            </Form>

            {res && (
                <div ref={responseRef} className="mt-6">
                    <Alert
                        message={res.startsWith(t("common:errorPrefix")) ? t("common:error") : t("tokenizeWordMask.success")}
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

export default TokenizeWordMaskForm;
