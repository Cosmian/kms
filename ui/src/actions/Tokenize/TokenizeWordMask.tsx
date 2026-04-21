import { Alert, Button, Card, Form, Input, Select, Space } from "antd";
import React, { useEffect, useRef, useState } from "react";
import { useAuth } from "../../hooks/useAuth";
import { postNoTTLVRequest } from "../../utils/utils";

interface WordListFormData {
    data: string;
    words: string[];
}

const TokenizeWordMaskForm: React.FC = () => {
    const [form] = Form.useForm<WordListFormData>();
    const [res, setRes] = useState<string | undefined>(undefined);
    const [isLoading, setIsLoading] = useState(false);
    const { idToken, serverUrl } = useAuth();
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
                "/tokenize/word-mask",
                { data: values.data, words: values.words ?? [] },
                idToken,
                serverUrl,
            );
            const typed = response as { result?: string; code?: number; message?: string };
            if (typed.result !== undefined) {
                setRes(`Result: ${typed.result}`);
            } else {
                setRes(`Error: ${typed.message ?? "Unknown error"}`);
            }
        } catch (e) {
            setRes(`Error: ${e}`);
            console.error("Word mask error:", e);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="rounded-lg p-6 m-4">
            <h1 className="text-2xl font-bold mb-6">Anonymize — Word Mask</h1>

            <div className="mb-8 space-y-2">
                <p>
                    Replace occurrences of sensitive words in a text with <code>XXXX</code>.
                </p>
                <p>Word matching is case-insensitive.</p>
            </div>

            <Form form={form} onFinish={onFinish} layout="vertical">
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <Form.Item
                            name="data"
                            label="Input text"
                            rules={[{ required: true, message: "Please enter the text to mask" }]}
                            help="Text containing sensitive words to replace"
                        >
                            <Input.TextArea rows={4} placeholder="e.g. Confidential: contains secret documents" />
                        </Form.Item>
                    </Card>

                    <Card>
                        <Form.Item
                            name="words"
                            label="Words to mask"
                            rules={[{ required: true, message: "Please enter at least one word to mask" }]}
                            help="Type a word and press Enter to add it to the list"
                        >
                            <Select mode="tags" placeholder="e.g. confidential, secret" open={false} />
                        </Form.Item>
                    </Card>

                    <Button type="primary" htmlType="submit" loading={isLoading} data-testid="submit-btn">
                        Mask Words
                    </Button>
                </Space>
            </Form>

            {res && (
                <div ref={responseRef} className="mt-6">
                    <Alert
                        message={res.startsWith("Error") ? "Error" : "Success"}
                        description={
                            <div data-testid="response-output" className="break-all font-mono text-sm whitespace-pre-wrap">
                                {res}
                            </div>
                        }
                        type={res.startsWith("Error") ? "error" : "success"}
                        showIcon
                    />
                </div>
            )}
        </div>
    );
};

export default TokenizeWordMaskForm;
