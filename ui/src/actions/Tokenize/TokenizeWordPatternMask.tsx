import { Alert, Button, Card, Form, Input, Space } from "antd";
import React, { useEffect, useRef, useState } from "react";
import { useAuth } from "../../contexts/AuthContext";
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
    const { idToken, serverUrl } = useAuth();
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
            console.error("Word pattern mask error:", e);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="rounded-lg p-6 m-4">
            <h1 className="text-2xl font-bold mb-6">Anonymize — Pattern Mask</h1>

            <div className="mb-8 space-y-2">
                <p>Replace all substrings matching a regular expression with a replacement string.</p>
                <p>Uses Rust regex syntax. The pattern is limited to 1 024 characters to prevent ReDoS attacks.</p>
            </div>

            <Form form={form} onFinish={onFinish} layout="vertical">
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <Form.Item
                            name="data"
                            label="Input text"
                            rules={[{ required: true, message: "Please enter the text to process" }]}
                            help="Text in which to apply the pattern substitution"
                        >
                            <Input.TextArea rows={4} placeholder="e.g. Call +33 6 12 34 56 78 or +1 800 555 0199" />
                        </Form.Item>
                    </Card>

                    <Card>
                        <Form.Item
                            name="pattern"
                            label="Regex pattern"
                            rules={[{ required: true, message: "Please enter a regex pattern" }]}
                            help="Regular expression to match (max 1 024 chars)"
                        >
                            <Input placeholder={String.raw`e.g. \+\d[\d\s]{7,14}\d`} />
                        </Form.Item>

                        <Form.Item
                            name="replace"
                            label="Replacement string"
                            rules={[{ required: true, message: "Please enter a replacement string" }]}
                            help="String to substitute for each match"
                        >
                            <Input placeholder="e.g. [PHONE]" />
                        </Form.Item>
                    </Card>

                    <Button type="primary" htmlType="submit" loading={isLoading} data-testid="submit-btn">
                        Apply Pattern Mask
                    </Button>
                </Space>
            </Form>

            {res && (
                <div ref={responseRef} className="mt-6">
                    <Alert
                        message={res.startsWith("Error") ? "Error" : "Success"}
                        description={<div data-testid="response-output" className="break-all font-mono text-sm whitespace-pre-wrap">{res}</div>}
                        type={res.startsWith("Error") ? "error" : "success"}
                        showIcon
                    />
                </div>
            )}
        </div>
    );
};

export default TokenizeWordPatternMaskForm;
