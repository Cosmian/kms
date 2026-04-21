import { Alert } from "antd";
import { Button, Card, Form, Input, Select, Space } from "antd";
import React, { useEffect, useRef, useState } from "react";
import { useAuth } from "../../hooks/useAuth";
import { postNoTTLVRequest } from "../../utils/utils";

interface HashFormData {
    data: string;
    method: string;
    salt?: string;
}

const HASH_METHODS = [
    { label: "SHA2 (256-bit)", value: "SHA2" },
    { label: "SHA3 (256-bit)", value: "SHA3" },
    { label: "Argon2 (password hashing)", value: "Argon2" },
];

const TokenizeHashForm: React.FC = () => {
    const [form] = Form.useForm<HashFormData>();
    const [res, setRes] = useState<string | undefined>(undefined);
    const [isLoading, setIsLoading] = useState(false);
    const { idToken, serverUrl } = useAuth();
    const responseRef = useRef<HTMLDivElement>(null);

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
            const response = await postNoTTLVRequest("/tokenize/hash", body, idToken, serverUrl);
            const typed = response as { result?: string; code?: number; message?: string };
            if (typed.result !== undefined) {
                setRes(`Result: ${typed.result}`);
            } else {
                setRes(`Error: ${typed.message ?? "Unknown error"}`);
            }
        } catch (e) {
            setRes(`Error: ${e}`);
            console.error("Hash tokenize error:", e);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="rounded-lg p-6 m-4">
            <h1 className="text-2xl font-bold mb-6">Anonymize — Hash</h1>

            <div className="mb-8 space-y-2">
                <p>Hash a string using SHA2, SHA3, or Argon2. Returns the base64-encoded digest.</p>
                <p>
                    For <strong>Argon2</strong>, a base64-encoded salt is required. SHA2 and SHA3 accept an optional salt.
                </p>
            </div>

            <Form form={form} onFinish={onFinish} layout="vertical" initialValues={{ method: "SHA2" }}>
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <Form.Item
                            name="data"
                            label="Input data"
                            rules={[{ required: true, message: "Please enter the string to hash" }]}
                            help="Plain-text string to hash"
                        >
                            <Input placeholder="e.g. hello world" />
                        </Form.Item>
                    </Card>

                    <Card>
                        <Form.Item name="method" label="Hash method" rules={[{ required: true, message: "Please select a hash method" }]}>
                            <Select data-testid="hash-method-select" options={HASH_METHODS} />
                        </Form.Item>

                        <Form.Item name="salt" label="Salt (base64, optional)" help="Required for Argon2. Optional for SHA2/SHA3.">
                            <Input placeholder="e.g. c2FsdA==" />
                        </Form.Item>
                    </Card>

                    <Button type="primary" htmlType="submit" loading={isLoading} data-testid="submit-btn">
                        Hash
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

export default TokenizeHashForm;
