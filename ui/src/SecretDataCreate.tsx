import { Button, Card, Checkbox, Form, Input, Select, Space } from "antd";
import React, { useEffect, useRef, useState } from "react";
import { useAuth } from "./AuthContext";
import { sendKmipRequest } from "./utils";
import { create_secret_data_ttlv_request, parse_create_ttlv_response, parse_import_ttlv_response } from "./wasm/pkg";

interface SecretDataCreateFormData {
    secretId?: string;
    secretValue?: string;
    secretType: "Seed" | "Password";
    tags: string[];
    sensitive: boolean;
    wrappingKeyId?: string;
}

type CreateResponse = {
    ObjectType: string;
    UniqueIdentifier: string;
};

type ImportResponse = {
    UniqueIdentifier: string;
};

const SecretDataCreateForm: React.FC = () => {
    const [form] = Form.useForm<SecretDataCreateFormData>();
    const [res, setRes] = useState<undefined | string>(undefined);
    const [isLoading, setIsLoading] = useState(false);
    const { idToken, serverUrl } = useAuth();
    const responseRef = useRef<HTMLDivElement>(null);
    const secretValue = Form.useWatch("secretValue", form);

    useEffect(() => {
        if (res && responseRef.current) {
            responseRef.current.scrollIntoView({ behavior: "smooth" });
        }
    }, [res]);

    useEffect(() => {
        const isInvalid = !secretValue || secretValue.length < 5;

        if (isInvalid) {
            form.setFieldsValue({ secretType: "Seed" });
        }
    }, [secretValue, form]);

    const isSecretTypeDisabled = !secretValue || secretValue.length < 5;

    const onFinish = async (values: SecretDataCreateFormData) => {
        setIsLoading(true);
        setRes(undefined);
        try {
            const request = create_secret_data_ttlv_request(
                values.secretType,
                values.secretValue,
                values.secretId,
                values.tags,
                values.sensitive,
                values.wrappingKeyId
            );
            const result_str = await sendKmipRequest(request, idToken, serverUrl);
            if (result_str) {
                if (values.secretValue) {
                    const result: ImportResponse = await parse_import_ttlv_response(result_str);
                    setRes(`${result.UniqueIdentifier} has been created.`);
                } else {
                    const result: CreateResponse = await parse_create_ttlv_response(result_str);
                    setRes(`${result.UniqueIdentifier} has been created.`);
                }
            }
        } catch (e) {
            setRes(`Error creating secret data: ${e}`);
            console.error("Error creating secret data:", e);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">Create a new secret data</h1>

            <div className="mb-8 space-y-2">
                <p>Create a new secret data:</p>
                <ul className="list-disc pl-5 space-y-1">
                    <li>When the secret value is specified, the secret will be created from the provided value.</li>
                    <li>Otherwise, a fresh 256-bit random seed will be created.</li>
                    <li>Tags can later be used to retrieve the secret. Tags are optional.</li>
                </ul>
            </div>

            <Form
                form={form}
                onFinish={onFinish}
                layout="vertical"
                initialValues={{
                    secretType: "Seed",
                    tags: [],
                    sensitive: false,
                }}
            >
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <Form.Item
                            name="secretValue"
                            label="Secret Value"
                            help="If provided, the secret data string must be at least 5 characters long and will be UTF-8 encoded"
                            rules={[
                                {
                                    validator: (_, value) => {
                                        if (!value || value.length >= 5) {
                                            return Promise.resolve();
                                        }
                                        return Promise.reject(new Error("Secret value must be at least 5 characters long or empty"));
                                    },
                                },
                            ]}
                        >
                            <Input.TextArea placeholder="Enter secret value" rows={2} />
                        </Form.Item>

                        <Form.Item
                            name="secretType"
                            label="Secret Data Type"
                            rules={[{ required: true, message: "Please select a secret type" }]}
                        >
                            <Select disabled={isSecretTypeDisabled}>
                                <Select.Option value="Seed">Seed</Select.Option>
                                <Select.Option value="Password">Password</Select.Option>
                            </Select>
                        </Form.Item>

                        <Form.Item name="secretId" label="Secret Data ID" help="Optional: a random UUID will be generated if not specified">
                            <Input placeholder="Enter secret ID" />
                        </Form.Item>

                        <Form.Item name="tags" label="Tags" help="Optional: Add tags to help retrieve the secret later">
                            <Select mode="tags" placeholder="Enter tags" open={false} />
                        </Form.Item>

                        <Form.Item
                            name="wrappingKeyId"
                            label="Wrapping Key ID"
                            help="Optional: ID of the key to wrap this new secret data with"
                        >
                            <Input placeholder="Enter wrapping key ID" />
                        </Form.Item>

                        <Form.Item name="sensitive" valuePropName="checked" help="If set, the secret will not be exportable">
                            <Checkbox>Sensitive</Checkbox>
                        </Form.Item>
                    </Card>

                    <Form.Item>
                        <Button type="primary" htmlType="submit" loading={isLoading} className="w-full text-white font-medium">
                            Create Secret Data
                        </Button>
                    </Form.Item>
                </Space>
                {res && (
                    <div ref={responseRef}>
                        <Card title="Secret data creation response">{res}</Card>
                    </div>
                )}
            </Form>
        </div>
    );
};

export default SecretDataCreateForm;
