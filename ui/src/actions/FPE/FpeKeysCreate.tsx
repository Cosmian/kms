import { Button, Card, Checkbox, Form, Input, Select, Space } from "antd";
import React, { useEffect, useRef, useState } from "react";
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
    const { idToken, serverUrl } = useAuth();
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
                setRes("Error: WASM FPE functions not available. Rebuild WASM with non-fips feature.");
                return;
            }
            const request = w.create_fpe_key_ttlv_request(values.keyId, values.tags, values.sensitive);
            const result_str = await sendKmipRequest(request, idToken, serverUrl);
            if (result_str) {
                const result: CreateResponse = await wasm.parse_create_ttlv_response(result_str);
                setRes(`${result.UniqueIdentifier} has been created.`);
            }
        } catch (e) {
            setRes(`Error creating FPE key: ${e}`);
            console.error("Error creating FPE key:", e);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">Create an FPE key</h1>

            <div className="mb-8 space-y-2">
                <p>Create a new 256-bit AES key for Format-Preserving Encryption (FPE-FF1).</p>
                <ul className="list-disc pl-5 space-y-1">
                    <li>FPE keys are always 256-bit AES keys using the FF1 algorithm.</li>
                    <li>The key is automatically tagged with &quot;fpe-ff1&quot;.</li>
                    <li>Tags can later be used to retrieve the key.</li>
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
                        <Form.Item name="keyId" label="Key ID" help="Optional: a random UUID will be generated if not specified">
                            <Input placeholder="Enter key ID" />
                        </Form.Item>

                        <Form.Item name="tags" label="Tags" help="Optional: Add tags to help retrieve the key later">
                            <Select mode="tags" placeholder="Enter tags" open={false} />
                        </Form.Item>

                        <Form.Item name="sensitive" valuePropName="checked" help="If set, the key will not be exportable">
                            <Checkbox>Sensitive</Checkbox>
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
                            Create FPE Key
                        </Button>
                    </Form.Item>
                </Space>
                {res && (
                    <div ref={responseRef} data-testid="response-output">
                        <Card title="FPE key creation response">{res}</Card>
                    </div>
                )}
            </Form>
        </div>
    );
};

export default FpeKeyCreateForm;
