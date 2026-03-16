import { Button, Card, Form, Input, Select, Space } from "antd";
import React, { useEffect, useRef, useState } from "react";
import { useAuth } from "./AuthContext";
import { sendKmipRequest } from "./utils";

interface MacComputeFormData {
    keyId?: string;
    tags?: string[];
    algorithm: string;
    data: string;
}

const MAC_HASHING_ALGORITHMS = [
    { label: "SHA-1", value: "SHA1" },
    { label: "SHA-224", value: "SHA224" },
    { label: "SHA-256", value: "SHA256" },
    { label: "SHA-384", value: "SHA384" },
    { label: "SHA-512", value: "SHA512" },
    { label: "SHA3-224", value: "SHA3224" },
    { label: "SHA3-256", value: "SHA3256" },
    { label: "SHA3-384", value: "SHA3384" },
    { label: "SHA3-512", value: "SHA3512" },
];

const buildMacRequest = (keyId: string, algorithm: string, dataHex: string) => ({
    tag: "Mac",
    type: "Structure",
    value: [
        { tag: "UniqueIdentifier", type: "TextString", value: keyId },
        {
            tag: "CryptographicParameters",
            type: "Structure",
            value: [{ tag: "HashingAlgorithm", type: "Enumeration", value: algorithm }],
        },
        { tag: "Data", type: "ByteString", value: dataHex },
    ],
});

const MacComputeForm: React.FC = () => {
    const [form] = Form.useForm<MacComputeFormData>();
    const [res, setRes] = useState<string | undefined>(undefined);
    const [isLoading, setIsLoading] = useState(false);
    const { idToken, serverUrl } = useAuth();
    const responseRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        if (res && responseRef.current) {
            responseRef.current.scrollIntoView({ behavior: "smooth" });
        }
    }, [res]);

    const onFinish = async (values: MacComputeFormData) => {
        setIsLoading(true);
        setRes(undefined);
        const id = values.keyId ? values.keyId : values.tags ? JSON.stringify(values.tags) : undefined;
        try {
            if (id == undefined) {
                setRes("Missing key identifier.");
                throw Error("Missing key identifier");
            }
            const request = buildMacRequest(id, values.algorithm, values.data);
            const result_str = await sendKmipRequest(request, idToken, serverUrl);
            if (result_str) {
                const response = JSON.parse(result_str) as { tag?: string; value?: Array<{ tag: string; type: string; value: string }> };
                const dataItem = response.value?.find((item) => item.tag === "MACData");
                if (dataItem) {
                    setRes(`MAC (hex): ${dataItem.value}`);
                } else {
                    setRes(`Response: ${result_str}`);
                }
            }
        } catch (e) {
            setRes(`Error computing MAC: ${e}`);
            console.error("Error computing MAC:", e);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="rounded-lg p-6 m-4">
            <h1 className="text-2xl font-bold mb-6">MAC Compute</h1>

            <div className="mb-8 space-y-2">
                <p>Compute a Message Authentication Code (MAC / HMAC) over data using a MAC key.</p>
                <p>The data must be provided as a hexadecimal string (e.g. <code>0011223344556677</code>).</p>
            </div>

            <Form
                form={form}
                onFinish={onFinish}
                layout="vertical"
                initialValues={{ algorithm: "SHA256" }}
            >
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <h3 className="text-m font-bold mb-4">Key Identification (required)</h3>
                        <Form.Item name="keyId" label="Key ID" help="The unique identifier of the MAC key">
                            <Input placeholder="Enter key ID" />
                        </Form.Item>
                        <Form.Item name="tags" label="Tags" help="Alternative to Key ID: specify tags to identify the key">
                            <Select mode="tags" placeholder="Enter tags" open={false} />
                        </Form.Item>
                    </Card>

                    <Card>
                        <Form.Item
                            name="algorithm"
                            label="Hashing Algorithm"
                            rules={[{ required: true, message: "Please select a hashing algorithm" }]}
                            help="Hash function used for the HMAC computation"
                        >
                            <Select data-testid="mac-algorithm-select" options={MAC_HASHING_ALGORITHMS} />
                        </Form.Item>
                    </Card>

                    <Card>
                        <Form.Item
                            name="data"
                            label="Data (hex)"
                            rules={[
                                { required: true, message: "Please enter data to authenticate" },
                                {
                                    pattern: /^[0-9a-fA-F]*$/,
                                    message: "Data must be a hexadecimal string",
                                },
                            ]}
                            help="Data to authenticate, as a hexadecimal string"
                        >
                            <Input.TextArea rows={4} placeholder="e.g. 0011223344556677889900" />
                        </Form.Item>
                    </Card>

                    <Button type="primary" htmlType="submit" loading={isLoading} data-testid="submit-btn">
                        Compute MAC
                    </Button>
                </Space>
            </Form>

            {res && (
                <div ref={responseRef} data-testid="response-output" className="mt-6 p-4 rounded-lg bg-gray-100 dark:bg-gray-800 break-all">
                    <pre className="whitespace-pre-wrap text-sm">{res}</pre>
                </div>
            )}
        </div>
    );
};

export default MacComputeForm;
