import { Button, Card, Form, Input, Select, Space, Tag } from "antd";
import React, { useEffect, useRef, useState } from "react";
import { useAuth } from "../../contexts/AuthContext";
import { sendKmipRequest } from "../../utils/utils";

interface MacVerifyFormData {
    keyId?: string;
    tags?: string[];
    algorithm: string;
    data: string;
    macData: string;
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

const buildMacVerifyRequest = (keyId: string, algorithm: string, dataHex: string, macDataHex: string) => ({
    tag: "MACVerify",
    type: "Structure",
    value: [
        { tag: "UniqueIdentifier", type: "TextString", value: keyId },
        {
            tag: "CryptographicParameters",
            type: "Structure",
            value: [{ tag: "HashingAlgorithm", type: "Enumeration", value: algorithm }],
        },
        { tag: "Data", type: "ByteString", value: dataHex },
        { tag: "MACData", type: "ByteString", value: macDataHex },
    ],
});

const MacVerifyForm: React.FC = () => {
    const [form] = Form.useForm<MacVerifyFormData>();
    const [res, setRes] = useState<string | undefined>(undefined);
    const [isValid, setIsValid] = useState<boolean | undefined>(undefined);
    const [isLoading, setIsLoading] = useState(false);
    const { idToken, serverUrl } = useAuth();
    const responseRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        if (res && responseRef.current) {
            responseRef.current.scrollIntoView({ behavior: "smooth" });
        }
    }, [res]);

    const onFinish = async (values: MacVerifyFormData) => {
        setIsLoading(true);
        setRes(undefined);
        setIsValid(undefined);
        const id = values.keyId ? values.keyId : values.tags ? JSON.stringify(values.tags) : undefined;
        try {
            if (id == undefined) {
                setRes("Missing key identifier.");
                throw Error("Missing key identifier");
            }
            const request = buildMacVerifyRequest(id, values.algorithm, values.data, values.macData);
            const result_str = await sendKmipRequest(request, idToken, serverUrl);
            if (result_str) {
                const response = JSON.parse(result_str) as { tag?: string; value?: Array<{ tag: string; type: string; value: unknown }> };
                const validityItem = response.value?.find((item) => item.tag === "ValidityIndicator");
                if (validityItem) {
                    const valid = validityItem.value === "Valid" || validityItem.value === true;
                    setIsValid(valid);
                    setRes(valid ? "MAC is valid." : "MAC is invalid.");
                } else {
                    setRes(`Response: ${result_str}`);
                }
            }
        } catch (e) {
            setRes(`Error verifying MAC: ${e}`);
            console.error("Error verifying MAC:", e);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="rounded-lg p-6 m-4">
            <h1 className="text-2xl font-bold mb-6">MAC Verify</h1>

            <div className="mb-8 space-y-2">
                <p>Verify a Message Authentication Code (MAC / HMAC) over data using a MAC key.</p>
                <p>Both the data and the MAC value must be provided as hexadecimal strings.</p>
            </div>

            <Form form={form} onFinish={onFinish} layout="vertical" initialValues={{ algorithm: "SHA256" }}>
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
                            <Select data-testid="mac-verify-algorithm-select" options={MAC_HASHING_ALGORITHMS} />
                        </Form.Item>
                    </Card>

                    <Card>
                        <Form.Item
                            name="data"
                            label="Data (hex)"
                            rules={[
                                { required: true, message: "Please enter data to verify" },
                                {
                                    pattern: /^[0-9a-fA-F]*$/,
                                    message: "Data must be a hexadecimal string",
                                },
                            ]}
                            help="Original data, as a hexadecimal string"
                        >
                            <Input.TextArea rows={4} placeholder="e.g. 0011223344556677889900" />
                        </Form.Item>

                        <Form.Item
                            name="macData"
                            label="MAC Value (hex)"
                            rules={[
                                { required: true, message: "Please enter the MAC value to verify" },
                                {
                                    pattern: /^[0-9a-fA-F]*$/,
                                    message: "MAC value must be a hexadecimal string",
                                },
                            ]}
                            help="Previously computed MAC value to verify against, as a hexadecimal string"
                        >
                            <Input.TextArea rows={3} placeholder="e.g. F91DDB96D12CF8FA..." />
                        </Form.Item>
                    </Card>

                    <Button type="primary" htmlType="submit" loading={isLoading} data-testid="submit-btn">
                        Verify MAC
                    </Button>
                </Space>
            </Form>

            {res && (
                <div ref={responseRef} data-testid="response-output" className="mt-6 p-4 rounded-lg bg-gray-100 dark:bg-gray-800">
                    {isValid !== undefined && (
                        <div className="mb-2">
                            <Tag color={isValid ? "success" : "error"} style={{ fontSize: "1rem", padding: "4px 12px" }}>
                                {isValid ? "✓ Valid" : "✗ Invalid"}
                            </Tag>
                        </div>
                    )}
                    <pre className="whitespace-pre-wrap text-sm break-all">{res}</pre>
                </div>
            )}
        </div>
    );
};

export default MacVerifyForm;
