import { Alert, Button, Card, Form, Input, InputNumber, Select, Space } from "antd";
import React, { useEffect, useRef, useState } from "react";
import { useAuth } from "../../contexts/AuthContext";
import { postNoTTLVRequest } from "../../utils/utils";

interface NoiseFormData {
    data: string;
    data_type: string;
    method: string;
    mean?: number;
    std_dev?: number;
    min_bound?: number;
    max_bound?: number;
}

const DATA_TYPES = [
    { label: "Float", value: "float" },
    { label: "Integer", value: "integer" },
    { label: "Date (RFC3339)", value: "date" },
];

const NOISE_METHODS = [
    { label: "Gaussian", value: "Gaussian" },
    { label: "Laplace", value: "Laplace" },
    { label: "Uniform", value: "Uniform" },
];

/** Convert a string input to the correct JSON value based on data_type. */
function toTypedData(raw: string, dataType: string): number | string {
    if (dataType === "float") return parseFloat(raw);
    if (dataType === "integer") return parseInt(raw, 10);
    return raw;
}

const TokenizeNoiseForm: React.FC = () => {
    const [form] = Form.useForm<NoiseFormData>();
    const [res, setRes] = useState<string | undefined>(undefined);
    const [isLoading, setIsLoading] = useState(false);
    const { idToken, serverUrl } = useAuth();
    const responseRef = useRef<HTMLDivElement>(null);
    const method = Form.useWatch("method", form);

    const showMeanStdDev = method === "Gaussian" || method === "Laplace";

    useEffect(() => {
        if (res && responseRef.current) {
            responseRef.current.scrollIntoView({ behavior: "smooth" });
        }
    }, [res]);

    const onFinish = async (values: NoiseFormData) => {
        setIsLoading(true);
        setRes(undefined);
        try {
            const data = toTypedData(values.data, values.data_type);
            const body: Record<string, unknown> = {
                data,
                data_type: values.data_type,
                method: values.method,
            };
            if (showMeanStdDev) {
                body.mean = values.mean;
                body.std_dev = values.std_dev;
            } else {
                body.min_bound = values.min_bound;
                body.max_bound = values.max_bound;
            }
            const response = await postNoTTLVRequest("/tokenize/noise", body, idToken, serverUrl);
            const typed = response as { result?: unknown; code?: number; message?: string };
            if (typed.result !== undefined) {
                setRes(`Result: ${JSON.stringify(typed.result)}`);
            } else {
                setRes(`Error: ${typed.message ?? "Unknown error"}`);
            }
        } catch (e) {
            setRes(`Error: ${e}`);
            console.error("Noise tokenize error:", e);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="rounded-lg p-6 m-4">
            <h1 className="text-2xl font-bold mb-6">Anonymize — Add Noise</h1>

            <div className="mb-8 space-y-2">
                <p>Add statistical noise to a numeric or date value using Gaussian, Laplace, or Uniform distributions.</p>
                <p>
                    For date values, provide an RFC3339-formatted string (e.g. <code>2023-04-07T12:34:56+02:00</code>).
                </p>
            </div>

            <Form form={form} onFinish={onFinish} layout="vertical" initialValues={{ data_type: "float", method: "Gaussian" }}>
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <Form.Item name="data_type" label="Data type" rules={[{ required: true, message: "Please select a data type" }]}>
                            <Select data-testid="noise-datatype-select" options={DATA_TYPES} />
                        </Form.Item>

                        <Form.Item
                            name="data"
                            label="Input value"
                            rules={[{ required: true, message: "Please enter a value" }]}
                            help="Numeric value or RFC3339 date string"
                        >
                            <Input placeholder="e.g. 42.5 or 2023-04-07T12:34:56+02:00" />
                        </Form.Item>
                    </Card>

                    <Card>
                        <Form.Item name="method" label="Distribution" rules={[{ required: true, message: "Please select a distribution" }]}>
                            <Select data-testid="noise-method-select" options={NOISE_METHODS} />
                        </Form.Item>

                        {showMeanStdDev ? (
                            <>
                                <Form.Item
                                    name="mean"
                                    label="Mean"
                                    rules={[{ required: true, message: "Please enter the mean" }]}
                                    help="Mean of the noise distribution"
                                >
                                    <InputNumber style={{ width: "100%" }} placeholder="e.g. 0" />
                                </Form.Item>
                                <Form.Item
                                    name="std_dev"
                                    label="Standard deviation"
                                    rules={[{ required: true, message: "Please enter the standard deviation" }]}
                                    help="Standard deviation (σ) of the distribution"
                                >
                                    <InputNumber style={{ width: "100%" }} min={0} placeholder="e.g. 1.0" />
                                </Form.Item>
                            </>
                        ) : (
                            <>
                                <Form.Item
                                    name="min_bound"
                                    label="Min bound"
                                    rules={[{ required: true, message: "Please enter the minimum bound" }]}
                                    help="Lower bound of the Uniform distribution"
                                >
                                    <InputNumber style={{ width: "100%" }} placeholder="e.g. -5" />
                                </Form.Item>
                                <Form.Item
                                    name="max_bound"
                                    label="Max bound"
                                    rules={[{ required: true, message: "Please enter the maximum bound" }]}
                                    help="Upper bound of the Uniform distribution"
                                >
                                    <InputNumber style={{ width: "100%" }} placeholder="e.g. 5" />
                                </Form.Item>
                            </>
                        )}
                    </Card>

                    <Button type="primary" htmlType="submit" loading={isLoading} data-testid="submit-btn">
                        Add Noise
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

export default TokenizeNoiseForm;
