import { Alert, Button, Card, Form, Input, InputNumber, Select, Space } from "antd";
import React, { useEffect, useRef, useState } from "react";
import { useAuth } from "../../contexts/AuthContext";
import { postNoTTLVRequest } from "../../utils/utils";

interface ScaleNumberFormData {
    data: string;
    data_type: string;
    mean: number;
    std_deviation: number;
    scale: number;
    translate: number;
}

const DATA_TYPES = [
    { label: "Float", value: "float" },
    { label: "Integer", value: "integer" },
];

const TokenizeScaleNumberForm: React.FC = () => {
    const [form] = Form.useForm<ScaleNumberFormData>();
    const [res, setRes] = useState<string | undefined>(undefined);
    const [isLoading, setIsLoading] = useState(false);
    const { idToken, serverUrl } = useAuth();
    const responseRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        if (res && responseRef.current) {
            responseRef.current.scrollIntoView({ behavior: "smooth" });
        }
    }, [res]);

    const onFinish = async (values: ScaleNumberFormData) => {
        setIsLoading(true);
        setRes(undefined);
        try {
            const data: number = values.data_type === "float" ? parseFloat(values.data) : parseInt(values.data, 10);
            const response = await postNoTTLVRequest(
                "/tokenize/scale-number",
                {
                    data,
                    data_type: values.data_type,
                    mean: values.mean,
                    std_deviation: values.std_deviation,
                    scale: values.scale,
                    translate: values.translate,
                },
                idToken,
                serverUrl,
            );
            const typed = response as { result?: unknown; code?: number; message?: string };
            if (typed.result !== undefined) {
                setRes(`Result: ${JSON.stringify(typed.result)}`);
            } else {
                setRes(`Error: ${typed.message ?? "Unknown error"}`);
            }
        } catch (e) {
            setRes(`Error: ${e}`);
            console.error("Scale number error:", e);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="rounded-lg p-6 m-4">
            <h1 className="text-2xl font-bold mb-6">Anonymize — Scale Number</h1>

            <div className="mb-8 space-y-2">
                <p>Normalize a number using z-score standardization, then apply a linear scale and translation.</p>
                <p>
                    The transformation is: <code>((x − mean) / std_deviation) × scale + translate</code>.
                </p>
            </div>

            <Form
                form={form}
                onFinish={onFinish}
                layout="vertical"
                initialValues={{ data_type: "float", mean: 0, std_deviation: 1, scale: 1, translate: 0 }}
            >
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <Form.Item name="data_type" label="Data type" rules={[{ required: true, message: "Please select a data type" }]}>
                            <Select data-testid="scalenumber-datatype-select" options={DATA_TYPES} />
                        </Form.Item>

                        <Form.Item
                            name="data"
                            label="Input number"
                            rules={[{ required: true, message: "Please enter a number" }]}
                            help="Number to normalize and scale"
                        >
                            <Input placeholder="e.g. 150.0" />
                        </Form.Item>
                    </Card>

                    <Card title="Distribution parameters">
                        <Form.Item
                            name="mean"
                            label="Mean (μ)"
                            rules={[{ required: true, message: "Please enter the mean" }]}
                            help="Mean of the original data distribution"
                        >
                            <InputNumber style={{ width: "100%" }} placeholder="e.g. 0" />
                        </Form.Item>

                        <Form.Item
                            name="std_deviation"
                            label="Standard deviation (σ)"
                            rules={[{ required: true, message: "Please enter the standard deviation" }]}
                            help="Standard deviation of the original data (must be non-zero)"
                        >
                            <InputNumber style={{ width: "100%" }} placeholder="e.g. 1" />
                        </Form.Item>
                    </Card>

                    <Card title="Scaling parameters">
                        <Form.Item
                            name="scale"
                            label="Scale factor"
                            rules={[{ required: true, message: "Please enter the scale factor" }]}
                            help="Multiplier applied after z-score normalization"
                        >
                            <InputNumber style={{ width: "100%" }} placeholder="e.g. 1" />
                        </Form.Item>

                        <Form.Item
                            name="translate"
                            label="Translation factor"
                            rules={[{ required: true, message: "Please enter the translation factor" }]}
                            help="Offset added after scaling"
                        >
                            <InputNumber style={{ width: "100%" }} placeholder="e.g. 0" />
                        </Form.Item>
                    </Card>

                    <Button type="primary" htmlType="submit" loading={isLoading} data-testid="submit-btn">
                        Scale Number
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

export default TokenizeScaleNumberForm;
