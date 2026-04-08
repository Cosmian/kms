import { Alert, Button, Card, Form, Input, InputNumber, Select, Space } from "antd";
import React, { useEffect, useRef, useState } from "react";
import { useAuth } from "../../contexts/useAuth";
import { postNoTTLVRequest } from "../../utils/utils";

interface AggregateNumberFormData {
    data: string;
    data_type: string;
    power_of_ten: number;
}

const DATA_TYPES = [
    { label: "Float", value: "float" },
    { label: "Integer", value: "integer" },
];

const TokenizeAggregateNumberForm: React.FC = () => {
    const [form] = Form.useForm<AggregateNumberFormData>();
    const [res, setRes] = useState<string | undefined>(undefined);
    const [isLoading, setIsLoading] = useState(false);
    const { idToken, serverUrl } = useAuth();
    const responseRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        if (res && responseRef.current) {
            responseRef.current.scrollIntoView({ behavior: "smooth" });
        }
    }, [res]);

    const onFinish = async (values: AggregateNumberFormData) => {
        setIsLoading(true);
        setRes(undefined);
        try {
            const data: number = values.data_type === "float" ? parseFloat(values.data) : parseInt(values.data, 10);
            const response = await postNoTTLVRequest(
                "/tokenize/aggregate-number",
                { data, data_type: values.data_type, power_of_ten: values.power_of_ten },
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
            console.error("Aggregate number error:", e);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="rounded-lg p-6 m-4">
            <h1 className="text-2xl font-bold mb-6">Anonymize — Aggregate Number</h1>

            <div className="mb-8 space-y-2">
                <p>Round a number to the nearest power of ten to reduce precision.</p>
                <p>
                    For example, rounding <code>1234</code> with <code>power_of_ten = 2</code> yields <code>1200</code>.
                </p>
            </div>

            <Form form={form} onFinish={onFinish} layout="vertical" initialValues={{ data_type: "integer", power_of_ten: 2 }}>
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <Form.Item name="data_type" label="Data type" rules={[{ required: true, message: "Please select a data type" }]}>
                            <Select data-testid="aggnumber-datatype-select" options={DATA_TYPES} />
                        </Form.Item>

                        <Form.Item
                            name="data"
                            label="Input number"
                            rules={[{ required: true, message: "Please enter a number" }]}
                            help="Number to round"
                        >
                            <Input placeholder="e.g. 1234" />
                        </Form.Item>
                    </Card>

                    <Card>
                        <Form.Item
                            name="power_of_ten"
                            label="Power of ten"
                            rules={[{ required: true, message: "Please enter the power of ten" }]}
                            help="Rounding precision: 1 → nearest 10, 2 → nearest 100, 3 → nearest 1000"
                        >
                            <InputNumber style={{ width: "100%" }} placeholder="e.g. 2" />
                        </Form.Item>
                    </Card>

                    <Button type="primary" htmlType="submit" loading={isLoading} data-testid="submit-btn">
                        Aggregate Number
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

export default TokenizeAggregateNumberForm;
