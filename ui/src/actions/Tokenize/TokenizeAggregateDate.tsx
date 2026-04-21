import { Alert, Button, Card, Form, Input, Select, Space } from "antd";
import React, { useEffect, useRef, useState } from "react";
import { useAuth } from "../../hooks/useAuth";
import { postNoTTLVRequest } from "../../utils/utils";

interface AggregateDateFormData {
    data: string;
    time_unit: string;
}

const TIME_UNITS = [
    { label: "Second", value: "Second" },
    { label: "Minute", value: "Minute" },
    { label: "Hour", value: "Hour" },
    { label: "Day", value: "Day" },
    { label: "Month", value: "Month" },
    { label: "Year", value: "Year" },
];

const TokenizeAggregateDateForm: React.FC = () => {
    const [form] = Form.useForm<AggregateDateFormData>();
    const [res, setRes] = useState<string | undefined>(undefined);
    const [isLoading, setIsLoading] = useState(false);
    const { idToken, serverUrl } = useAuth();
    const responseRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        if (res && responseRef.current) {
            responseRef.current.scrollIntoView({ behavior: "smooth" });
        }
    }, [res]);

    const onFinish = async (values: AggregateDateFormData) => {
        setIsLoading(true);
        setRes(undefined);
        try {
            const response = await postNoTTLVRequest(
                "/tokenize/aggregate-date",
                { data: values.data, time_unit: values.time_unit },
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
            console.error("Aggregate date error:", e);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="rounded-lg p-6 m-4">
            <h1 className="text-2xl font-bold mb-6">Anonymize — Aggregate Date</h1>

            <div className="mb-8 space-y-2">
                <p>Truncate an RFC3339 date to reduce its temporal precision.</p>
                <p>
                    For example, truncating <code>2023-04-07T12:34:56+02:00</code> to <strong>Hour</strong> yields{" "}
                    <code>2023-04-07T12:00:00+02:00</code>.
                </p>
            </div>

            <Form form={form} onFinish={onFinish} layout="vertical" initialValues={{ time_unit: "Hour" }}>
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <Form.Item
                            name="data"
                            label="Date (RFC3339)"
                            rules={[{ required: true, message: "Please enter an RFC3339 date" }]}
                            help="Date to truncate, e.g. 2023-04-07T12:34:56+02:00"
                        >
                            <Input placeholder="e.g. 2023-04-07T12:34:56+02:00" />
                        </Form.Item>
                    </Card>

                    <Card>
                        <Form.Item
                            name="time_unit"
                            label="Truncate to"
                            rules={[{ required: true, message: "Please select a time unit" }]}
                            help="All sub-units below this level are set to zero"
                        >
                            <Select data-testid="aggdate-timeunit-select" options={TIME_UNITS} />
                        </Form.Item>
                    </Card>

                    <Button type="primary" htmlType="submit" loading={isLoading} data-testid="submit-btn">
                        Aggregate Date
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

export default TokenizeAggregateDateForm;
