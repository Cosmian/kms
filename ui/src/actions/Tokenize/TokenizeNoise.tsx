import { Alert, Button, Card, Form, Input, InputNumber, Select, Space } from "antd";
import React, { useEffect, useRef, useState } from "react";
import { Trans, useTranslation } from "react-i18next";
import { useAuth } from "../../contexts/useAuth";
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
    const { serverUrl } = useAuth();
    const { t } = useTranslation("actions");
    const responseRef = useRef<HTMLDivElement>(null);
    const method = Form.useWatch("method", form);
    const DATA_TYPES = [
        { label: t("tokenizeNoise.dataTypeFloat"), value: "float" },
        { label: t("tokenizeNoise.dataTypeInteger"), value: "integer" },
        { label: t("tokenizeNoise.dataTypeDate"), value: "date" },
    ];
    const NOISE_METHODS = [
        { label: t("tokenizeNoise.methodGaussian"), value: "Gaussian" },
        { label: t("tokenizeNoise.methodLaplace"), value: "Laplace" },
        { label: t("tokenizeNoise.methodUniform"), value: "Uniform" },
    ];

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
            const response = await postNoTTLVRequest("/tokenize/noise", body, serverUrl);
            const typed = response as { result?: unknown; code?: number; message?: string };
            if (typed.result !== undefined) {
                setRes(t("tokenizeNoise.resultPrefix", { value: JSON.stringify(typed.result) }));
            } else {
                setRes(`${t("common:errorPrefix")}${typed.message ?? t("tokenizeNoise.unknownError")}`);
            }
        } catch (e) {
            setRes(`${t("common:errorPrefix")}${e}`);
            console.error("Noise tokenize error:", e);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="rounded-lg p-6 m-4">
            <h1 className="text-2xl font-bold mb-6">{t("tokenizeNoise.title")}</h1>

            <div className="mb-8 space-y-2">
                <p>{t("tokenizeNoise.intro")}</p>
                <p>
                    <Trans ns="actions" i18nKey="tokenizeNoise.introDate" components={{ code: <code /> }} />
                </p>
            </div>

            <Form form={form} onFinish={onFinish} layout="vertical" initialValues={{ data_type: "float", method: "Gaussian" }}>
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <Form.Item
                            name="data_type"
                            label={t("tokenizeNoise.dataType")}
                            rules={[{ required: true, message: t("tokenizeNoise.pleaseSelectDataType") }]}
                        >
                            <Select data-testid="noise-datatype-select" options={DATA_TYPES} />
                        </Form.Item>

                        <Form.Item
                            name="data"
                            label={t("tokenizeNoise.inputValue")}
                            rules={[{ required: true, message: t("tokenizeNoise.pleaseEnterValue") }]}
                            help={t("tokenizeNoise.inputValueHelp")}
                        >
                            <Input placeholder={t("tokenizeNoise.inputValuePlaceholder")} />
                        </Form.Item>
                    </Card>

                    <Card>
                        <Form.Item
                            name="method"
                            label={t("tokenizeNoise.distribution")}
                            rules={[{ required: true, message: t("tokenizeNoise.pleaseSelectDistribution") }]}
                        >
                            <Select data-testid="noise-method-select" options={NOISE_METHODS} />
                        </Form.Item>

                        {showMeanStdDev ? (
                            <>
                                <Form.Item
                                    name="mean"
                                    label={t("tokenizeNoise.mean")}
                                    rules={[{ required: true, message: t("tokenizeNoise.pleaseEnterMean") }]}
                                    help={t("tokenizeNoise.meanHelp")}
                                >
                                    <InputNumber style={{ width: "100%" }} placeholder={t("tokenizeNoise.meanPlaceholder")} />
                                </Form.Item>
                                <Form.Item
                                    name="std_dev"
                                    label={t("tokenizeNoise.stdDev")}
                                    rules={[{ required: true, message: t("tokenizeNoise.pleaseEnterStdDev") }]}
                                    help={t("tokenizeNoise.stdDevHelp")}
                                >
                                    <InputNumber style={{ width: "100%" }} min={0} placeholder={t("tokenizeNoise.stdDevPlaceholder")} />
                                </Form.Item>
                            </>
                        ) : (
                            <>
                                <Form.Item
                                    name="min_bound"
                                    label={t("tokenizeNoise.minBound")}
                                    rules={[{ required: true, message: t("tokenizeNoise.pleaseEnterMinBound") }]}
                                    help={t("tokenizeNoise.minBoundHelp")}
                                >
                                    <InputNumber style={{ width: "100%" }} placeholder={t("tokenizeNoise.minBoundPlaceholder")} />
                                </Form.Item>
                                <Form.Item
                                    name="max_bound"
                                    label={t("tokenizeNoise.maxBound")}
                                    rules={[{ required: true, message: t("tokenizeNoise.pleaseEnterMaxBound") }]}
                                    help={t("tokenizeNoise.maxBoundHelp")}
                                >
                                    <InputNumber style={{ width: "100%" }} placeholder={t("tokenizeNoise.maxBoundPlaceholder")} />
                                </Form.Item>
                            </>
                        )}
                    </Card>

                    <Button type="primary" htmlType="submit" loading={isLoading} data-testid="submit-btn">
                        {t("tokenizeNoise.submit")}
                    </Button>
                </Space>
            </Form>

            {res && (
                <div ref={responseRef} className="mt-6">
                    <Alert
                        message={res.startsWith(t("common:errorPrefix")) ? t("common:error") : t("tokenizeNoise.success")}
                        description={
                            <div data-testid="response-output" className="break-all font-mono text-sm whitespace-pre-wrap">
                                {res}
                            </div>
                        }
                        type={res.startsWith(t("common:errorPrefix")) ? "error" : "success"}
                        showIcon
                    />
                </div>
            )}
        </div>
    );
};

export default TokenizeNoiseForm;
