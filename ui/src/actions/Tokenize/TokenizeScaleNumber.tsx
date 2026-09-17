import { Alert, Button, Card, Form, Input, InputNumber, Select, Space } from "antd";
import React, { useEffect, useRef, useState } from "react";
import { Trans, useTranslation } from "react-i18next";
import { useAuth } from "../../contexts/useAuth";
import { postNoTTLVRequest } from "../../utils/utils";

interface ScaleNumberFormData {
    data: string;
    data_type: string;
    mean: number;
    std_deviation: number;
    scale: number;
    translate: number;
}

const TokenizeScaleNumberForm: React.FC = () => {
    const [form] = Form.useForm<ScaleNumberFormData>();
    const [res, setRes] = useState<string | undefined>(undefined);
    const [isLoading, setIsLoading] = useState(false);
    const { serverUrl } = useAuth();
    const { t } = useTranslation("actions");
    const responseRef = useRef<HTMLDivElement>(null);
    const DATA_TYPES = [
        { label: t("tokenizeScaleNumber.dataTypeFloat"), value: "float" },
        { label: t("tokenizeScaleNumber.dataTypeInteger"), value: "integer" },
    ];

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
                serverUrl,
            );
            const typed = response as { result?: unknown; code?: number; message?: string };
            if (typed.result !== undefined) {
                setRes(t("tokenizeScaleNumber.resultPrefix", { value: JSON.stringify(typed.result) }));
            } else {
                setRes(`${t("common:errorPrefix")}${typed.message ?? t("tokenizeScaleNumber.unknownError")}`);
            }
        } catch (e) {
            setRes(`${t("common:errorPrefix")}${e}`);
            console.error("Scale number error:", e);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="rounded-lg p-6 m-4">
            <h1 className="text-2xl font-bold mb-6">{t("tokenizeScaleNumber.title")}</h1>

            <div className="mb-8 space-y-2">
                <p>{t("tokenizeScaleNumber.intro")}</p>
                <p>
                    <Trans ns="actions" i18nKey="tokenizeScaleNumber.introFormula" components={{ code: <code /> }} />
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
                        <Form.Item
                            name="data_type"
                            label={t("tokenizeScaleNumber.dataType")}
                            rules={[{ required: true, message: t("tokenizeScaleNumber.pleaseSelectDataType") }]}
                        >
                            <Select data-testid="scalenumber-datatype-select" options={DATA_TYPES} />
                        </Form.Item>

                        <Form.Item
                            name="data"
                            label={t("tokenizeScaleNumber.inputNumber")}
                            rules={[{ required: true, message: t("tokenizeScaleNumber.pleaseEnterNumber") }]}
                            help={t("tokenizeScaleNumber.inputNumberHelp")}
                        >
                            <Input placeholder={t("tokenizeScaleNumber.inputNumberPlaceholder")} />
                        </Form.Item>
                    </Card>

                    <Card title={t("tokenizeScaleNumber.distributionParams")}>
                        <Form.Item
                            name="mean"
                            label={t("tokenizeScaleNumber.mean")}
                            rules={[{ required: true, message: t("tokenizeScaleNumber.pleaseEnterMean") }]}
                            help={t("tokenizeScaleNumber.meanHelp")}
                        >
                            <InputNumber style={{ width: "100%" }} placeholder={t("tokenizeScaleNumber.meanPlaceholder")} />
                        </Form.Item>

                        <Form.Item
                            name="std_deviation"
                            label={t("tokenizeScaleNumber.stdDev")}
                            rules={[{ required: true, message: t("tokenizeScaleNumber.pleaseEnterStdDev") }]}
                            help={t("tokenizeScaleNumber.stdDevHelp")}
                        >
                            <InputNumber style={{ width: "100%" }} placeholder={t("tokenizeScaleNumber.stdDevPlaceholder")} />
                        </Form.Item>
                    </Card>

                    <Card title={t("tokenizeScaleNumber.scalingParams")}>
                        <Form.Item
                            name="scale"
                            label={t("tokenizeScaleNumber.scale")}
                            rules={[{ required: true, message: t("tokenizeScaleNumber.pleaseEnterScale") }]}
                            help={t("tokenizeScaleNumber.scaleHelp")}
                        >
                            <InputNumber style={{ width: "100%" }} placeholder={t("tokenizeScaleNumber.scalePlaceholder")} />
                        </Form.Item>

                        <Form.Item
                            name="translate"
                            label={t("tokenizeScaleNumber.translate")}
                            rules={[{ required: true, message: t("tokenizeScaleNumber.pleaseEnterTranslate") }]}
                            help={t("tokenizeScaleNumber.translateHelp")}
                        >
                            <InputNumber style={{ width: "100%" }} placeholder={t("tokenizeScaleNumber.translatePlaceholder")} />
                        </Form.Item>
                    </Card>

                    <Button type="primary" htmlType="submit" loading={isLoading} data-testid="submit-btn">
                        {t("tokenizeScaleNumber.submit")}
                    </Button>
                </Space>
            </Form>

            {res && (
                <div ref={responseRef} className="mt-6">
                    <Alert
                        message={res.startsWith(t("common:errorPrefix")) ? t("common:error") : t("tokenizeScaleNumber.success")}
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

export default TokenizeScaleNumberForm;
