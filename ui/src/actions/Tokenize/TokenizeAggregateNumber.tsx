import { Alert, Button, Card, Form, Input, InputNumber, Select, Space } from "antd";
import React, { useEffect, useRef, useState } from "react";
import { Trans, useTranslation } from "react-i18next";
import { useAuth } from "../../contexts/useAuth";
import { postNoTTLVRequest } from "../../utils/utils";

interface AggregateNumberFormData {
    data: string;
    data_type: string;
    power_of_ten: number;
}

const TokenizeAggregateNumberForm: React.FC = () => {
    const [form] = Form.useForm<AggregateNumberFormData>();
    const [res, setRes] = useState<string | undefined>(undefined);
    const [isLoading, setIsLoading] = useState(false);
    const { serverUrl } = useAuth();
    const { t } = useTranslation("actions");
    const responseRef = useRef<HTMLDivElement>(null);
    const DATA_TYPES = [
        { label: t("tokenizeAggregateNumber.dataTypeFloat"), value: "float" },
        { label: t("tokenizeAggregateNumber.dataTypeInteger"), value: "integer" },
    ];

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
                serverUrl,
            );
            const typed = response as { result?: string; code?: number; message?: string };
            if (typed.result !== undefined) {
                setRes(t("tokenizeAggregateNumber.resultPrefix", { value: typed.result }));
            } else {
                setRes(`${t("common:errorPrefix")}${typed.message ?? t("tokenizeAggregateNumber.unknownError")}`);
            }
        } catch (e) {
            setRes(`${t("common:errorPrefix")}${e}`);
            console.error("Aggregate number error:", e);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="rounded-lg p-6 m-4">
            <h1 className="text-2xl font-bold mb-6">{t("tokenizeAggregateNumber.title")}</h1>

            <div className="mb-8 space-y-2">
                <p>{t("tokenizeAggregateNumber.intro")}</p>
                <p>
                    <Trans ns="actions" i18nKey="tokenizeAggregateNumber.introExample" components={{ code: <code /> }} />
                </p>
            </div>

            <Form form={form} onFinish={onFinish} layout="vertical" initialValues={{ data_type: "integer", power_of_ten: 2 }}>
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <Form.Item
                            name="data_type"
                            label={t("tokenizeAggregateNumber.dataType")}
                            rules={[{ required: true, message: t("tokenizeAggregateNumber.pleaseSelectDataType") }]}
                        >
                            <Select data-testid="aggnumber-datatype-select" options={DATA_TYPES} />
                        </Form.Item>

                        <Form.Item
                            name="data"
                            label={t("tokenizeAggregateNumber.inputNumber")}
                            rules={[{ required: true, message: t("tokenizeAggregateNumber.pleaseEnterNumber") }]}
                            help={t("tokenizeAggregateNumber.inputNumberHelp")}
                        >
                            <Input placeholder={t("tokenizeAggregateNumber.inputNumberPlaceholder")} />
                        </Form.Item>
                    </Card>

                    <Card>
                        <Form.Item
                            name="power_of_ten"
                            label={t("tokenizeAggregateNumber.powerOfTen")}
                            rules={[{ required: true, message: t("tokenizeAggregateNumber.pleaseEnterPowerOfTen") }]}
                            help={t("tokenizeAggregateNumber.powerOfTenHelp")}
                        >
                            <InputNumber style={{ width: "100%" }} placeholder={t("tokenizeAggregateNumber.powerOfTenPlaceholder")} />
                        </Form.Item>
                    </Card>

                    <Button type="primary" htmlType="submit" loading={isLoading} data-testid="submit-btn">
                        {t("tokenizeAggregateNumber.submit")}
                    </Button>
                </Space>
            </Form>

            {res && (
                <div ref={responseRef} className="mt-6">
                    <Alert
                        message={res.startsWith(t("common:errorPrefix")) ? t("common:error") : t("tokenizeAggregateNumber.success")}
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

export default TokenizeAggregateNumberForm;
