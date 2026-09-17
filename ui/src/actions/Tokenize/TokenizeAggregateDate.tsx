import { Alert, Button, Card, Form, Input, Select, Space } from "antd";
import React, { useEffect, useRef, useState } from "react";
import { Trans, useTranslation } from "react-i18next";
import { useAuth } from "../../contexts/useAuth";
import { postNoTTLVRequest } from "../../utils/utils";

interface AggregateDateFormData {
    data: string;
    time_unit: string;
}

const TokenizeAggregateDateForm: React.FC = () => {
    const [form] = Form.useForm<AggregateDateFormData>();
    const [res, setRes] = useState<string | undefined>(undefined);
    const [isLoading, setIsLoading] = useState(false);
    const { serverUrl } = useAuth();
    const { t } = useTranslation("actions");
    const responseRef = useRef<HTMLDivElement>(null);
    const TIME_UNITS = [
        { label: t("tokenizeAggregateDate.timeUnitSecond"), value: "Second" },
        { label: t("tokenizeAggregateDate.timeUnitMinute"), value: "Minute" },
        { label: t("tokenizeAggregateDate.timeUnitHour"), value: "Hour" },
        { label: t("tokenizeAggregateDate.timeUnitDay"), value: "Day" },
        { label: t("tokenizeAggregateDate.timeUnitMonth"), value: "Month" },
        { label: t("tokenizeAggregateDate.timeUnitYear"), value: "Year" },
    ];

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
                serverUrl,
            );
            const typed = response as { result?: string; code?: number; message?: string };
            if (typed.result !== undefined) {
                setRes(t("tokenizeAggregateDate.resultPrefix", { value: typed.result }));
            } else {
                setRes(`${t("common:errorPrefix")}${typed.message ?? t("tokenizeAggregateDate.unknownError")}`);
            }
        } catch (e) {
            setRes(`${t("common:errorPrefix")}${e}`);
            console.error("Aggregate date error:", e);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="rounded-lg p-6 m-4">
            <h1 className="text-2xl font-bold mb-6">{t("tokenizeAggregateDate.title")}</h1>

            <div className="mb-8 space-y-2">
                <p>{t("tokenizeAggregateDate.intro")}</p>
                <p>
                    <Trans ns="actions" i18nKey="tokenizeAggregateDate.introExample" components={{ code: <code />, strong: <strong /> }} />
                </p>
            </div>

            <Form form={form} onFinish={onFinish} layout="vertical" initialValues={{ time_unit: "Hour" }}>
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <Form.Item
                            name="data"
                            label={t("tokenizeAggregateDate.dateLabel")}
                            rules={[{ required: true, message: t("tokenizeAggregateDate.pleaseEnterDate") }]}
                            help={t("tokenizeAggregateDate.dateHelp")}
                        >
                            <Input placeholder={t("tokenizeAggregateDate.datePlaceholder")} />
                        </Form.Item>
                    </Card>

                    <Card>
                        <Form.Item
                            name="time_unit"
                            label={t("tokenizeAggregateDate.truncateTo")}
                            rules={[{ required: true, message: t("tokenizeAggregateDate.pleaseSelectTimeUnit") }]}
                            help={t("tokenizeAggregateDate.truncateHelp")}
                        >
                            <Select data-testid="aggdate-timeunit-select" options={TIME_UNITS} />
                        </Form.Item>
                    </Card>

                    <Button type="primary" htmlType="submit" loading={isLoading} data-testid="submit-btn">
                        {t("tokenizeAggregateDate.submit")}
                    </Button>
                </Space>
            </Form>

            {res && (
                <div ref={responseRef} className="mt-6">
                    <Alert
                        message={res.startsWith(t("common:errorPrefix")) ? t("common:error") : t("tokenizeAggregateDate.success")}
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

export default TokenizeAggregateDateForm;
