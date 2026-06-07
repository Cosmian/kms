import { Button, Card, Checkbox, Form, Input, Select, Space } from "antd";
import React, { useCallback, useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { getNoTTLVRequest, postNoTTLVRequest } from "../../utils/utils";
import { useActionState } from "../../hooks/useActionState";
import { ActionResponse } from "../../components/common/ActionResponse";
import LocateButton from "../../components/common/LocateButton";
import LocateButton from "../../components/common/LocateButton";
import * as wasm from "../../wasm/pkg";

interface AccessGrantFormData {
    user_id: string;
    unique_identifier: string;
    operation_types: string[];
    grant_create_access_right: boolean;
}

const AccessGrantForm: React.FC = () => {
    const [form] = Form.useForm<AccessGrantFormData>();
    const { res, isLoading, responseRef, serverUrl, execute } = useActionState();
    const [isPrivilegedUser, setIsPrivilegedUser] = useState<boolean | undefined>(undefined);
    const { t } = useTranslation("actions");

    const kmipOperations = useMemo(() => {
        try {
            const ops = wasm.get_kmip_operations() as unknown as { value: string; label: string }[];
            if (Array.isArray(ops)) return ops;
        } catch {
            /* WASM not ready */
        }
        return [];
    }, []);

    const fetchPrivilegedAccess = useCallback(async () => {
        setIsPrivilegedUser(undefined);
        try {
            const response = await getNoTTLVRequest("/access/privileged", serverUrl);
            setIsPrivilegedUser(response.has_privileged_access);
        } catch (e) {
            console.error("Error fetching privileged access:", e);
        }
    }, [serverUrl]);

    useEffect(() => {
        fetchPrivilegedAccess();
    }, [fetchPrivilegedAccess]);

    const onFinish = async (values: AccessGrantFormData) => {
        await execute(async () => {
            if (values.grant_create_access_right) {
                values.operation_types.push("create");
            }
            const response = await postNoTTLVRequest("/access/grant", values, serverUrl);
            return response.success;
        });
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">{t("accessGrant.title")}</h1>

            <div className="mb-8 space-y-2">
                <p>{t("accessGrant.intro")}</p>
                <p>{t("accessGrant.ownerOnly")}</p>
            </div>

            <Form
                form={form}
                onFinish={onFinish}
                layout="vertical"
                initialValues={{ operation_types: [], grant_create_access_right: false }}
            >
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <Form.Item
                            name="user_id"
                            label={t("accessGrant.userIdentifier")}
                            rules={[{ required: true, message: t("accessGrant.pleaseEnterUserId") }]}
                            help={t("accessGrant.userIdHelp")}
                        >
                            <Input placeholder={t("accessGrant.enterUserId")} />
                        </Form.Item>

                        <Form.Item
                            name="operation_types"
                            label={t("accessGrant.kmipOperations")}
                            help={t("accessGrant.kmipOperationsHelp")}
                        >
                            <Select
                                mode="multiple"
                                options={kmipOperations}
                                placeholder={t("accessGrant.selectOperations")}
                                data-testid="operation-types-select"
                                onChange={() => {
                                    form.validateFields(["unique_identifier"]);
                                }}
                            />
                        </Form.Item>

                        <Form.Item
                            label={t("accessGrant.objectUid")}
                            shouldUpdate={(prevValues, currentValues) => prevValues.operation_types !== currentValues.operation_types}
                        >
                            {({ getFieldValue }) => {
                                const ops = getFieldValue("operation_types") || [];
                                return (
                                    <div>
                                        <div className="flex items-center gap-2">
                                            <Form.Item
                                                name="unique_identifier"
                                                noStyle
                                                rules={[
                                                    {
                                                        required: ops.length > 0,
                                                        message: t("accessGrant.pleaseEnterObjectUid"),
                                                    },
                                                ]}
                                            >
                                                <Input
                                                    placeholder={t("accessGrant.enterObjectUid")}
                                                    disabled={ops.length === 0}
                                                    style={{ flex: 1 }}
                                                />
                                            </Form.Item>
                                            <LocateButton onSelect={(uid: string) => form.setFieldValue("unique_identifier", uid)} />
                                        </div>
                                        <div className="text-gray-500 dark:text-gray-400 text-sm mt-1">
                                            {t("accessGrant.objectUidHelp")}
                                        </div>
                                    </div>
                                );
                            }}
                        </Form.Item>

                        {isPrivilegedUser && (
                            <Form.Item name="grant_create_access_right" valuePropName="checked" help={t("accessGrant.createAccessHelp")}>
                                <Checkbox>{t("accessGrant.createAccess")}</Checkbox>
                            </Form.Item>
                        )}
                    </Card>

                    <Form.Item>
                        <Button
                            type="primary"
                            htmlType="submit"
                            loading={isLoading}
                            className="w-full text-white font-medium"
                            data-testid="submit-btn"
                        >
                            {t("accessGrant.submit")}
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            <ActionResponse res={res} responseRef={responseRef} title={t("accessGrant.responseTitle")} />
        </div>
    );
};

export default AccessGrantForm;
