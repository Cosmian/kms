import { Button, Card, Checkbox, Form, Input, Select, Space } from "antd";
import React, { useCallback, useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { getNoTTLVRequest, postNoTTLVRequest } from "../../utils/utils";
import { useActionState } from "../../hooks/useActionState";
import { ActionResponse } from "../../components/common/ActionResponse";
import LocateButton from "../../components/common/LocateButton";
import * as wasm from "../../wasm/pkg";

interface AccessRevokeFormData {
    user_id: string;
    unique_identifier: string;
    operation_types: string[];
    revoke_create_access_right: boolean;
}

const AccessRevokeForm: React.FC = () => {
    const [form] = Form.useForm<AccessRevokeFormData>();
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

    const onFinish = async (values: AccessRevokeFormData) => {
        await execute(async () => {
            if (values.revoke_create_access_right) {
                values.operation_types.push("create");
            }
            const response = await postNoTTLVRequest("/access/revoke", values, serverUrl);
            return response.success;
        });
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">{t("accessRevoke.title")}</h1>

            <div className="mb-8 space-y-2">
                <p>{t("accessRevoke.intro")}</p>
                <p>{t("accessRevoke.ownerOnly")}</p>
            </div>

            <Form
                form={form}
                onFinish={onFinish}
                layout="vertical"
                initialValues={{ operation_types: [], revoke_create_access_right: false }}
            >
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <Form.Item
                            name="user_id"
                            label={t("accessRevoke.userIdentifier")}
                            rules={[{ required: true, message: t("accessRevoke.pleaseEnterUserId") }]}
                            help={t("accessRevoke.userIdHelp")}
                        >
                            <Input placeholder={t("accessRevoke.enterUserId")} />
                        </Form.Item>

                        <Form.Item
                            name="operation_types"
                            label={t("accessRevoke.kmipOperations")}
                            help={t("accessRevoke.kmipOperationsHelp")}
                        >
                            <Select
                                mode="multiple"
                                options={kmipOperations}
                                placeholder={t("accessRevoke.selectOperations")}
                                onChange={() => {
                                    form.validateFields(["unique_identifier"]);
                                }}
                            />
                        </Form.Item>

                        <Form.Item
                            label={t("accessRevoke.objectUid")}
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
                                                        message: t("accessRevoke.pleaseEnterObjectUid"),
                                                    },
                                                ]}
                                            >
                                                <Input
                                                    placeholder={t("accessRevoke.enterObjectUid")}
                                                    disabled={ops.length === 0}
                                                    style={{ flex: 1 }}
                                                />
                                            </Form.Item>
                                            <LocateButton onSelect={(uid: string) => form.setFieldValue("unique_identifier", uid)} />
                                        </div>
                                        <div className="text-gray-500 dark:text-gray-400 text-sm mt-1">
                                            {t("accessRevoke.objectUidHelp")}
                                        </div>
                                    </div>
                                );
                            }}
                        </Form.Item>
                        {isPrivilegedUser && (
                            <Form.Item name="revoke_create_access_right" valuePropName="checked" help={t("accessRevoke.createAccessHelp")}>
                                <Checkbox>{t("accessRevoke.createAccess")}</Checkbox>
                            </Form.Item>
                        )}
                    </Card>
                    <Form.Item>
                        <Button
                            type="primary"
                            danger
                            htmlType="submit"
                            loading={isLoading}
                            className="w-full text-white font-medium"
                            data-testid="submit-btn"
                        >
                            {t("accessRevoke.submit")}
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            <ActionResponse res={res} responseRef={responseRef} title={t("accessRevoke.responseTitle")} />
        </div>
    );
};

export default AccessRevokeForm;
