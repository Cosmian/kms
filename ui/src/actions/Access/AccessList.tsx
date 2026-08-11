import { Button, Card, Form, Input, Space, Table } from "antd";
import React, { useState } from "react";
import { useTranslation } from "react-i18next";
import { getNoTTLVRequest } from "../../utils/utils";
import { useActionState } from "../../hooks/useActionState";
import { ActionResponse } from "../../components/common/ActionResponse";

interface AccessListFormData {
    unique_identifier: string;
}

interface AccessRight {
    user_id: string;
    operations: string[];
}

const AccessListForm: React.FC = () => {
    const [form] = Form.useForm<AccessListFormData>();
    const { res, isLoading, responseRef, serverUrl, execute } = useActionState();
    const [accessRights, setAccessRights] = useState<AccessRight[]>([]);
    const { t } = useTranslation("actions");

    const onFinish = async (values: AccessListFormData) => {
        setAccessRights([]);
        await execute(async () => {
            const response = await getNoTTLVRequest(`/access/list/${values.unique_identifier}`, serverUrl);
            if (response.length) {
                setAccessRights(response);
            } else {
                return t("accessList.emptyResult");
            }
        });
    };

    const columns = [
        {
            title: t("accessList.colUser"),
            dataIndex: "user_id",
            key: "user_id",
        },
        {
            title: t("accessList.colOperations"),
            dataIndex: "operations",
            key: "operations",
            render: (operations: string[]) => operations.join(", "),
        },
    ];

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">{t("accessList.title")}</h1>

            <div className="mb-8 space-y-2">
                <p>{t("accessList.intro")}</p>
                <p>{t("accessList.ownerOnly")}</p>
            </div>

            <Form form={form} onFinish={onFinish} layout="vertical">
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <Form.Item
                            name="unique_identifier"
                            label={t("accessList.objectUid")}
                            rules={[{ required: true, message: t("accessList.pleaseEnterObjectUid") }]}
                            help={t("accessList.objectUidHelp")}
                        >
                            <Input placeholder={t("accessList.enterObjectUid")} />
                        </Form.Item>
                    </Card>
                    <Form.Item>
                        <Button
                            type="primary"
                            htmlType="submit"
                            loading={isLoading}
                            className="w-full text-white font-medium"
                            data-testid="submit-btn"
                        >
                            {t("accessList.submit")}
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            <ActionResponse res={res} responseRef={responseRef} title={t("accessList.responseTitle")} />

            {accessRights.length > 0 && (
                <div className="mt-8" ref={responseRef} data-testid="response-output">
                    <Card title={t("accessList.accessRightsTitle")}>
                        <Table dataSource={accessRights} columns={columns} rowKey="user_id" pagination={false} />
                    </Card>
                </div>
            )}
        </div>
    );
};

export default AccessListForm;
