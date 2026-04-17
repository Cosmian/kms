import { Button, Card, Form, Input, Space } from "antd";
import React, { useCallback, useEffect, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useAuth } from "../../contexts/AuthContext";
import { getNoTTLVRequest, putNoTTLVRequest } from "../../utils/utils";

interface RoleUpdateFormData {
    role_id: string;
    name: string;
    description?: string;
}

const RoleUpdateForm: React.FC = () => {
    const [form] = Form.useForm<RoleUpdateFormData>();
    const [res, setRes] = useState<string | undefined>(undefined);
    const [isLoading, setIsLoading] = useState(false);
    const [isFetching, setIsFetching] = useState(false);
    const { idToken, serverUrl } = useAuth();
    const responseRef = useRef<HTMLDivElement>(null);
    const [searchParams] = useSearchParams();

    useEffect(() => {
        if (res && responseRef.current) {
            responseRef.current.scrollIntoView({ behavior: "smooth" });
        }
    }, [res]);

    const fetchRole = useCallback(
        async (roleId: string) => {
            setIsFetching(true);
            try {
                const response = await getNoTTLVRequest(`/roles/${roleId}`, idToken, serverUrl);
                form.setFieldsValue({
                    role_id: response.role.id,
                    name: response.role.name,
                    description: response.role.description ?? "",
                });
            } catch (e) {
                setRes(`Error fetching role: ${e}`);
                console.error("Error fetching role:", e);
            } finally {
                setIsFetching(false);
            }
        },
        [form, idToken, serverUrl],
    );

    useEffect(() => {
        const roleId = searchParams.get("roleId");
        if (roleId) {
            form.setFieldValue("role_id", roleId);
            fetchRole(roleId);
        }
    }, [searchParams, form, fetchRole]);

    const onFinish = async (values: RoleUpdateFormData) => {
        setIsLoading(true);
        setRes(undefined);
        try {
            const response = await putNoTTLVRequest(
                `/roles/${values.role_id}`,
                { name: values.name, description: values.description || undefined },
                idToken,
                serverUrl,
            );
            setRes(response.success);
        } catch (e) {
            setRes(`Error updating role: ${e}`);
            console.error("Error updating role:", e);
        } finally {
            setIsLoading(false);
        }
    };

    const handleFetch = () => {
        const roleId = form.getFieldValue("role_id");
        if (roleId) {
            fetchRole(roleId);
        }
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">Update Role</h1>

            <div className="mb-8 space-y-2">
                <p>Update the display name and description of an existing role. Enter the role ID or navigate here from the roles list.</p>
            </div>

            <Form form={form} onFinish={onFinish} layout="vertical">
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <Form.Item
                            name="role_id"
                            label="Role ID"
                            rules={[{ required: true, message: "Please enter the role ID" }]}
                            help="The unique identifier of the role to update"
                        >
                            <Input
                                placeholder="Enter role ID"
                                data-testid="role-id-input"
                                onBlur={handleFetch}
                                onPressEnter={(e) => {
                                    e.preventDefault();
                                    handleFetch();
                                }}
                            />
                        </Form.Item>

                        <Form.Item
                            name="name"
                            label="Display Name"
                            rules={[{ required: true, message: "Please enter a display name" }]}
                        >
                            <Input placeholder="Updated Role Name" disabled={isFetching} data-testid="role-name-input" />
                        </Form.Item>

                        <Form.Item name="description" label="Description">
                            <Input.TextArea placeholder="Updated description..." rows={3} disabled={isFetching} data-testid="role-desc-input" />
                        </Form.Item>
                    </Card>

                    <Form.Item>
                        <Button type="primary" htmlType="submit" loading={isLoading} className="w-full text-white font-medium" data-testid="submit-btn">
                            Update Role
                        </Button>
                    </Form.Item>
                </Space>
            </Form>

            {res && (
                <div ref={responseRef} data-testid="response-output">
                    <Card title="Update role response">{res}</Card>
                </div>
            )}
        </div>
    );
};

export default RoleUpdateForm;
