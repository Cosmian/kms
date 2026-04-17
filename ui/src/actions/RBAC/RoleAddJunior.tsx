import { Button, Card, Form, Select, Space } from "antd";
import React, { useCallback, useEffect, useRef, useState } from "react";
import { useAuth } from "../../contexts/AuthContext";
import { getNoTTLVRequest, postNoTTLVRequest } from "../../utils/utils";

interface Role {
    id: string;
    name: string;
    description?: string;
    builtin: boolean;
}

interface HierarchyFormData {
    senior_role_id: string;
    junior_role_id: string;
}

const RoleAddJunior: React.FC = () => {
    const [form] = Form.useForm<HierarchyFormData>();
    const [roles, setRoles] = useState<Role[]>([]);
    const [res, setRes] = useState<string | undefined>(undefined);
    const [isLoading, setIsLoading] = useState(false);
    const { idToken, serverUrl } = useAuth();
    const responseRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        if (res && responseRef.current) {
            responseRef.current.scrollIntoView({ behavior: "smooth" });
        }
    }, [res]);

    const fetchRoles = useCallback(async () => {
        try {
            const response = await getNoTTLVRequest("/roles", idToken, serverUrl);
            setRoles(response.roles ?? []);
        } catch (e) {
            console.error("Error fetching roles:", e);
        }
    }, [idToken, serverUrl]);

    useEffect(() => {
        fetchRoles();
    }, [fetchRoles]);

    const onFinish = async (values: HierarchyFormData) => {
        if (values.senior_role_id === values.junior_role_id) {
            setRes("Error: Senior and junior roles must be different (no self-loops).");
            return;
        }
        setIsLoading(true);
        setRes(undefined);
        try {
            const response = await postNoTTLVRequest(
                `/roles/${values.senior_role_id}/juniors/${values.junior_role_id}`,
                {},
                idToken,
                serverUrl,
            );
            setRes(response.success ?? "Hierarchy edge added successfully.");
            form.resetFields();
        } catch (e) {
            setRes(`Error adding hierarchy edge: ${e}`);
            console.error("Error adding hierarchy edge:", e);
        } finally {
            setIsLoading(false);
        }
    };

    const roleOptions = roles.map((r) => ({
        value: r.id,
        label: `${r.name} (${r.id})`,
    }));

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">Add Junior Role</h1>

            <div className="mb-8 space-y-2">
                <p>
                    Create a hierarchy edge so that a <strong>senior role</strong> inherits all
                    permissions of a <strong>junior role</strong>. For example, making
                    &ldquo;crypto-user&rdquo; a junior of &ldquo;operator&rdquo; means operators
                    automatically get all crypto-user permissions.
                </p>
            </div>

            <Form form={form} onFinish={onFinish} layout="vertical">
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <Form.Item
                            name="senior_role_id"
                            label="Senior Role (inherits permissions)"
                            rules={[{ required: true, message: "Please select the senior role" }]}
                        >
                            <Select
                                showSearch
                                placeholder="Select senior role"
                                options={roleOptions}
                                filterOption={(input, option) =>
                                    (option?.label ?? "").toLowerCase().includes(input.toLowerCase())
                                }
                                data-testid="senior-role-select"
                            />
                        </Form.Item>

                        <Form.Item
                            name="junior_role_id"
                            label="Junior Role (provides permissions)"
                            rules={[{ required: true, message: "Please select the junior role" }]}
                        >
                            <Select
                                showSearch
                                placeholder="Select junior role"
                                options={roleOptions}
                                filterOption={(input, option) =>
                                    (option?.label ?? "").toLowerCase().includes(input.toLowerCase())
                                }
                                data-testid="junior-role-select"
                            />
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
                            Add Hierarchy Edge
                        </Button>
                    </Form.Item>
                </Space>
            </Form>

            {res && (
                <div ref={responseRef} data-testid="response-output">
                    <Card title="Add junior role response">{res}</Card>
                </div>
            )}
        </div>
    );
};

export default RoleAddJunior;
