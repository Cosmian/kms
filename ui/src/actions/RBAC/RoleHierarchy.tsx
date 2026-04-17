import { Button, Card, Modal, Space, Tag, Tree, Typography } from "antd";
import { ApartmentOutlined, DeleteOutlined, ReloadOutlined } from "@ant-design/icons";
import React, { useCallback, useEffect, useRef, useState } from "react";
import { useAuth } from "../../contexts/AuthContext";
import { deleteNoTTLVRequest, getNoTTLVRequest } from "../../utils/utils";

interface Role {
    id: string;
    name: string;
    description?: string;
    builtin: boolean;
}

interface RoleTreeNode {
    role: Role;
    juniors: RoleTreeNode[];
}

interface HierarchyEdge {
    senior_role_id: string;
    junior_role_id: string;
}

interface AntTreeDataNode {
    title: React.ReactNode;
    key: string;
    children: AntTreeDataNode[];
    icon?: React.ReactNode;
}

const convertToAntTree = (
    node: RoleTreeNode,
    onRemoveEdge: (seniorId: string, juniorId: string) => void,
    parentId?: string,
): AntTreeDataNode => {
    return {
        title: (
            <Space>
                <span style={{ fontWeight: node.role.builtin ? 600 : 400 }}>
                    {node.role.name}
                </span>
                <Tag>{node.role.id}</Tag>
                {node.role.builtin && <Tag color="blue">Built-in</Tag>}
                {parentId && (
                    <Button
                        size="small"
                        danger
                        icon={<DeleteOutlined />}
                        onClick={(e) => {
                            e.stopPropagation();
                            onRemoveEdge(parentId, node.role.id);
                        }}
                        title={`Remove ${node.role.id} as junior of ${parentId}`}
                    />
                )}
            </Space>
        ),
        key: parentId ? `${parentId}->${node.role.id}` : node.role.id,
        icon: <ApartmentOutlined />,
        children: node.juniors.map((junior) =>
            convertToAntTree(junior, onRemoveEdge, node.role.id),
        ),
    };
};

const RoleHierarchy: React.FC = () => {
    const [roles, setRoles] = useState<Role[]>([]);
    const [edges, setEdges] = useState<HierarchyEdge[]>([]);
    const [isLoading, setIsLoading] = useState(false);
    const [res, setRes] = useState<string | undefined>(undefined);
    const { idToken, serverUrl } = useAuth();
    const responseRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        if (res && responseRef.current) {
            responseRef.current.scrollIntoView({ behavior: "smooth" });
        }
    }, [res]);

    const fetchData = useCallback(async () => {
        setIsLoading(true);
        setRes(undefined);
        try {
            const [rolesResponse, edgesResponse] = await Promise.all([
                getNoTTLVRequest("/roles", idToken, serverUrl),
                getNoTTLVRequest("/roles-hierarchy", idToken, serverUrl),
            ]);
            setRoles(rolesResponse.roles ?? []);
            setEdges(edgesResponse.edges ?? []);
        } catch (e) {
            setRes(`Error fetching hierarchy: ${e}`);
            console.error("Error fetching hierarchy:", e);
        } finally {
            setIsLoading(false);
        }
    }, [idToken, serverUrl]);

    useEffect(() => {
        fetchData();
    }, [fetchData]);

    const handleRemoveEdge = (seniorId: string, juniorId: string) => {
        Modal.confirm({
            title: "Remove hierarchy edge?",
            content: `This will stop "${seniorId}" from inheriting permissions of "${juniorId}".`,
            okText: "Remove",
            okType: "danger",
            onOk: async () => {
                try {
                    const response = await deleteNoTTLVRequest(
                        `/roles/${seniorId}/juniors/${juniorId}`,
                        idToken,
                        serverUrl,
                    );
                    setRes(response.success);
                    await fetchData();
                } catch (e) {
                    setRes(`Error removing edge: ${e}`);
                    console.error("Error removing edge:", e);
                }
            },
        });
    };

    // Build trees from flat roles + edges data client-side
    const buildTrees = (): AntTreeDataNode[] => {
        const roleMap = new Map(roles.map((r) => [r.id, r]));
        const childrenMap = new Map<string, string[]>();
        const hasParent = new Set<string>();

        for (const edge of edges) {
            const children = childrenMap.get(edge.senior_role_id) ?? [];
            children.push(edge.junior_role_id);
            childrenMap.set(edge.senior_role_id, children);
            hasParent.add(edge.junior_role_id);
        }

        const buildNode = (roleId: string): RoleTreeNode | null => {
            const role = roleMap.get(roleId);
            if (!role) return null;
            const childIds = childrenMap.get(roleId) ?? [];
            const juniors = childIds
                .map((id) => buildNode(id))
                .filter((n): n is RoleTreeNode => n !== null);
            return { role, juniors };
        };

        // Root roles are those with no parent
        const rootIds = roles
            .map((r) => r.id)
            .filter((id) => !hasParent.has(id));

        return rootIds
            .map((id) => buildNode(id))
            .filter((n): n is RoleTreeNode => n !== null)
            .map((node) => convertToAntTree(node, handleRemoveEdge));
    };

    const treeData = buildTrees();

    return (
        <div className="p-6">
            <div className="flex justify-between items-center mb-6">
                <h1 className="text-2xl font-bold">Role Hierarchy</h1>
                <Button type="default" icon={<ReloadOutlined />} onClick={fetchData} loading={isLoading}>
                    Refresh
                </Button>
            </div>

            <div className="mb-8 space-y-2">
                <p>
                    The role hierarchy defines inheritance relationships between roles.
                    A senior role inherits all permissions of its junior roles. Use
                    &ldquo;Add Junior Role&rdquo; to create new hierarchy edges.
                </p>
            </div>

            <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                <Card>
                    {treeData.length > 0 ? (
                        <Tree
                            showIcon
                            defaultExpandAll
                            treeData={treeData}
                            selectable={false}
                        />
                    ) : (
                        <Typography.Text type="secondary">
                            {isLoading ? "Loading..." : "No hierarchy edges defined."}
                        </Typography.Text>
                    )}
                </Card>
            </Space>

            {res && (
                <div ref={responseRef} data-testid="response-output">
                    <Card title="Response" className="mt-4">
                        {res}
                    </Card>
                </div>
            )}
        </div>
    );
};

export default RoleHierarchy;
