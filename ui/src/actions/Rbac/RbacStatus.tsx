import { Card, Descriptions, Spin, Tag } from "antd";
import React, { useCallback, useEffect, useState } from "react";
import { useAuth } from "../../contexts/AuthContext";
import { getNoTTLVRequest } from "../../utils/utils";

interface RbacStatusData {
    enabled: boolean;
    engine: string;
}

const RbacStatus: React.FC = () => {
    const [status, setStatus] = useState<RbacStatusData | undefined>(undefined);
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState<string | undefined>(undefined);
    const { idToken, serverUrl } = useAuth();

    const fetchStatus = useCallback(async () => {
        setIsLoading(true);
        setError(undefined);
        try {
            const response: RbacStatusData = await getNoTTLVRequest("/rbac/status", idToken, serverUrl);
            setStatus(response);
        } catch (e) {
            setError(`Error fetching RBAC status: ${e}`);
            console.error("Error fetching RBAC status:", e);
        } finally {
            setIsLoading(false);
        }
    }, [idToken, serverUrl]);

    useEffect(() => {
        if (idToken) {
            fetchStatus();
        } else {
            setStatus(undefined);
        }
    }, [fetchStatus, idToken]);

    const engineLabel = (engine: string) => {
        switch (engine) {
            case "embedded_regorus":
                return "Embedded Rego (regorus)";
            case "external_opa":
                return "External OPA Server";
            default:
                return engine;
        }
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">RBAC Status</h1>
            {isLoading && <Spin size="large" />}
            {error && <Card>{error}</Card>}
            {status && (
                <Card data-testid="rbac-status-card">
                    <Descriptions column={1} bordered>
                        <Descriptions.Item label="RBAC Enforcement">
                            {status.enabled ? (
                                <Tag color="green" data-testid="rbac-enabled-tag">
                                    ENABLED
                                </Tag>
                            ) : (
                                <Tag color="default" data-testid="rbac-disabled-tag">
                                    DISABLED
                                </Tag>
                            )}
                        </Descriptions.Item>
                        <Descriptions.Item label="Policy Engine">
                            {engineLabel(status.engine)}
                        </Descriptions.Item>
                    </Descriptions>
                </Card>
            )}
        </div>
    );
};

export default RbacStatus;
