import { Alert, Button, Card, Descriptions, Space, Tag } from "antd";
import React, { useEffect, useState } from "react";
import { useAuth } from "./AuthContext";
import { getNoTTLVRequest } from "./utils";

interface CseStatus {
    server_type: string;
    vendor_id: string;
    version: string;
    name: string;
    kacls_url: string;
    operations_supported: {
        [key: string]: string;
    };
}

interface CseConfig {
    [key: string]: any;
}

const CseInfo: React.FC = () => {
    const [isLoading, setIsLoading] = useState(false);
    const [cseStatus, setCseStatus] = useState<CseStatus | null>(null);
    const [cseConfig, setCseConfig] = useState<CseConfig | null>(null);
    const [keysExist, setKeysExist] = useState<boolean | null>(null);
    const [error, setError] = useState<string | undefined>(undefined);
    const { serverUrl } = useAuth();

    const fetchCseInfo = async () => {
        setIsLoading(true);
        setError(undefined);
        setCseStatus(null);
        setCseConfig(null);
        setKeysExist(null);

        try {
            // Fetch CSE Status
            try {
                const statusResponse = await getNoTTLVRequest("/google_cse/status", null, serverUrl);
                setCseStatus(statusResponse);
            } catch {
                setError("Google CSE is not enabled/configured");
            }

            // Fetch CSE Config
            // try {
            //     const configResponse = await getNoTTLVRequest("/cse_config", null, serverUrl);
            //     setCseConfig(configResponse);
            // } catch (configError) {
            //     console.warn("CSE Config not available:", configError);
            // }

            // Check if keys exist
            // try {
            //     const keysResponse = await getNoTTLVRequest("/keys", null, serverUrl);
            //     setKeysExist(
            //         keysResponse && (Array.isArray(keysResponse) ? keysResponse.length > 0 : Object.keys(keysResponse).length > 0)
            //     );
            // } catch (keysError) {
            //     console.warn("Keys check failed:", keysError);
            //     setKeysExist(false);
            // }
        } catch (e) {
            setError(`Error fetching CSE information: ${e}`);
            console.error("Error fetching CSE information:", e);
        } finally {
            setIsLoading(false);
        }
    };

    useEffect(() => {
        fetchCseInfo();
    }, []);

    const renderConfigContent = (config: CseConfig) => {
        const items = Object.entries(config).map(([key, value]) => ({
            key,
            label: key,
            children: typeof value === "object" ? JSON.stringify(value, null, 2) : String(value),
        }));

        return <Descriptions column={1} items={items} bordered size="small" />;
    };

    return (
        <div className="p-6">
            <div className="flex justify-between items-center mb-6">
                <h1 className="text-2xl font-bold">CSE Information</h1>
                <Button type="primary" onClick={fetchCseInfo} loading={isLoading} className="bg-blue-500 hover:bg-blue-700 border-0">
                    Refresh
                </Button>
            </div>

            <div className="mb-8 space-y-2">
                <p>Google Client-Side Encryption (CSE) configuration and status information.</p>
                <p>This displays the current CSE server details, supported operations, and key availability.</p>
            </div>

            <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                {/* CSE Status Card */}
                {cseStatus ? (
                    <Card title="CSE Status" className="border rounded">
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
                            <div>
                                <p>
                                    <strong>Server Type:</strong> <Tag color="blue">{cseStatus.server_type}</Tag>
                                </p>
                                <p>
                                    <strong>Vendor:</strong> {cseStatus.vendor_id}
                                </p>
                                <p>
                                    <strong>Version:</strong> <Tag color="green">{cseStatus.version}</Tag>
                                </p>
                            </div>
                            <div>
                                <p>
                                    <strong>Name:</strong> {cseStatus.name}
                                </p>
                                <p>
                                    <strong>KACLS URL:</strong>{" "}
                                    <a
                                        href={cseStatus.kacls_url}
                                        target="_blank"
                                        rel="noopener noreferrer"
                                        className="text-blue-600 hover:text-blue-800"
                                    >
                                        {cseStatus.kacls_url}
                                    </a>
                                </p>
                            </div>
                        </div>

                        {cseStatus.operations_supported && (
                            <div>
                                <h4 className="font-semibold mb-3">Supported Operations</h4>
                                <div className="flex flex-wrap gap-2">
                                    {Object.values(cseStatus.operations_supported).map((operation, index) => (
                                        <Tag key={index} color="purple">
                                            {operation}
                                        </Tag>
                                    ))}
                                </div>
                            </div>
                        )}
                    </Card>
                ) : (
                    <Card title="CSE Status" className="border rounded">
                        <Alert message={error} type="error" showIcon />
                    </Card>
                )}

                {/* CSE Config Card */}
                {cseConfig && (
                    <Card title="CSE Configuration" className="border rounded">
                        {renderConfigContent(cseConfig)}
                    </Card>
                )}

                {/* Keys Status Card */}
                {cseStatus && (
                    <Card title="Keys Status" className="border rounded">
                        <div className="flex items-center space-x-3">
                            <span>
                                <strong>Keys Available:</strong>
                            </span>
                            {keysExist === null ? (
                                <Tag color="default">Checking...</Tag>
                            ) : keysExist ? (
                                <Tag color="success">✓ Keys Found</Tag>
                            ) : (
                                <Tag color="error">✗ No Keys Found</Tag>
                            )}
                        </div>
                        {keysExist === false && (
                            <Alert
                                message="No keys are currently available"
                                description="You may need to create or import keys to use CSE functionality."
                                type="warning"
                                showIcon
                                className="mt-3"
                            />
                        )}
                    </Card>
                )}
            </Space>
        </div>
    );
};

export default CseInfo;
