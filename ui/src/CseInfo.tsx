import { Alert, Button, Card, Space, Tag } from "antd";
import React, { useCallback, useEffect, useState } from "react";
import { useAuth } from "./AuthContext";
import { getNoTTLVRequest, sendKmipRequest } from "./utils";
import { export_ttlv_request } from "./wasm/pkg/cosmian_kms_client_wasm";
import ExternalLink from "./components/ExternalLink";

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

const CseInfo: React.FC = () => {
    const [isLoading, setIsLoading] = useState(false);
    const [cseStatus, setCseStatus] = useState<CseStatus | null>(null);
    const [symKeyExist, setSymKeyExist] = useState<boolean | null>(null);

    const [error, setError] = useState<string | undefined>(undefined);
    const { serverUrl, idToken } = useAuth();

    const fetchCseInfo = useCallback(async () => {
        setIsLoading(true);
        setError(undefined);
        setCseStatus(null);
        setSymKeyExist(null);

        try {
            // Fetch CSE Status
            try {
                const statusResponse = await getNoTTLVRequest("/google_cse/status", null, serverUrl);
                setCseStatus(statusResponse);
            } catch {
                setError("Google CSE is not enabled/configured");
            }

            // Check if key exist
            try {
                const request = export_ttlv_request("google_cse", false, "raw");
                await sendKmipRequest(request, idToken, serverUrl);
                setSymKeyExist(true);
            } catch (keysError) {
                console.warn("Symmetric google_cse key check failed:", keysError);
                setSymKeyExist(false);
            }
        } catch (e) {
            setError(`Error fetching CSE information: ${e}`);
            console.error("Error fetching CSE information:", e);
        } finally {
            setIsLoading(false);
        }
    }, [idToken, serverUrl]);

    useEffect(() => {
        fetchCseInfo();
    }, [fetchCseInfo]);

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
                                    <ExternalLink href={cseStatus.kacls_url} className="text-blue-600 hover:text-blue-800">
                                        {cseStatus.kacls_url}
                                    </ExternalLink>
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

                {/* Key Status Card */}
                {cseStatus && (
                    <Card title="Key Status" className="border rounded">
                        <div className="flex items-center space-x-3">
                            <div>
                                {symKeyExist === null ? (
                                    <Tag color="default">Checking...</Tag>
                                ) : symKeyExist ? (
                                    <Tag color="success">✓ Access to google_cse symmetric key found</Tag>
                                ) : (
                                    <Tag color="error">✗ No access to google_cse symmetric key found</Tag>
                                )}
                            </div>
                        </div>
                    </Card>
                )}
            </Space>
        </div>
    );
};

export default CseInfo;
