import { Alert, Button, Card, Space, Tag } from "antd";
import React, { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { useAuth } from "../../contexts/useAuth";
import { getNoTTLVRequest, sendKmipRequest } from "../../utils/utils";
import { export_ttlv_request } from "../../wasm/pkg/cosmian_kms_client_wasm";
import ExternalLink from "../../components/common/ExternalLink";

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
    const { t } = useTranslation("actions");
    const { serverUrl } = useAuth();

    const fetchCseInfo = useCallback(async () => {
        setIsLoading(true);
        setError(undefined);
        setCseStatus(null);
        setSymKeyExist(null);

        try {
            // Fetch CSE Status
            try {
                const statusResponse = await getNoTTLVRequest("/google_cse/status", serverUrl);
                setCseStatus(statusResponse);
            } catch {
                setError(t("cseInfo.notEnabled"));
            }

            // Check if key exist
            try {
                const request = export_ttlv_request("google_cse", false, "raw");
                await sendKmipRequest(request, serverUrl);
                setSymKeyExist(true);
            } catch (keysError) {
                console.warn("Symmetric google_cse key check failed:", keysError);
                setSymKeyExist(false);
            }
        } catch (e) {
            setError(t("cseInfo.errorFetching", { error: String(e) }));
            console.error("Error fetching CSE information:", e);
        } finally {
            setIsLoading(false);
        }
    }, [serverUrl, t]);

    useEffect(() => {
        fetchCseInfo();
    }, [fetchCseInfo]);

    return (
        <div className="p-6">
            <div className="flex justify-between items-center mb-6">
                <h1 className="text-2xl font-bold">{t("cseInfo.title")}</h1>
                <Button type="primary" onClick={fetchCseInfo} loading={isLoading} className="bg-blue-500 hover:bg-blue-700 border-0">
                    {t("cseInfo.refresh")}
                </Button>
            </div>

            <div className="mb-8 space-y-2">
                <p>{t("cseInfo.intro")}</p>
                <p>{t("cseInfo.intro2")}</p>
            </div>

            <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                {/* CSE Status Card */}
                {cseStatus ? (
                    <Card title={t("cseInfo.statusCard")} className="border rounded">
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
                            <div>
                                <p>
                                    <strong>{t("cseInfo.serverType")}</strong> <Tag color="blue">{cseStatus.server_type}</Tag>
                                </p>
                                <p>
                                    <strong>{t("cseInfo.vendor")}</strong> {cseStatus.vendor_id}
                                </p>
                                <p>
                                    <strong>{t("cseInfo.version")}</strong> <Tag color="green">{cseStatus.version}</Tag>
                                </p>
                            </div>
                            <div>
                                <p>
                                    <strong>{t("cseInfo.name")}</strong> {cseStatus.name}
                                </p>
                                <p>
                                    <strong>{t("cseInfo.kaclsUrl")}</strong>{" "}
                                    <ExternalLink
                                        href={cseStatus.kacls_url}
                                        className="text-blue-600 dark:text-blue-400 hover:text-blue-800 dark:hover:text-blue-300"
                                    >
                                        {cseStatus.kacls_url}
                                    </ExternalLink>
                                </p>
                            </div>
                        </div>

                        {cseStatus.operations_supported && (
                            <div>
                                <h4 className="font-semibold mb-3">{t("cseInfo.supportedOperations")}</h4>
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
                    <Card title={t("cseInfo.statusCard")} className="border rounded">
                        <Alert message={error} type="error" showIcon />
                    </Card>
                )}

                {/* Key Status Card */}
                {cseStatus && (
                    <Card title={t("cseInfo.keyStatusCard")} className="border rounded">
                        <div className="flex items-center space-x-3">
                            <div>
                                {symKeyExist === null ? (
                                    <Tag color="default">{t("cseInfo.checking")}</Tag>
                                ) : symKeyExist ? (
                                    <Tag color="success">{t("cseInfo.keyFound")}</Tag>
                                ) : (
                                    <Tag color="error">{t("cseInfo.keyNotFound")}</Tag>
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
