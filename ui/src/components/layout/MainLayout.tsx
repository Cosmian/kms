import { DownloadOutlined, MoonOutlined, SunOutlined } from "@ant-design/icons";
import { Alert, Button, Layout, Spin, Switch, Tag, Tooltip } from "antd";
import React, { useCallback, useEffect, useState } from "react";
import { Trans, useTranslation } from "react-i18next";
import { Link, Outlet } from "react-router-dom";
import { useAuth } from "../../contexts/useAuth";
import Footer from "./Footer";
import Header, { ServerInfo } from "./Header";
import Sidebar from "./Sidebar";
import type { LayoutOutletContext } from "./NonFipsRoute";
import { fetchUiConfig, type UiFeatures } from "../../utils/uiConfig";
import LanguageSwitcher from "../common/LanguageSwitcher";
import { AuthMethod, getNoTTLVRequest } from "../../utils/utils";
import { fetchHealth, healthMarker } from "../../utils/health";

type MainLayoutProps = {
    isDarkMode: boolean;
    setIsDarkMode: (value: boolean) => void;
    authMethod: AuthMethod;
    wasmError: boolean;
    /** Defined only when CERT is active and other methods are also configured. */
    onCertLogout?: () => void;
};

const MainLayout: React.FC<MainLayoutProps> = ({ isDarkMode, setIsDarkMode, authMethod, wasmError, onCertLogout }) => {
    const [serverVersion, setServerVersion] = useState("");
    const [serverHealth, setServerHealth] = useState<string>("");
    const [serverHealthLatencyMs, setServerHealthLatencyMs] = useState<number | null>(null);
    const [serverInfo, setServerInfo] = useState<ServerInfo | null>(null);
    const [loading, setLoading] = useState<boolean>(true);
    const { logout, serverUrl, userId } = useAuth();
    const { t } = useTranslation("layout");
    const [downloadTarget, setDownloadTarget] = useState<string>();
    const [currentUser, setCurrentUser] = useState<string | null>(null);
    const [uiConfig, setUiConfig] = useState<{ serverUrl: string; userId: typeof userId; features?: UiFeatures }>();
    const features = uiConfig && uiConfig.serverUrl === serverUrl && uiConfig.userId === userId ? uiConfig.features : null;

    useEffect(() => {
        if (!serverUrl || (authMethod === "JWT" && !userId)) return;
        let cancelled = false;
        void fetchUiConfig(serverUrl).then((features) => {
            if (!cancelled) setUiConfig({ serverUrl, userId, features });
        });
        return () => {
            cancelled = true;
        };
    }, [authMethod, serverUrl, userId]);

    // Fail closed: until the server reports it is NOT in FIPS mode (or if /server-info is
    // unavailable), hide and block the features that do not exist in a FIPS build.
    const isFips = serverInfo?.fips_mode ?? true;

    const serverHealthLabel =
        serverHealthLatencyMs === null
            ? t("main.health", { status: serverHealth })
            : t("main.healthWithLatency", { status: serverHealth, latency: serverHealthLatencyMs });

    const fetchServerInfo = useCallback(async () => {
        if (authMethod != "JWT" || userId) {
            try {
                // Fetch /server-info first: it decides which features are available (FIPS mode),
                // so it must not depend on /version succeeding.
                const info = await getNoTTLVRequest("/server-info", serverUrl);
                setServerInfo(info as ServerInfo);
                const version = await getNoTTLVRequest("/version", serverUrl);
                setServerVersion(version);
                // Fetch the authenticated username via /me (runs through auth middleware).
                // This correctly returns the cert CN for CERT auth.
                try {
                    const me = await getNoTTLVRequest("/me", serverUrl);
                    if (me && typeof me === "object" && "user" in me) {
                        setCurrentUser((me as { user: string }).user);
                    }
                } catch {
                    // /me may fail if no auth is configured; fall back to default_username.
                    setCurrentUser((info as ServerInfo).default_username ?? null);
                }
            } catch {
                setServerVersion(t("main.unavailable"));
            } finally {
                setLoading(false);
            }
        } else {
            setLoading(false);
        }
    }, [authMethod, serverUrl, t, userId]);

    // /health is public and may be slow (the server bounds its HSM probes to 2 s): it has its own
    // request, so a DEGRADED, DOWN or unreachable node never hides the version or delays the page.
    const fetchServerHealth = useCallback(async () => {
        try {
            const health = await fetchHealth(serverUrl, 5_000);
            setServerHealth(health.status);
            setServerHealthLatencyMs(health.latency_ms);
        } catch {
            setServerHealth(t("main.unavailable"));
            setServerHealthLatencyMs(null);
        }
    }, [serverUrl, t]);

    const reportHealth = useCallback((status: string, latencyMs: number | null) => {
        setServerHealth(status);
        setServerHealthLatencyMs(latencyMs);
    }, []);

    const downloadCliUrl = "/download-cli";

    const determineDownloadTarget = useCallback(async () => {
        const kmsUrl = serverUrl + downloadCliUrl;
        try {
            const response = await fetch(kmsUrl, {
                method: "HEAD",
                credentials: "include",
            });

            if (response.status == 200) {
                setDownloadTarget(serverUrl + downloadCliUrl);
                return;
            }
        } catch {
            // Ignore network issues and fall back to the public package page.
        }

        setDownloadTarget("https://package.cosmian.com/kms");
    }, [downloadCliUrl, serverUrl]);

    useEffect(() => {
        fetchServerInfo();
        fetchServerHealth();
        determineDownloadTarget();
    }, [determineDownloadTarget, fetchServerHealth, fetchServerInfo]);

    const handleLogout = async () => {
        await logout();
    };

    return (
        <Layout>
            <Layout.Header className="fixed w-full z-10 p-0 h-16 border-b flex items-center justify-between border-gray-300 dark:border-gray-700">
                <div className="flex items-center w-full h-full">
                    <Header isDarkMode={isDarkMode} serverInfo={serverInfo} />
                    {import.meta.env.VITE_DEV_MODE === "true" && (
                        <Tooltip title={features === undefined ? t("main.devUiConfigUnavailable") : undefined}>
                            <span className="ml-5 inline-flex whitespace-nowrap" data-testid="dev-mode-banner">
                                <Alert
                                    message={t("main.devUnrestricted")}
                                    type="info"
                                    showIcon
                                    closable
                                    className="py-0 px-3 text-sm leading-tight"
                                />
                            </span>
                        </Tooltip>
                    )}
                    <div className="flex items-center h-full ml-auto" style={{ gap: "16px" }}>
                        <LanguageSwitcher />
                        <Switch
                            className="w-20"
                            checked={isDarkMode}
                            onChange={() => setIsDarkMode(!isDarkMode)}
                            checkedChildren={<MoonOutlined />}
                            unCheckedChildren={<SunOutlined />}
                        />
                        {downloadTarget && (
                            <Link to={downloadTarget} target="_blank">
                                <Button type="primary" shape="round" icon={<DownloadOutlined />}>
                                    {t("main.downloadCli")}
                                </Button>
                            </Link>
                        )}
                        {authMethod === "JWT" ||
                        authMethod === "AUTH_VERIFIER" ||
                        authMethod === "AUTH_VERIFIER_SAML" ||
                        authMethod === "SPIFFE" ? (
                            <div className="flex justify-center items-center h-full overflow-hidden ml-4">
                                {userId && (
                                    <Tag className="truncate text-sm leading-tight" color="purple" data-testid="session-user-tag">
                                        {userId}
                                    </Tag>
                                )}
                                <Button onClick={handleLogout} className="ml-4 whitespace-nowrap" data-testid="logout-btn">
                                    {t("main.logout")}
                                </Button>
                            </div>
                        ) : (
                            <div className="flex justify-center items-center h-full overflow-hidden ml-4">
                                {currentUser && (
                                    <Tag className="truncate text-sm leading-tight" color="green">
                                        {currentUser}
                                    </Tag>
                                )}
                                {onCertLogout && (
                                    <Button onClick={onCertLogout} className="ml-4 whitespace-nowrap" data-testid="logout-btn">
                                        {t("main.logout")}
                                    </Button>
                                )}
                            </div>
                        )}
                    </div>
                </div>
            </Layout.Header>

            <Layout id="main-page" className="overflow-hidden" style={{ marginTop: 64, height: "calc(100vh - 64px)" }}>
                <Sidebar isFips={isFips} isDarkMode={isDarkMode} features={features} />
                <Layout id="main-center" className="flex flex-col overflow-hidden">
                    <Layout.Content id="main-content" className="flex-grow overflow-auto p-4">
                        {authMethod === "None" && (
                            <Alert
                                type="warning"
                                showIcon
                                banner
                                className="mb-4"
                                message={
                                    <span className="text-yellow-900 dark:text-yellow-200 font-bold">{t("main.authDisabledTitle")}</span>
                                }
                                description={
                                    <span className="text-yellow-900 dark:text-yellow-200">{t("main.authDisabledDescription")}</span>
                                }
                            />
                        )}
                        {wasmError && (
                            <Alert
                                type="warning"
                                showIcon
                                message={
                                    <span className="text-yellow-900 dark:text-yellow-200 font-bold">{t("main.wasmUnavailableTitle")}</span>
                                }
                                description={
                                    <span className="text-yellow-900 dark:text-yellow-200">
                                        <Trans i18nKey="main.wasmUnavailableDescription" ns="layout" components={{ code: <code /> }} />
                                    </span>
                                }
                            />
                        )}
                        {loading || features === null ? (
                            <Spin size="large" />
                        ) : (
                            <Outlet context={{ isFips, features, reportHealth } satisfies LayoutOutletContext} />
                        )}
                    </Layout.Content>
                    <Footer
                        version={serverVersion}
                        health={
                            serverHealth ? (
                                <Link to="/server-health" data-testid="footer-health">
                                    {healthMarker(serverHealth)} {serverHealthLabel}
                                </Link>
                            ) : undefined
                        }
                    />
                </Layout>
            </Layout>
        </Layout>
    );
};

export default MainLayout;
