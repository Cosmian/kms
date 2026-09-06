import { DownOutlined } from "@ant-design/icons";
import { Alert, Button, Dropdown, Input } from "antd";
import React, { useState } from "react";
import { useTranslation } from "react-i18next";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../contexts/useAuth";
import { useBranding } from "../contexts/useBranding";
import { AuthMethod, getNoTTLVRequest, loginAuthVerifier } from "../utils/utils";

interface LoginProps {
    auth: boolean;
    error?: undefined | string;
    /** Configured login methods, ordered by priority (primary first). */
    authMethods?: AuthMethod[];
    /** Called when a client-certificate probe succeeds; updates isAuthenticated in App. */
    onCertAuthenticated?: () => void;
}

const LoginPage: React.FC<LoginProps> = ({ auth, error, authMethods, onCertAuthenticated }) => {
    // Keep only browser-login methods, preserving the server's priority order.
    const methods = (authMethods ?? []).filter((m): m is AuthMethod => m === "JWT" || m === "AUTH_VERIFIER" || m === "CERT");
    const [selectedMethod, setSelectedMethod] = useState<AuthMethod | undefined>(methods[0]);
    const [isLoading, setIsLoading] = useState(false);
    const [certError, setCertError] = useState<string | null>(null);
    const [authVerifierUsername, setAuthVerifierUsername] = useState("");
    const [authVerifierPassword, setAuthVerifierPassword] = useState("");
    const [authVerifierTotpCode, setAuthVerifierTotpCode] = useState("");
    const [authVerifierTotpRequired, setAuthVerifierTotpRequired] = useState(false);
    const [authVerifierError, setAuthVerifierError] = useState<string | null>(null);
    const { login, serverUrl } = useAuth();
    const navigate = useNavigate();
    const branding = useBranding();
    const { t } = useTranslation("layout");

    const methodLabel = (method: AuthMethod) => {
        switch (method) {
            case "JWT":
                return t("login.oidc");
            case "CERT":
                return t("login.certificate");
            case "AUTH_VERIFIER":
                return t("login.authVerifier");
            default:
                return method ?? "";
        }
    };

    const handleLogin = async () => {
        try {
            setIsLoading(true);
            await login();
        } catch (error) {
            console.error("Login error:", error);
        } finally {
            setIsLoading(false);
        }
    };

    const handleAccessKms = async () => {
        try {
            setIsLoading(true);
            setCertError(null);
            // /version works without a cert; /access/create returns 401 without one
            await getNoTTLVRequest("/access/create", serverUrl);
            if (onCertAuthenticated) {
                // Multi-method: tell App.tsx the user is now authenticated so the
                // route guard lets them through without a full-page reload.
                onCertAuthenticated();
            } else {
                navigate("/locate");
            }
        } catch (err) {
            console.error("Certificate validation failed:", err);
            setCertError(t("login.certErrorDescription"));
        } finally {
            setIsLoading(false);
        }
    };

    /**
     * Act on a method chosen from the primary or secondary control.
     * One-click methods (JWT redirect, CERT probe) execute immediately; the
     * form-based method (AUTH_VERIFIER) is selected so its form is revealed.
     */
    const selectMethod = (method: AuthMethod) => {
        if (method === "JWT") {
            void handleLogin();
        } else if (method === "CERT") {
            void handleAccessKms();
        } else {
            setSelectedMethod("AUTH_VERIFIER");
        }
    };

    // Methods offered by the secondary control (everything except the current one).
    const otherMethods = methods.filter((m) => m !== selectedMethod);

    const handleAuthVerifierLogin = async () => {
        try {
            setIsLoading(true);
            setAuthVerifierError(null);
            const nextStep = await loginAuthVerifier(
                serverUrl,
                authVerifierUsername,
                authVerifierPassword,
                authVerifierTotpRequired ? authVerifierTotpCode : undefined,
            );
            if (nextStep === "TotpRequired") {
                setAuthVerifierTotpRequired(true);
            } else {
                // Full page navigation (not react-router) so the app's auth bootstrap
                // re-runs and picks up the session cookie the server just set.
                window.location.assign("/ui/locate");
            }
        } catch (err) {
            console.error("Auth Verifier login failed:", err);
            setAuthVerifierError(err instanceof Error ? err.message : String(err));
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="relative min-h-screen flex items-center justify-center bg-gray-900 flex-col">
            {/* Background Image */}
            <div
                className="absolute inset-0 bg-cover bg-center flex"
                style={{ backgroundImage: `url('${branding.backgroundImageUrl}')` }}
            />
            <div
                className="relative w-2/3 shadow-2xl rounded-lg p-20 flex flex-col items-center"
                style={{ backgroundColor: branding.loginCardColor ?? "rgba(126,34,206,0.3)" }}
            >
                {branding.logoDarkUrl && <img src={branding.logoDarkUrl} alt={branding.logoAlt} className="z-10 w-40 mb-20" />}
                <div className="text-center text-7xl font-bold text-white mb-10 z-10">{branding.loginTitle}</div>
                {branding.loginSubtitle && <div className="text-center text-xl text-white/90 mb-10 z-10">{branding.loginSubtitle}</div>}
                <div className="space-y-6 text-center w-1/2">
                    {auth && <p className="text-white">{t("login.signUp")}</p>}
                    {error && <p className="text-purple-300">{error}</p>}
                    {certError && (
                        <Alert type="error" showIcon message={t("login.certFailed")} description={certError} className="text-left mb-8" />
                    )}
                    {selectedMethod === "AUTH_VERIFIER" ? (
                        <div className="space-y-4 text-left" data-testid="auth-verifier-login-form">
                            {authVerifierError && (
                                <Alert
                                    type="error"
                                    showIcon
                                    message={t("login.authFailed")}
                                    description={authVerifierError}
                                    className="text-left mb-4"
                                    data-testid="auth-verifier-login-error"
                                />
                            )}
                            {authVerifierTotpRequired ? (
                                <Input
                                    autoFocus
                                    placeholder={t("login.totpPlaceholder")}
                                    value={authVerifierTotpCode}
                                    onChange={(e) => setAuthVerifierTotpCode(e.target.value)}
                                    onPressEnter={handleAuthVerifierLogin}
                                    data-testid="auth-verifier-totp-input"
                                />
                            ) : (
                                <>
                                    <Input
                                        autoFocus
                                        placeholder={t("login.usernamePlaceholder")}
                                        autoComplete="username"
                                        value={authVerifierUsername}
                                        onChange={(e) => setAuthVerifierUsername(e.target.value)}
                                        onPressEnter={handleAuthVerifierLogin}
                                        data-testid="auth-verifier-username-input"
                                    />
                                    <Input.Password
                                        placeholder={t("login.passwordPlaceholder")}
                                        autoComplete="current-password"
                                        value={authVerifierPassword}
                                        onChange={(e) => setAuthVerifierPassword(e.target.value)}
                                        onPressEnter={handleAuthVerifierLogin}
                                        data-testid="auth-verifier-password-input"
                                    />
                                </>
                            )}
                            <Button
                                type="primary"
                                block
                                onClick={handleAuthVerifierLogin}
                                loading={isLoading}
                                data-testid="auth-verifier-login-submit"
                            >
                                {authVerifierTotpRequired ? t("login.verifyCode") : t("login.login")}
                            </Button>
                        </div>
                    ) : selectedMethod === "JWT" ? (
                        <Button type="primary" block onClick={handleLogin} loading={isLoading} data-testid="oidc-login-btn">
                            {t("login.oidc")}
                        </Button>
                    ) : selectedMethod === "CERT" ? (
                        <Button type="primary" block onClick={handleAccessKms} loading={isLoading} data-testid="cert-login-btn">
                            {t("login.certificate")}
                        </Button>
                    ) : null}

                    {/* Secondary action(s): nothing for a single method, a button for
                        one alternative, a dropdown for several. */}
                    {otherMethods.length === 1 && (
                        <Button block disabled={isLoading} onClick={() => selectMethod(otherMethods[0])} data-testid="login-secondary-btn">
                            {methodLabel(otherMethods[0])}
                        </Button>
                    )}
                    {otherMethods.length >= 2 && (
                        <Dropdown
                            trigger={["click"]}
                            menu={{
                                items: otherMethods.map((m) => ({ key: String(m), label: methodLabel(m) })),
                                onClick: ({ key }) => selectMethod(key as AuthMethod),
                            }}
                        >
                            <Button block disabled={isLoading} data-testid="login-secondary-dropdown">
                                Other sign-in options <DownOutlined />
                            </Button>
                        </Dropdown>
                    )}
                </div>
            </div>
        </div>
    );
};

export default LoginPage;
