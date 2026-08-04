import { Alert, Button, Input, Spin } from "antd";
import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../contexts/useAuth";
import { useBranding } from "../contexts/useBranding";
import { AuthMethod, getNoTTLVRequest, loginAuthVerifier } from "../utils/utils";

interface LoginProps {
    auth: boolean;
    error?: undefined | string;
    authMethod?: AuthMethod;
}

const LoginPage: React.FC<LoginProps> = ({ auth, error, authMethod }) => {
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
        if (authMethod === "CERT") {
            try {
                setIsLoading(true);
                setCertError(null);
                // /version works without a cert; /access/create returns 401 without one
                await getNoTTLVRequest("/access/create", serverUrl);
                navigate("/locate");
            } catch (err) {
                console.error("Certificate validation failed:", err);
                setCertError(
                    "No client certificate was provided or it is invalid. If the problem persists, close all instances of your browser and relaunch with the correct client certificate previously loaded.",
                );
            } finally {
                setIsLoading(false);
            }
        } else {
            navigate("/locate");
        }
    };

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
                    {auth && <p className="text-white">Sign up for free and explore rights delegation for multiple users</p>}
                    {error && <p className="text-purple-700">{error}</p>}
                    {certError && (
                        <Alert
                            type="error"
                            showIcon
                            message="CERT identity verification failed"
                            description={certError}
                            className="text-left mb-8"
                        />
                    )}
                    {authMethod === "AUTH_VERIFIER" ? (
                        <div className="space-y-4 text-left" data-testid="auth-verifier-login-form">
                            {authVerifierError && (
                                <Alert
                                    type="error"
                                    showIcon
                                    message="Authentication failed"
                                    description={authVerifierError}
                                    className="text-left mb-4"
                                    data-testid="auth-verifier-login-error"
                                />
                            )}
                            {authVerifierTotpRequired ? (
                                <Input
                                    autoFocus
                                    placeholder="One-time code (TOTP)"
                                    value={authVerifierTotpCode}
                                    onChange={(e) => setAuthVerifierTotpCode(e.target.value)}
                                    onPressEnter={handleAuthVerifierLogin}
                                    data-testid="auth-verifier-totp-input"
                                />
                            ) : (
                                <>
                                    <Input
                                        autoFocus
                                        placeholder="Username"
                                        autoComplete="username"
                                        value={authVerifierUsername}
                                        onChange={(e) => setAuthVerifierUsername(e.target.value)}
                                        onPressEnter={handleAuthVerifierLogin}
                                        data-testid="auth-verifier-username-input"
                                    />
                                    <Input.Password
                                        placeholder="Password"
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
                                {authVerifierTotpRequired ? "VERIFY CODE" : "LOGIN"}
                            </Button>
                        </div>
                    ) : isLoading ? (
                        <Spin size="large" />
                    ) : auth ? (
                        <Button type="primary" block onClick={handleLogin} loading={isLoading} data-testid="oidc-login-btn">
                            LOGIN
                        </Button>
                    ) : (
                        <Button type="primary" block onClick={handleAccessKms} loading={isLoading}>
                            ACCESS KMS
                        </Button>
                    )}
                </div>
            </div>
        </div>
    );
};

export default LoginPage;
