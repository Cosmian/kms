import { Alert, Button, Spin } from "antd";
import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../contexts/AuthContext";
import { useBranding } from "../contexts/useBranding";
import { AuthMethod, getNoTTLVRequest } from "../utils/utils";

interface LoginProps {
    auth: boolean;
    error?: undefined | string;
    authMethod?: AuthMethod;
}

const LoginPage: React.FC<LoginProps> = ({ auth, error, authMethod }) => {
    const [isLoading, setIsLoading] = useState(false);
    const [certError, setCertError] = useState<string | null>(null);
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
                await getNoTTLVRequest("/access/create", null, serverUrl);
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
            navigate("locate");
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
                    {isLoading ? (
                        <Spin size="large" />
                    ) : auth ? (
                        <Button ghost block className="hover:decoration-purple-700" onClick={handleLogin} loading={isLoading}>
                            LOGIN
                        </Button>
                    ) : (
                        <Button ghost block className="hover:decoration-purple-700" onClick={handleAccessKms} loading={isLoading}>
                            ACCESS KMS
                        </Button>
                    )}
                </div>
            </div>
        </div>
    );
};

export default LoginPage;
