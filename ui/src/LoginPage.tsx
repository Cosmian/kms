import { Button, message, Spin } from "antd";
import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "./AuthContext";
import { useBranding } from "./BrandingContext";

interface LoginProps {
    auth: boolean;
    error?: undefined | string;
}

const LoginPage: React.FC<LoginProps> = ({ auth, error }) => {
    const [isLoading, setIsLoading] = useState(false);
    const { login } = useAuth();
    const navigate = useNavigate();
    const branding = useBranding();

    const handleLogin = async () => {
        try {
            setIsLoading(true);
            await login();
        } catch (error) {
            console.error("Login error:", error);
            message.error("Authentication failed. Please try again.");
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
            <div className="relative w-2/3 shadow-2xl rounded-lg p-20 flex flex-col items-center bg-purple-700/30">
                {branding.logoDarkUrl && (
                    <img src={branding.logoDarkUrl} alt={branding.logoAlt} className="z-10 w-40 mb-20" />
                )}
                <div className="text-center text-7xl font-bold text-white mb-10 z-10">{branding.loginTitle}</div>
                {branding.loginSubtitle && (
                    <div className="text-center text-xl text-white/90 mb-10 z-10">{branding.loginSubtitle}</div>
                )}
                <div className="space-y-6 text-center w-1/2">
                    {auth && <p className="text-white">Sign up for free and explore rights delegation for multiple users</p>}
                    {error && <p className="text-purple-700">{error}</p>}
                    {isLoading ? (
                        <Spin size="large" />
                    ) : auth ? (
                        <Button ghost block className="hover:decoration-purple-700" onClick={handleLogin} loading={isLoading}>
                            LOGIN
                        </Button>
                    ) : (
                        <Button ghost block className="hover:decoration-purple-700" onClick={() => navigate("locate")} loading={isLoading}>
                            ACCESS KMS
                        </Button>
                    )}
                </div>
            </div>
        </div>
    );
};

export default LoginPage;
