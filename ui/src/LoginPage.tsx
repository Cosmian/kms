import { Button, message, Spin } from "antd";
import React, { useState } from "react";
import { useAuth } from "./AuthContext";

const LoginPage: React.FC = () => {
    const [isLoading, setIsLoading] = useState(false);
    const { login } = useAuth();

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
            <img src="/ui/Cosmian-Logo-Dark.svg" alt="Cosmian Logo" className="z-10 w-40 fixed top-5" />
            {/* Background Image */}
            <div
                className="absolute inset-0 bg-cover bg-center flex"
                style={{ backgroundImage: "url('/ui/login_page_background_image.png')" }}
            />
            <div className="relative w-2/3 shadow-2xl rounded-lg p-20 flex flex-col items-center bg-purple-700/30">
                <div className="text-center text-7xl font-bold text-white mb-20 z-10">Cosmian KMS user interface</div>
                <div className="space-y-6 text-center w-1/2">
                    <p className="text-white">Authenticate using your organization's identity provider.</p>

                    {isLoading ? (
                        <Spin size="large" />
                    ) : (
                        <Button ghost block className="hover:decoration-purple-700" onClick={handleLogin} loading={isLoading}>
                            LOGIN
                        </Button>
                    )}
                    {/* Accessible Error Message */}
                    <div id="error-message" role="alert" aria-live="polite" className="text-red-500 text-sm mt-2"></div>
                </div>
            </div>
        </div>
    );
};

export default LoginPage;
