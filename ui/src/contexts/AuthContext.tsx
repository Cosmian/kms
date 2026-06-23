import { ReactNode, useState } from "react";
import { AuthContext } from "./AuthContextDef.tsx";

export { useAuth } from "./useAuth";

export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
    const [userId, setUserId] = useState<string | null>(null);
    const [serverUrl, setServerUrl] = useState<string>("");

    const login = async () => {
        try {
            const kmsUrl = serverUrl + "/ui/login_flow";
            window.location.href = kmsUrl;
        } catch (error) {
            console.error("Login error:", error);
        }
    };

    const logout = () => {
        setUserId(null);
        const kmsUrl = serverUrl + "/ui/logout";
        window.location.href = kmsUrl;
    };

    return (
        <AuthContext.Provider value={{ serverUrl, setServerUrl, userId, setUserId, login, logout }}>
            {children}
        </AuthContext.Provider>
    );
};
