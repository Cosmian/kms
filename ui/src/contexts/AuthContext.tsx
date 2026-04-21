import { ReactNode, useState } from "react";
import { AuthContext } from "./AuthContextDef.tsx";

export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
    const [idToken, setIdToken] = useState<string | null>(null);
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
        setIdToken(null);
        const kmsUrl = serverUrl + "/ui/logout";
        window.location.href = kmsUrl;
    };

    return (
        <AuthContext.Provider value={{ serverUrl, setServerUrl, idToken, setIdToken, userId, setUserId, login, logout }}>
            {children}
        </AuthContext.Provider>
    );
};
