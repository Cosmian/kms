import { ReactNode, useState } from "react";
import { AuthContext } from "./AuthContextDef.tsx";

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

    // POST (not a link): logout changes state and must not be triggerable by a cross-site GET.
    // A form submission lets the browser follow the server's redirect (to the IdP logout page).
    const logout = () => {
        setUserId(null);
        const form = document.createElement("form");
        form.method = "POST";
        form.action = serverUrl + "/ui/logout";
        document.body.appendChild(form);
        form.submit();
    };

    return <AuthContext.Provider value={{ serverUrl, setServerUrl, userId, setUserId, login, logout }}>{children}</AuthContext.Provider>;
};
