import { createContext, ReactNode, useContext, useState } from "react";

// Define the context type
interface AuthContextType {
    serverUrl: string;
    setServerUrl: (url: string) => void;
    idToken: string | null;
    setIdToken: (token: string | null) => void;
    login: () => Promise<void>;
    logout: () => void;
}

// Create the context with a default value
const AuthContext = createContext<AuthContextType | undefined>(undefined);

// Provider component
export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
    const [idToken, setIdToken] = useState<string | null>(null);
    const [serverUrl, setServerUrl] = useState<string>("");

    // Login function
    const login = async () => {
        try {
            const kmsUrl = serverUrl + "/ui/login_flow";
            window.location.href = kmsUrl;
        } catch (error) {
            console.error("Login error:", error);
        }
    };

    // Logout function
    const logout = () => {
        setIdToken(null);
        const kmsUrl = serverUrl + "/ui/logout";
        window.location.href = kmsUrl;
    };

    return <AuthContext.Provider value={{ serverUrl, setServerUrl, idToken, setIdToken, login, logout }}>{children}</AuthContext.Provider>;
};

// Custom hook for using auth context
export const useAuth = (): AuthContextType => {
    const context = useContext(AuthContext);
    if (!context) {
        throw new Error("useAuth must be used within an AuthProvider");
    }
    return context;
};
