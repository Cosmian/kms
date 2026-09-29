import { createContext } from "react";

export interface AuthContextType {
    serverUrl: string;
    setServerUrl: (url: string) => void;
    userId: string | null;
    setUserId: (userId: string | null) => void;
    login: () => Promise<void>;
    logout: () => void;
}

export const AuthContext = createContext<AuthContextType | undefined>(undefined);
