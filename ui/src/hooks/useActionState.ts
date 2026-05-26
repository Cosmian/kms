import { useCallback, useEffect, useRef, useState } from "react";
import { useAuth } from "../contexts/AuthContext";

interface ActionState {
    res: string | undefined;
    isLoading: boolean;
    responseRef: React.RefObject<HTMLDivElement | null>;
    idToken: string | null;
    serverUrl: string;
    execute: (fn: () => Promise<string | undefined>) => Promise<void>;
    setRes: (msg: string | undefined) => void;
}

export function useActionState(): ActionState {
    const [res, setRes] = useState<string | undefined>(undefined);
    const [isLoading, setIsLoading] = useState(false);
    const { idToken, serverUrl } = useAuth();
    const responseRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        if (res && responseRef.current) {
            responseRef.current.scrollIntoView({ behavior: "smooth" });
        }
    }, [res]);

    const execute = useCallback(async (fn: () => Promise<string | undefined>) => {
        setIsLoading(true);
        setRes(undefined);
        try {
            const result = await fn();
            if (result) setRes(result);
        } catch (e) {
            const message = e instanceof Error ? e.message : String(e);
            setRes(message);
            console.error(message);
        } finally {
            setIsLoading(false);
        }
    }, []);

    return { res, isLoading, responseRef, idToken, serverUrl, execute, setRes };
}
