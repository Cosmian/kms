export type AuthMethod = "None" | "JWT" | "CERT";

export const fetchIdToken = async (serverUrl: string): Promise<{ id_token: string; user_id: string } | null> => {
    try {
        const kmsUrl = serverUrl + "/ui/token";
        const response = await fetch(kmsUrl, {
            method: "GET",
            credentials: "include",
        });
        if (!response.ok) throw new Error("Failed to fetch token");

        const data: { id_token: string; user_id: string } = await response.json();
        return data;
    } catch (error) {
        console.error(error);
        return null;
    }
};

export const fetchAuthMethod = async (serverUrl: string): Promise<AuthMethod> => {
    try {
        const kmsUrl = serverUrl + "/ui/auth_method";
        const response = await fetch(kmsUrl, {
            method: "GET",
            credentials: "include",
        });
        if (!response.ok) throw new Error("Failed to fetch auth method");

        const data: { auth_method: AuthMethod } = await response.json();
        return data.auth_method;
    } catch (error) {
        console.error(error);
        return "None";
    }
};

export const sendKmipRequest = async (request: object, idToken: string | null, serverUrl: string) => {
    const kmsUrl = serverUrl + "/kmip/2_1";
    const response = await fetch(kmsUrl, {
        method: "POST",
        credentials: "include",
        headers: {
            "Content-Type": "application/json",
            ...(idToken && { Authorization: `Bearer ${idToken}` }),
        },
        body: JSON.stringify(request),
    });

    if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`${response.status}: ${errorText}`);
    }

    return JSON.stringify(await response.json());
};

export const postNoTTLVRequest = async (path: string, request: object, idToken: string | null, serverUrl: string) => {
    const kmsUrl = serverUrl + path;
    const response = await fetch(kmsUrl, {
        method: "POST",
        credentials: "include",
        headers: {
            "Content-Type": "application/json",
            ...(idToken && { Authorization: `Bearer ${idToken}` }),
        },
        body: JSON.stringify(request),
    });

    if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`${response.status}: ${errorText}`);
    }

    return await response.json();
};

export const getNoTTLVRequest = async (path: string, idToken: string | null, serverUrl: string) => {
    const kmsUrl = serverUrl + path;

    const controller = new AbortController();
    const timeoutMs = 30_000;
    const timeoutHandle = setTimeout(() => controller.abort(), timeoutMs);

    const response = await fetch(kmsUrl, {
        method: "GET",
        credentials: "include",
        signal: controller.signal,
        headers: {
            ...(idToken && { Authorization: `Bearer ${idToken}` }),
        },
    });

    clearTimeout(timeoutHandle);

    if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`${response.status}: ${errorText}`);
    }

    return await response.json();
};

export const getNoTTLVRequestWithTimeout = async (
    path: string,
    idToken: string | null,
    serverUrl: string,
    timeoutMs: number
) => {
    const kmsUrl = serverUrl + path;
    const controller = new AbortController();
    const timeoutHandle = setTimeout(() => controller.abort(), timeoutMs);

    try {
        const response = await fetch(kmsUrl, {
            method: "GET",
            credentials: "include",
            signal: controller.signal,
            headers: {
                ...(idToken && { Authorization: `Bearer ${idToken}` }),
            },
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`${response.status}: ${errorText}`);
        }

        return await response.json();
    } finally {
        clearTimeout(timeoutHandle);
    }
};

export const downloadFile = (data: string | Uint8Array, filename: string, mimeType: string) => {
    const blobData = data instanceof Uint8Array ? [data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) as ArrayBuffer] : [data];
    const blob = new Blob(blobData, { type: mimeType });
    const url = URL.createObjectURL(blob);

    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);

    URL.revokeObjectURL(url);
};

export const saveDecryptedFile = (data: Uint8Array, fileName: string, mimeType: string) => {
    let url: string;
    if (mimeType === "application/pdf") {
        let binary = "";
        const bytes = new Uint8Array(data);
        const len = bytes.byteLength;
        for (let i = 0; i < len; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        const base64 = btoa(binary);
        url = "data:application/pdf;base64," + base64;
    } else {
        const decoder = new TextDecoder("utf-8");
        const text = decoder.decode(new Uint8Array(data));
        const blob = new Blob([text], { type: "application/octet-stream" });
        url = URL.createObjectURL(blob);
    }
    const link = document.createElement("a");
    link.href = url;
    link.download = fileName;
    document.body.appendChild(link);

    setTimeout(() => {
        link.click();
        document.body.removeChild(link);
    }, 66);

    setTimeout(() => URL.revokeObjectURL(url), 1000);
};

export const getMimeType = (fileName: string): string => {
    const extension = fileName.split(".").pop()?.toLowerCase() || "";

    const mimeTypes: Record<string, string> = {
        pdf: "application/pdf",
        txt: "text/plain",
        csv: "text/csv",
        json: "application/json",
        xml: "application/xml",
        png: "image/png",
        jpg: "image/jpeg",
        jpeg: "image/jpeg",
        gif: "image/gif",
        mp4: "video/mp4",
        mp3: "audio/mpeg",
        zip: "application/zip",
        tar: "application/x-tar",
        rar: "application/vnd.rar",
    };

    return mimeTypes[extension] || "application/octet-stream";
};

export type ObjectType = "rsa" | "ec" | "symmetric" | "covercrypt" | "certificate" | "secret-data" | "opaque-object";

export const getObjectLabel = (type: ObjectType): string => {
    switch (type) {
        case "rsa":
        case "ec":
        case "symmetric":
        case "covercrypt":
            return "key";
        case "certificate":
            return "certificate";
        case "secret-data":
            return "secret data";
        case "opaque-object":
            return "opaque object";
        default:
            return "object";
    }
};

export const getTypeString = (type: ObjectType): string => {
    switch (type) {
        case "rsa":
            return "an RSA";
        case "ec":
            return "an EC";
        case "covercrypt":
            return "a CoverCrypt";
        case "symmetric":
            return "a symmetric";
        case "certificate":
            return "a";
        case "secret-data":
            return "a";
        case "opaque-object":
            return "an";
        default:
            return "a";
    }
};
