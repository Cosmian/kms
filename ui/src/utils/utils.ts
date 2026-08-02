export type AuthMethod = "None" | "JWT" | "CERT" | "COSMIAN" | undefined;

/** Strip HTML tags from error responses (server may return HTML error pages). */
const stripHtml = (text: string): string =>
    text
        .replace(/<[^>]*>/g, "")
        .replace(/\s+/g, " ")
        .trim();

/**
 * Maximum file size (in bytes) for server-side encryption.
 * The KMS server accepts up to 64 MB JSON payloads. The TTLV JSON format encodes
 * binary data as uppercase hex strings (2× expansion), so the effective cleartext
 * limit is 64 MB / 2 ≈ 32 MB (with margin for the JSON envelope).
 */
export const MAX_UPLOAD_SIZE_BYTES = 30 * 1024 * 1024;

/** Human-readable file size formatting. */
export const formatFileSize = (bytes: number): string => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
};

export const fetchWhoAmI = async (serverUrl: string): Promise<{ user_id: string } | null> => {
    try {
        const kmsUrl = serverUrl + "/ui/whoami";
        const response = await fetch(kmsUrl, {
            method: "GET",
            credentials: "include",
        });
        if (!response.ok) throw new Error("Failed to fetch session user");

        const data: { user_id: string } = await response.json();
        return data;
    } catch {
        return null;
    }
};

export const fetchAuthMethod = async (serverUrl: string): Promise<AuthMethod> => {
    // Completely skip the fetch if we're in dev mode to avoid unnecessary friction.
    if (import.meta.env.VITE_DEV_MODE === "true") {
        return "None";
    }
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
        return undefined;
    }
};

/** Outcome of a `POST /ui/login_as` call — mirrors the KMS server's `CosmianLoginResponse`. */
type CosmianLoginNextStep = "Authenticated" | "TotpRequired";

/**
 * Log in against the Cosmian authentication server via the KMS's BFF proxy
 * (`POST /ui/login_as`). On success the KMS stores the authenticated user in the
 * session cookie; the AS's JWT never reaches the browser.
 *
 * Pass `totpCode` once the caller has already received a `"TotpRequired"` response.
 */
export const loginCosmian = async (
    serverUrl: string,
    username: string,
    password: string,
    totpCode?: string,
): Promise<CosmianLoginNextStep> => {
    const kmsUrl = serverUrl + "/ui/login_as";
    const response = await fetch(kmsUrl, {
        method: "POST",
        credentials: "include",
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify({ username, password, totp_code: totpCode }),
    });

    const data: unknown = await response.json().catch(() => null);

    if (!response.ok) {
        const message =
            data && typeof data === "object" && "error" in data && typeof (data as { error: unknown }).error === "string"
                ? (data as { error: string }).error
                : `Login failed (${response.status})`;
        throw new Error(message);
    }

    return (data as { next_step: CosmianLoginNextStep }).next_step;
};

export const sendKmipRequest = async (request: object, serverUrl: string) => {
    const kmsUrl = serverUrl + "/kmip/2_1";
    const response = await fetch(kmsUrl, {
        method: "POST",
        credentials: "include",
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify(request),
    });

    if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`${response.status}: ${stripHtml(errorText)}`);
    }

    return JSON.stringify(await response.json());
};

export const postNoTTLVRequest = async (path: string, request: object, serverUrl: string) => {
    const kmsUrl = serverUrl + path;
    const response = await fetch(kmsUrl, {
        method: "POST",
        credentials: "include",
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify(request),
    });

    if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`${response.status}: ${stripHtml(errorText)}`);
    }

    return await response.json();
};

export const getNoTTLVRequest = async (path: string, serverUrl: string) => {
    const kmsUrl = serverUrl + path;

    const controller = new AbortController();
    const timeoutMs = 30_000;
    const timeoutHandle = setTimeout(() => controller.abort(), timeoutMs);

    const response = await fetch(kmsUrl, {
        method: "GET",
        credentials: "include",
        signal: controller.signal,
        headers: {},
    });

    clearTimeout(timeoutHandle);

    if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`${response.status}: ${stripHtml(errorText)}`);
    }

    return await response.json();
};

export const getNoTTLVRequestWithTimeout = async (path: string, serverUrl: string, timeoutMs: number) => {
    const kmsUrl = serverUrl + path;
    const controller = new AbortController();
    const timeoutHandle = setTimeout(() => controller.abort(), timeoutMs);

    try {
        const response = await fetch(kmsUrl, {
            method: "GET",
            credentials: "include",
            signal: controller.signal,
            headers: {},
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`${response.status}: ${stripHtml(errorText)}`);
        }

        return await response.json();
    } finally {
        clearTimeout(timeoutHandle);
    }
};

export const downloadFile = (data: string | Uint8Array, filename: string, mimeType: string) => {
    const blobData =
        data instanceof Uint8Array ? [data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) as ArrayBuffer] : [data];
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

export type ObjectType = "rsa" | "ec" | "symmetric" | "covercrypt" | "pqc" | "certificate" | "secret-data" | "opaque-object";

export const getObjectLabel = (type: ObjectType): string => {
    switch (type) {
        case "rsa":
        case "ec":
        case "symmetric":
        case "covercrypt":
        case "pqc":
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
        case "pqc":
            return "a PQC";
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
