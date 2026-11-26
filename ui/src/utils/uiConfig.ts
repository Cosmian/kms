const featureKeys = ["kv", "hsm", "google_cse", "crypto_officer"] as const;
export type UiFeature = (typeof featureKeys)[number];
export type UiFeatures = Partial<Record<UiFeature, boolean>>;

export async function fetchUiConfig(serverUrl: string): Promise<UiFeatures | undefined> {
    try {
        const result = await fetch(`${serverUrl}/ui/config`, {
            credentials: "include",
            signal: AbortSignal.timeout(2_000),
        });
        // Older or headless KMS instances may not serve this endpoint.
        if (result.status === 404) return undefined;
        if (!result.ok) throw new Error(`UI configuration returned HTTP ${result.status}`);
        const response: unknown = await result.json();
        if (response === null || typeof response !== "object" || Array.isArray(response)) {
            throw new Error("Invalid UI configuration response");
        }
        const entries: [UiFeature, boolean][] = [];
        for (const key of featureKeys) {
            if (!Object.hasOwn(response, key)) continue;
            const value: unknown = Reflect.get(response, key);
            if (typeof value !== "boolean") throw new Error(`Invalid UI feature flag: ${key}`);
            entries.push([key, value]);
        }
        return Object.fromEntries(entries);
    } catch (error) {
        console.warn("Could not load UI configuration; retaining existing menu behavior", error);
        return undefined;
    }
}
