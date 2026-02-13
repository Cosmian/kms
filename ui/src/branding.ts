import type { ThemeConfig } from "antd";

export type MenuTheme = "light" | "dark";

export type Branding = {
    title: string;
    faviconUrl?: string;

    logoAlt: string;
    logoLightUrl: string;
    logoDarkUrl: string;

    loginTitle: string;
    loginSubtitle?: string;
    backgroundImageUrl: string;

    menuTheme?: MenuTheme;

    tokens?: {
        light?: ThemeConfig["token"];
        dark?: ThemeConfig["token"];
    };
};

const DEFAULT_BRANDING: Branding = {
    title: "KMS",
    faviconUrl: "/ui/themes/example/favicon-32x32.png",

    logoAlt: "Key Management System",
    logoLightUrl: "/ui/themes/example/logo-light.svg",
    logoDarkUrl: "/ui/themes/example/logo-dark.svg",

    loginTitle: "Key Management System",
    loginSubtitle: "",
    backgroundImageUrl: "/ui/themes/example/login_background.png",

    menuTheme: "light",

    tokens: {
        light: {
            colorPrimary: "#e34319",
            colorText: "#292f52",
        },
        dark: {
            colorPrimary: "#9e6eff",
            colorText: "#e4dddd",
        },
    },
};

function isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === "object" && value !== null;
}

function mergeBranding(defaults: Branding, overrides: Partial<Branding>): Branding {
    const merged: Branding = {
        ...defaults,
        ...overrides,
        tokens: {
            light: {
                ...(defaults.tokens?.light ?? {}),
                ...(overrides.tokens?.light ?? {}),
            },
            dark: {
                ...(defaults.tokens?.dark ?? {}),
                ...(overrides.tokens?.dark ?? {}),
            },
        },
    };

    return merged;
}

export async function loadBranding(options?: { url?: string; cacheBust?: boolean }): Promise<Branding> {
    const url = options?.url ?? "/ui/branding.json";
    const cacheBust = options?.cacheBust ?? true;

    const fetchUrl = cacheBust ? `${url}?v=${encodeURIComponent(String(Date.now()))}` : url;

    try {
        const response = await fetch(fetchUrl, { cache: "no-store" });
        if (!response.ok) {
            return DEFAULT_BRANDING;
        }
        const parsed: unknown = await response.json();
        if (!isRecord(parsed)) {
            return DEFAULT_BRANDING;
        }
        return mergeBranding(DEFAULT_BRANDING, parsed as Partial<Branding>);
    } catch {
        return DEFAULT_BRANDING;
    }
}

export function applyBrandingToDocument(branding: Branding) {
    if (branding.title) {
        document.title = branding.title;
    }

    if (branding.faviconUrl) {
        const link = document.querySelector<HTMLLinkElement>("link[rel='icon']") ?? document.createElement("link");
        link.rel = "icon";
        link.href = branding.faviconUrl;
        document.head.appendChild(link);
    }
}

export function getDefaultBranding(): Branding {
    return DEFAULT_BRANDING;
}
