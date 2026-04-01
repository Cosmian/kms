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
    /** CSS color for the translucent card overlaid on the login background.
     *  Accepts any CSS color value, e.g. "rgba(126,34,206,0.3)" or "#7e22ce4d". */
    loginCardColor?: string;

    menuTheme?: MenuTheme;

    /** Whether the Covercrypt section is visible in the UI.
     *  Defaults to `true` when omitted from branding.json. */
    enableCovercrypt?: boolean;

    /** Display label for the Post-Quantum section in the sidebar menu.
     *  Defaults to `"PQC"` when omitted. */
    pqcLabel?: string;

    /** Algorithm values to hide from the PQC key creation dropdown.
     *  The values must match the `value` field returned by `get_pqc_algorithms()`. */
    hiddenPqcAlgorithms?: string[];

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
    loginCardColor: "rgba(126,34,206,0.3)",

    menuTheme: "light",

    enableCovercrypt: true,

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

function getDefaultBranding(): Branding {
    return DEFAULT_BRANDING;
}
