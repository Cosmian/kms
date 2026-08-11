import i18n from "i18next";
import LanguageDetector from "i18next-browser-languagedetector";
import { initReactI18next } from "react-i18next";

import { LOCALE_REGISTRY, SUPPORTED_LOCALES, SupportedLocale } from "./localeRegistry";

export { SUPPORTED_LOCALES };
export type { SupportedLocale };

/** localStorage key used to persist the user-selected language (mirrors "darkMode"). */
const LOCALE_STORAGE_KEY = "locale";

/** Resolves any detected/browser language tag to one of our supported locales, defaulting to "en". */
const resolveSupportedLocale = (lng: string): SupportedLocale =>
    SUPPORTED_LOCALES.find((locale) => locale !== "en" && LOCALE_REGISTRY[locale].matches(lng)) ?? "en";

i18n.use(LanguageDetector)
    .use(initReactI18next)
    .init({
        resources: Object.fromEntries(SUPPORTED_LOCALES.map((locale) => [locale, LOCALE_REGISTRY[locale].resources])),
        fallbackLng: "en",
        supportedLngs: [...SUPPORTED_LOCALES],
        load: "all",
        detection: {
            // Prefer an explicit user choice, then the browser language.
            order: ["localStorage", "navigator"],
            caches: ["localStorage"],
            lookupLocalStorage: LOCALE_STORAGE_KEY,
            // Normalise every detected locale to one of the supported bundles.
            convertDetectedLanguage: resolveSupportedLocale,
        },
        interpolation: {
            // React already escapes values; i18next must not double-escape.
            escapeValue: false,
        },
        returnNull: false,
    });
