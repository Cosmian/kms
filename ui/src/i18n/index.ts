import i18n from "i18next";
import LanguageDetector from "i18next-browser-languagedetector";
import { initReactI18next } from "react-i18next";

import actionsEn from "./locales/en/actions.json";
import commonEn from "./locales/en/common.json";
import layoutEn from "./locales/en/layout.json";
import locateEn from "./locales/en/locate.json";
import menuEn from "./locales/en/menu.json";

import actionsZh from "./locales/zh-CN/actions.json";
import commonZh from "./locales/zh-CN/common.json";
import layoutZh from "./locales/zh-CN/layout.json";
import locateZh from "./locales/zh-CN/locate.json";
import menuZh from "./locales/zh-CN/menu.json";

/** localStorage key used to persist the user-selected language (mirrors "darkMode"). */
const LOCALE_STORAGE_KEY = "locale";

/** Locales the UI ships translations for. */
export const SUPPORTED_LOCALES = ["en", "zh-CN"] as const;
export type SupportedLocale = (typeof SUPPORTED_LOCALES)[number];

/** Maps any Chinese dialect (zh, zh-CN, zh-TW, ...) to our Simplified Chinese bundle. */
export const isChineseLocale = (lng: string): boolean => lng.toLowerCase().startsWith("zh");

i18n.use(LanguageDetector)
    .use(initReactI18next)
    .init({
        resources: {
            en: {
                common: commonEn,
                menu: menuEn,
                layout: layoutEn,
                locate: locateEn,
                actions: actionsEn,
            },
            "zh-CN": {
                common: commonZh,
                menu: menuZh,
                layout: layoutZh,
                locate: locateZh,
                actions: actionsZh,
            },
        },
        fallbackLng: "en",
        supportedLngs: [...SUPPORTED_LOCALES],
        load: "all",
        detection: {
            // Prefer an explicit user choice, then the browser language.
            order: ["localStorage", "navigator"],
            caches: ["localStorage"],
            lookupLocalStorage: LOCALE_STORAGE_KEY,
            // Normalise every detected locale to one of the supported bundles.
            convertDetectedLanguage: (lng) => (isChineseLocale(lng) ? "zh-CN" : "en"),
        },
        interpolation: {
            // React already escapes values; i18next must not double-escape.
            escapeValue: false,
        },
        returnNull: false,
    });
