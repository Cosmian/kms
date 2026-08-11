import type { Locale as AntdLocale } from "antd/es/locale";
import enUS from "antd/locale/en_US";
import zhCN from "antd/locale/zh_CN";

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

interface LocaleResources {
    common: object;
    menu: object;
    layout: object;
    locate: object;
    actions: object;
}

export interface LocaleDefinition {
    label: string;
    antdLocale: AntdLocale;
    dayjsLocale: string;
    /** Matches browser/detected language tags (e.g. "zh-TW") onto this locale. */
    matches: (lng: string) => boolean;
    resources: LocaleResources;
}

/** Single source of truth for every locale the UI ships: labels, antd/dayjs bindings, and translation bundles. */
export const LOCALE_REGISTRY = {
    en: {
        label: "🇺🇸 English",
        antdLocale: enUS,
        dayjsLocale: "en",
        matches: (lng) => lng.toLowerCase().startsWith("en"),
        resources: {
            common: commonEn,
            menu: menuEn,
            layout: layoutEn,
            locate: locateEn,
            actions: actionsEn,
        },
    },
    "zh-CN": {
        label: "🇨🇳 中文",
        antdLocale: zhCN,
        dayjsLocale: "zh-cn",
        matches: (lng) => lng.toLowerCase().startsWith("zh"),
        resources: {
            common: commonZh,
            menu: menuZh,
            layout: layoutZh,
            locate: locateZh,
            actions: actionsZh,
        },
    },
} as const satisfies Record<string, LocaleDefinition>;

export const SUPPORTED_LOCALES = Object.keys(LOCALE_REGISTRY) as SupportedLocale[];
export type SupportedLocale = keyof typeof LOCALE_REGISTRY;
