import dayjs from "dayjs";
import "dayjs/locale/zh-cn";
import { useEffect } from "react";
import { useTranslation } from "react-i18next";

import { LOCALE_REGISTRY, SUPPORTED_LOCALES, SupportedLocale } from "./localeRegistry";

/**
 * React hook that tracks the active i18n language and exposes:
 *  - the Ant Design locale object for <ConfigProvider locale={...}>
 *  - the dayjs locale name so date pickers follow the selected language
 * It also keeps <html lang="..."> in sync with the active language.
 */
export function useAppLocale() {
    const { i18n } = useTranslation();
    const current: SupportedLocale = SUPPORTED_LOCALES.includes(i18n.language as SupportedLocale)
        ? (i18n.language as SupportedLocale)
        : "en";
    const { antdLocale, dayjsLocale } = LOCALE_REGISTRY[current];

    useEffect(() => {
        document.documentElement.lang = current;
        dayjs.locale(dayjsLocale);
    }, [current, dayjsLocale]);

    return { isZh: current === "zh-CN", antdLocale };
}
