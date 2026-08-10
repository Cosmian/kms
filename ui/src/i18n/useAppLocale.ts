import enUS from "antd/locale/en_US";
import zhCN from "antd/locale/zh_CN";
import dayjs from "dayjs";
import "dayjs/locale/zh-cn";
import { useEffect } from "react";
import { useTranslation } from "react-i18next";

import { isChineseLocale } from "./index";

/**
 * React hook that tracks the active i18n language and exposes:
 *  - the Ant Design locale object for <ConfigProvider locale={...}>
 *  - the dayjs locale name so date pickers follow the selected language
 * It also keeps <html lang="..."> in sync with the active language.
 */
export function useAppLocale() {
    const { i18n } = useTranslation();
    const isZh = isChineseLocale(i18n.language);

    useEffect(() => {
        document.documentElement.lang = isZh ? "zh-CN" : "en";
        dayjs.locale(isZh ? "zh-cn" : "en");
    }, [isZh]);

    return { isZh, antdLocale: isZh ? zhCN : enUS };
}
