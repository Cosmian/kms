import { GlobalOutlined } from "@ant-design/icons";
import { Select } from "antd";
import React from "react";
import { useTranslation } from "react-i18next";

import { SUPPORTED_LOCALES, SupportedLocale } from "../../i18n";

const localeOptions: { value: SupportedLocale; label: string }[] = [
    { value: "en", label: "English" },
    { value: "zh-CN", label: "中文" },
];

/**
 * Header language switcher. Persists the selection via i18next-browser-
 * languagedetector (localStorage key "locale").
 */
const LanguageSwitcher: React.FC = () => {
    const { i18n } = useTranslation();
    const current = SUPPORTED_LOCALES.includes(i18n.language as SupportedLocale) ? (i18n.language as SupportedLocale) : "en";

    const handleChange = (value: SupportedLocale) => {
        void i18n.changeLanguage(value);
    };

    return (
        <Select
            value={current}
            onChange={handleChange}
            options={localeOptions}
            size="small"
            variant="borderless"
            suffixIcon={<GlobalOutlined />}
            popupMatchSelectWidth={false}
            data-testid="language-switcher"
            aria-label="Language"
        />
    );
};

export default LanguageSwitcher;
