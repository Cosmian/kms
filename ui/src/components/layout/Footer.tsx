import { ApiOutlined } from "@ant-design/icons";
import { Layout } from "antd";
import React from "react";
import { useTranslation } from "react-i18next";

interface FooterProps {
    version: string;
}

const Footer: React.FC<FooterProps> = ({ version }) => {
    const { t } = useTranslation("layout");
    return (
        <Layout.Footer className="text-center">
            <p>
                {t("footer.version", { version })}
                <span className="mx-2">|</span>
                <a href="/swagger" target="_blank" rel="noopener noreferrer">
                    <ApiOutlined /> {t("footer.apiDocumentation")}
                </a>
            </p>
        </Layout.Footer>
    );
};

export default Footer;
