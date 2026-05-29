import { ApiOutlined } from "@ant-design/icons";
import { Layout } from "antd";
import React from "react";

interface FooterProps {
    version: string;
}

const Footer: React.FC<FooterProps> = ({ version }) => (
    <Layout.Footer className="text-center">
        <p>
            KMS Server Version: {version}
            <span className="mx-2">|</span>
            <a href="/swagger" target="_blank" rel="noopener noreferrer">
                <ApiOutlined /> API Documentation
            </a>
        </p>
    </Layout.Footer>
);

export default Footer;
