import { Layout } from 'antd'
import React from 'react'

interface FooterProps {
    version: string;
}

const Footer: React.FC<FooterProps> = ({ version }) => (
    <Layout.Footer className="text-center">
        <p>KMS Server Version: {version}</p>
    </Layout.Footer>
);

export default Footer;
