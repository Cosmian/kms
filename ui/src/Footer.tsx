import { Layout } from 'antd'
import React from 'react'

interface FooterProps {
    version: string;
}

const Footer: React.FC<FooterProps> = ({ version }) => (
    <Layout.Footer className="text-center bg-gray-100 border-t border-gray-300">
        <p>KMS Server Version: {version}</p>
    </Layout.Footer>
);

export default Footer;
