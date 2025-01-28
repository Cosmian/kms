import React from 'react';
import { Layout } from 'antd';

interface FooterProps {
    version: string;
}

const Footer: React.FC<FooterProps> = ({ version }) => (
    <Layout.Footer className="text-center bg-gray-100">
        <p>KMS Server Version: {version}</p>
    </Layout.Footer>
);

export default Footer;