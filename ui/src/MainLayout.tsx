import { Layout, Switch } from 'antd'
import React, { useEffect, useState } from 'react'
import { Outlet } from 'react-router-dom'
import Footer from './Footer'
import Header from './Header'
import Sidebar from './Sidebar'
import { getNoTTLVRequest } from './utils'

type MainLayoutProps = {
    isDarkMode: boolean;
    setIsDarkMode: (value: boolean) => void;
}

const MainLayout: React.FC<MainLayoutProps> = ({ isDarkMode, setIsDarkMode }) => {
    const [serverVersion, setServerVersion] = useState('');

    useEffect(() => {
        async function fetchServerVersion() {
             const version = await getNoTTLVRequest("/version");
            setServerVersion(version)
        }

        fetchServerVersion();
    }, []);

    return (
        <Layout>
            <Layout.Header className="fixed w-full z-10 p-0 h-16 border-b flex items-center border-gray-300">
                <Header isDarkMode={isDarkMode} />
                <Switch
                className='w-24'
                checked={isDarkMode}
                onChange={() => setIsDarkMode(!isDarkMode)}
                checkedChildren="🌙 Dark"
                unCheckedChildren="☀️ Light"
            />
            </Layout.Header>
            <Layout id="main-page" className="overflow-hidden" style={{ marginTop: 64, height: 'calc(100vh - 64px)' }}>
                <Sidebar />
                <Layout id="main-center" className="flex flex-col overflow-hidden">
                    <Layout.Content id="main-content" className="flex-grow overflow-auto p-4">
                        <Outlet />
                    </Layout.Content>
                    <Footer version={serverVersion} />
                </Layout>
            </Layout>
        </Layout>
    )
};

export default MainLayout;
