import React from 'react';
import { Layout } from 'antd';
import { Outlet } from 'react-router-dom';
import Header from './Header';
import Sidebar from './Sidebar';
import Footer from './Footer';

const MainLayout: React.FC = () => (
    <Layout className="min-h-screen">
        <Layout.Header className="fixed w-full z-10 p-0 h-16">
            <Header />
        </Layout.Header>
        <Layout id="main-page" className="overflow-hidden" style={{ marginTop: 64, height: 'calc(100vh - 64px)' }}>
            <Sidebar />
            <Layout id="main-center" className="flex flex-col overflow-hidden">
                <Layout.Content id="main-content" className="flex-grow overflow-auto p-4">
                    <Outlet />
                </Layout.Content>
                <Footer version="1.0.0" />
            </Layout>
        </Layout>
    </Layout>
);

export default MainLayout;