import { MoonOutlined, SunOutlined } from "@ant-design/icons";
import { Button, Layout, Spin, Switch } from "antd";
import React, { useEffect, useState } from "react";
import { Outlet } from "react-router-dom";
import { useAuth } from "./AuthContext";
import Footer from "./Footer";
import Header from "./Header";
import Sidebar from "./Sidebar";
import { AuthMethod, getNoTTLVRequest } from "./utils";

type MainLayoutProps = {
    isDarkMode: boolean;
    setIsDarkMode: (value: boolean) => void;
    authMethod: AuthMethod;
};

const MainLayout: React.FC<MainLayoutProps> = ({ isDarkMode, setIsDarkMode, authMethod }) => {
    const [serverVersion, setServerVersion] = useState("");
    const [loading, setLoading] = useState<boolean>(true);
    const { logout, idToken, serverUrl } = useAuth();

    useEffect(() => {
        async function fetchServerVersion() {
            if (idToken || authMethod != "JWT") {
                try {
                    const version = await getNoTTLVRequest("/version", idToken, serverUrl);
                    setServerVersion(version);
                } catch (error) {
                    console.error("Error fetching server version:", error);
                    setServerVersion("Unavailable");
                } finally {
                    setLoading(false);
                }
            } else {
                setLoading(false);
            }
        }

        fetchServerVersion();
    }, []);

    const handleLogout = async () => {
        await logout();
    };

    return (
        <Layout>
            <Layout.Header className="fixed w-full z-10 p-0 h-16 border-b flex items-center justify-between border-gray-300">
                <div className="flex items-center w-full">
                    <Header isDarkMode={isDarkMode} />
                    <div className="flex items-center">
                        <Switch
                            className="w-20 h-[25px]"
                            checked={isDarkMode}
                            onChange={() => setIsDarkMode(!isDarkMode)}
                            checkedChildren={<MoonOutlined />}
                            unCheckedChildren={<SunOutlined />}
                        />
                        {authMethod == "JWT" && (
                            <Button onClick={handleLogout} className="ml-4 w-18">
                                Logout
                            </Button>
                        )}
                    </div>
                </div>
            </Layout.Header>
            <Layout id="main-page" className="overflow-hidden" style={{ marginTop: 64, height: "calc(100vh - 64px)" }}>
                <Sidebar />
                <Layout id="main-center" className="flex flex-col overflow-hidden">
                    <Layout.Content id="main-content" className="flex-grow overflow-auto p-4">
                        {loading ? <Spin size="large" /> : <Outlet />}
                    </Layout.Content>
                    <Footer version={serverVersion} />
                </Layout>
            </Layout>
        </Layout>
    );
};

export default MainLayout;
