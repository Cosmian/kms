import React, { useState } from 'react';
import { Layout, Menu } from 'antd';
import { useNavigate } from 'react-router-dom';
import { menuItems } from './menuItems';
import { MenuItem } from './MenuItem';

const { Sider } = Layout;

const Sidebar: React.FC = () => {
    const [collapsed, setCollapsed] = useState(false);
    const navigate = useNavigate();

    const convertMenuItems = (items: MenuItem[]): { key: string, label: string, children?: any[] }[] => {
        return items.map(item => ({
            key: item.key,
            label: item.label,
            children: item.children ? convertMenuItems(item.children) : undefined,
        }));
    };

    return (
        <Sider
            collapsible
            collapsed={collapsed}
            onCollapse={setCollapsed}
            className="h-full"
            style={{ position: 'sticky', top: 0 }}
        >
            <Menu
                mode="inline"
                theme="dark"
                defaultSelectedKeys={['1']}
                defaultOpenKeys={['access-rights']}
                items={menuItems}
                onClick={({ key }) => navigate(key)}
                className="h-full border-r-0"
            />
        </Sider>
    );
};

export default Sidebar;