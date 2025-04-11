import { Layout, Menu, MenuProps, Tooltip } from "antd";
import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { menuItems } from "./menuItems.tsx";

const { Sider } = Layout;

interface LevelKeysProps {
    key?: string;
    children?: LevelKeysProps[];
}

const Sidebar: React.FC = () => {
    const [collapsed, setCollapsed] = useState(false);
    const navigate = useNavigate();
    const [stateOpenKeys, setStateOpenKeys] = useState<string[]>([]);

    const getLevelKeys = (items1: LevelKeysProps[]) => {
        const key: Record<string, number> = {};
        const func = (items2: LevelKeysProps[], level = 1) => {
            items2.forEach((item) => {
                if (item.key) {
                    key[item.key] = level;
                }
                if (item.children) {
                    func(item.children, level + 1);
                }
            });
        };
        func(items1);
        return key;
    };

    const levelKeys = getLevelKeys(menuItems as LevelKeysProps[]);

    const onOpenChange: MenuProps["onOpenChange"] = (openKeys) => {
        const currentOpenKey = openKeys.find((key) => stateOpenKeys.indexOf(key) === -1);
        // open
        if (currentOpenKey !== undefined) {
            const repeatIndex = openKeys
                .filter((key) => key !== currentOpenKey)
                .findIndex((key) => levelKeys[key] === levelKeys[currentOpenKey]);

            setStateOpenKeys(
                openKeys
                    // remove repeat key
                    .filter((_, index) => index !== repeatIndex)
                    // remove current level all child
                    .filter((key) => levelKeys[key] <= levelKeys[currentOpenKey])
            );
        } else {
            // close
            setStateOpenKeys(openKeys);
        }
    };

    const modifiedMenuItems = menuItems.map((item) => ({
        ...item,
        label: collapsed ? <Tooltip title={item.label}>{item.icon ? item.icon : item.collapsedlabel}</Tooltip> : item.label,
    }));

    return (
        <Sider
            collapsible
            collapsed={collapsed}
            onCollapse={setCollapsed}
            className="h-full"
            theme="light"
            style={{ position: "sticky", top: 0, overflow: "auto" }}
        >
            <Menu
                mode="inline"
                defaultSelectedKeys={["1"]}
                defaultOpenKeys={["access-rights"]}
                openKeys={stateOpenKeys}
                onOpenChange={onOpenChange}
                items={modifiedMenuItems}
                onClick={({ key }) => navigate(key)}
                className="h-full border-r-0"
                style={{ fontWeight: "500", overflow: "auto" }}
            />
        </Sider>
    );
};

export default Sidebar;
