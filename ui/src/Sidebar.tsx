import { Layout, Menu, MenuProps, Tooltip } from "antd";
import React, { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "./AuthContext.tsx";
import { MenuItem, menuItems } from "./menuItems.tsx";
import { getNoTTLVRequest } from "./utils.ts";

const { Sider } = Layout;

interface LevelKeysProps {
    key?: string;
    children?: LevelKeysProps[];
}

const Sidebar: React.FC = () => {
    const [collapsed, setCollapsed] = useState(false);
    const navigate = useNavigate();
    const [stateOpenKeys, setStateOpenKeys] = useState<string[]>([]);
    const [processedMenuItems, setProcessedMenuItems] = useState<MenuItem[]>(menuItems);
    const { idToken, serverUrl } = useAuth();

    const fetchCreatePermission = useCallback(async () => {
        try {
            const response = await getNoTTLVRequest("/access/create", idToken, serverUrl);
            processMenuItems(response.has_create_permission);
        } catch (e) {
            console.error("Error fetching create permission:", e);
            processMenuItems(false);
        }
    }, [idToken, serverUrl]);

    useEffect(() => {
        // Only attempt fetching permissions when we have a JWT
        if (idToken) {
            fetchCreatePermission();
        } else {
            // Default: disable create/import when unauthenticated
            processMenuItems(false);
        }
    }, [fetchCreatePermission, idToken]);

    // Process menu items to disable "Create" and "Import" options based on access rights
    const processMenuItems = (hasCreateAccess: boolean) => {
        const processItems = (items: MenuItem[]): MenuItem[] => {
            return items.map((item) => {
                const newItem = { ...item };

                // Check if item is a Create item
                const isCreateItem = item.key && (item.key.includes("/create") || item.key.includes("/create-") || item.label === "Create");

                // Check if item is an Import item
                const isImportItem = item.key && (item.key.includes("/import") || item.key.includes("/import-") || item.label === "Import");

                // Handle disabled state based on access rights
                if (isCreateItem || isImportItem) {
                    newItem.disabled = !hasCreateAccess;
                }

                // Process children recursively if they exist
                if (newItem.children) {
                    newItem.children = processItems(newItem.children);
                }

                return newItem;
            });
        };

        setProcessedMenuItems(processItems(menuItems));
    };

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
                openKeys.filter((_, index) => index !== repeatIndex).filter((key) => levelKeys[key] <= levelKeys[currentOpenKey])
            );
        } else {
            // close
            setStateOpenKeys(openKeys);
        }
    };

    const modifiedMenuItems = processedMenuItems.map((item) => ({
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
