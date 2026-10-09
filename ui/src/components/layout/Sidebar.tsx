import { Layout, Menu, MenuProps } from "antd";
import React, { useCallback, useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../../contexts/useAuth";
import { useBranding } from "../../contexts/useBranding";
import { MenuItem, getMenuItems } from "../../menuItems.tsx";
import { AuthMethod, fetchAuthMethod, getNoTTLVRequest } from "../../utils/utils.ts";

const { Sider } = Layout;

interface LevelKeysProps {
    key?: string;
    children?: LevelKeysProps[];
}

const Sidebar: React.FC<{ isFips?: boolean; isDarkMode?: boolean }> = ({ isFips = false, isDarkMode = false }) => {
    const [collapsed, setCollapsed] = useState(false);
    const navigate = useNavigate();
    const [stateOpenKeys, setStateOpenKeys] = useState<string[]>([]);
    const branding = useBranding();
    const { t } = useTranslation("menu");
    const menuItems = useMemo(
        () => getMenuItems({ enableCovercrypt: branding.enableCovercrypt, pqcLabel: branding.pqcLabel, isFips }),
        [branding.enableCovercrypt, branding.pqcLabel, isFips],
    );
    const [processedMenuItems, setProcessedMenuItems] = useState<MenuItem[]>(menuItems);
    const { serverUrl } = useAuth();

    // Process menu items to disable "Create" and "Import" options based on access rights
    const processMenuItems = useCallback(
        (hasCreateAccess: boolean) => {
            const processItems = (items: MenuItem[]): MenuItem[] => {
                return items.map((item) => {
                    const newItem = { ...item };

                    // Check if item is a Create item
                    const isCreateItem =
                        item.key && (item.key.includes("/create") || item.key.includes("/create-") || item.label === "Create");

                    // // Check if item is an Import item
                    const isImportItem =
                        item.key && (item.key.includes("/import") || item.key.includes("/import-") || item.label === "Import");

                    // // Handle disabled state based on access rights
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
        },
        [menuItems],
    );

    const fetchCreatePermission = useCallback(async () => {
        try {
            const response = await getNoTTLVRequest("/access/create", serverUrl);
            processMenuItems(response.has_create_permission);
        } catch {
            processMenuItems(false);
        }
    }, [serverUrl, processMenuItems]);

    useEffect(() => {
        (async () => {
            let method: AuthMethod | null = null;
            try {
                method = await fetchAuthMethod(serverUrl);
            } catch {
                /* ignore */
            }
            // In no-auth mode ("None") grant create/import access immediately
            // without calling the permissions API. Also grant if the auth method
            // could not be determined (e.g. server not yet reachable).
            if (method === "None" || method === null) {
                processMenuItems(true);
            } else {
                fetchCreatePermission();
            }
        })();
    }, [fetchCreatePermission, serverUrl, processMenuItems]);

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

    const onOpenChange: MenuProps["onOpenChange"] = (openKeys: string[]) => {
        const currentOpenKey = openKeys.find((key) => stateOpenKeys.indexOf(key) === -1);
        // open
        if (currentOpenKey !== undefined) {
            const repeatIndex = openKeys
                .filter((key: string) => key !== currentOpenKey)
                .findIndex((key: string) => levelKeys[key] === levelKeys[currentOpenKey]);

            setStateOpenKeys(
                openKeys
                    .filter((_, index: number) => index !== repeatIndex)
                    .filter((key: string) => levelKeys[key] <= levelKeys[currentOpenKey]),
            );
        } else {
            // close
            setStateOpenKeys(openKeys);
        }
    };

    // Menu labels are i18n keys: translate via the "menu" namespace, falling
    // back to the English/branding label. rawLabel items (e.g. the branding-
    // provided PQC label) are rendered verbatim.
    const displayLabel = useCallback((item: MenuItem) => (item.rawLabel ? item.label : t(item.key, { defaultValue: item.label })), [t]);

    // Calculate sidebar width based on longest label in the current language.
    const siderWidth = useMemo(() => {
        if (collapsed) {
            return undefined; // Let AntD handle collapsedWidth
        }
        // Recursively extract all translated labels from menu items.
        const allLabels: string[] = [];
        const traverse = (menuItem: MenuItem) => {
            allLabels.push(displayLabel(menuItem));
            menuItem.children?.forEach(traverse);
        };
        processedMenuItems.forEach(traverse);
        const longestLabelLength = allLabels.reduce((max, label) => Math.max(max, label.length), 0);
        // Base width calculation: ~8.5 px per character + 80 px for padding/icon/chevron.
        // Clamp between 220 px (minimum for "Symmetric" or similar) and 360 px (reasonable max).
        return Math.max(220, Math.min(360, Math.ceil(longestLabelLength * 8.5 + 80)));
    }, [processedMenuItems, collapsed, displayLabel]);

    // Recursively decorate every menu level so that sub-menu labels are
    // translated too, not just the top level. Ant Design handles hiding text
    // when collapsed (showing only the icon) and uses the label as the popup
    // sub-menu title — no custom tooltip wrapping needed.
    const decorateMenuItems = (items: MenuItem[]): NonNullable<MenuProps["items"]> =>
        items.map((item) => ({
            ...item,
            label: displayLabel(item),
            ...(item.children ? { children: decorateMenuItems(item.children) } : {}),
        }));

    const modifiedMenuItems = decorateMenuItems(processedMenuItems);

    return (
        <Sider
            collapsible
            collapsed={collapsed}
            onCollapse={setCollapsed}
            width={siderWidth}
            collapsedWidth={80}
            className="h-full"
            style={{ position: "sticky", top: 0, overflow: "auto", background: "var(--cosmian-sidebar-bg)" }}
        >
            <Menu
                mode="inline"
                theme={isDarkMode ? "dark" : (branding.menuTheme ?? "light")}
                defaultSelectedKeys={["1"]}
                defaultOpenKeys={["access-rights"]}
                openKeys={stateOpenKeys}
                onOpenChange={onOpenChange}
                items={modifiedMenuItems}
                onClick={({ key }: { key: string }) => navigate(key)}
                className="h-full border-r-0"
                style={{ fontWeight: "500", overflow: "auto", background: "var(--cosmian-sidebar-bg)" }}
            />
        </Sider>
    );
};

export default Sidebar;
