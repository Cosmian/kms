export interface MenuItem {
    key: string;
    label: string;
    description?: string;
    icon?: React.ReactNode;
    collapsedLabel?: string;
    children?: MenuItem[];
    component?: React.ComponentType;
}
