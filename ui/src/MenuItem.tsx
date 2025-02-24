export interface MenuItem {
    key: string;
    label: string;
    description?: string;
    icon?: React.ReactNode;
    collapsedlabel?: string;
    children?: MenuItem[];
    component?: React.ComponentType;
}
