export interface MenuItem {
    key: string;
    label: string;
    description?: string;
    children?: MenuItem[];
    component?: React.ComponentType;
}