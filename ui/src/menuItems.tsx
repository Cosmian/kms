import { SafetyCertificateOutlined, SearchOutlined, SolutionOutlined, ToolOutlined } from "@ant-design/icons";

export interface MenuItem {
    key: string;
    label: string;
    description?: string;
    icon?: React.ReactNode;
    collapsedlabel?: string;
    children?: MenuItem[];
    component?: React.ComponentType;
}

export const menuItems: MenuItem[] = [
    {
        key: "locate",
        label: "Locate",
        icon: <SearchOutlined />,
    },
    {
        key: "sym",
        label: "Symmetric",
        collapsedlabel: "SYM",
        children: [
            {
                key: "sym/keys",
                label: "Keys",
                children: [
                    { key: "sym/keys/create", label: "Create" },
                    { key: "sym/keys/export", label: "Export" },
                    { key: "sym/keys/import", label: "Import" },
                    { key: "sym/keys/revoke", label: "Revoke" },
                    { key: "sym/keys/destroy", label: "Destroy" },
                ],
            },
            { key: "sym/encrypt", label: "Encrypt" },
            { key: "sym/decrypt", label: "Decrypt" },
        ],
    },
    {
        key: "rsa",
        label: "RSA",
        collapsedlabel: "RSA",
        children: [
            {
                key: "rsa/keys",
                label: "Keys",
                children: [
                    { key: "rsa/keys/create", label: "Create" },
                    { key: "rsa/keys/export", label: "Export" },
                    { key: "rsa/keys/import", label: "Import" },
                    { key: "rsa/keys/revoke", label: "Revoke" },
                    { key: "rsa/keys/destroy", label: "Destroy" },
                ],
            },
            { key: "rsa/encrypt", label: "Encrypt" },
            { key: "rsa/decrypt", label: "Decrypt" },
        ],
    },
    {
        key: "ec",
        label: "Elliptic Curve",
        collapsedlabel: "EC",
        children: [
            {
                key: "ec/keys",
                label: "Keys",
                children: [
                    { key: "ec/keys/create", label: "Create" },
                    { key: "ec/keys/export", label: "Export" },
                    { key: "ec/keys/import", label: "Import" },
                    { key: "ec/keys/revoke", label: "Revoke" },
                    { key: "ec/keys/destroy", label: "Destroy" },
                ],
            },
            { key: "ec/encrypt", label: "Encrypt" },
            { key: "ec/decrypt", label: "Decrypt" },
        ],
    },
    {
        key: "cc",
        label: "Covercrypt",
        collapsedlabel: "CC",
        children: [
            {
                key: "cc/keys",
                label: "Keys",
                children: [
                    { key: "cc/keys/create-master-key-pair", label: "Create Master Key Pair" },
                    { key: "cc/keys/create-user-key", label: "Create User Key" },
                    { key: "cc/keys/export", label: "Export" },
                    { key: "cc/keys/import", label: "Import" },
                    { key: "cc/keys/revoke", label: "Revoke" },
                    { key: "cc/keys/destroy", label: "Destroy" },
                ],
            },
            { key: "cc/encrypt", label: "Encrypt" },
            { key: "cc/decrypt", label: "Decrypt" },
        ],
    },
    {
        key: "certificates",
        label: "Certificates",
        icon: <SafetyCertificateOutlined />,
        children: [
            {
                key: "certificates/certs",
                label: "Certs",
                children: [
                    { key: "certificates/certs/certify", label: "Certify" },
                    { key: "certificates/certs/export", label: "Export" },
                    { key: "certificates/certs/import", label: "Import" },
                    { key: "certificates/certs/revoke", label: "Revoke" },
                    { key: "certificates/certs/destroy", label: "Destroy" },
                    { key: "certificates/certs/validate", label: "Validate" },
                ],
            },
            { key: "certificates/encrypt", label: "Encrypt" },
            { key: "certificates/decrypt", label: "Decrypt" },
        ],
    },
    {
        key: "attributes",
        label: "Attributes",
        icon: <ToolOutlined />,
        children: [
            { key: "attributes/get", label: "Get" },
            { key: "attributes/set", label: "Set" },
            { key: "attributes/delete", label: "Delete" },
        ],
    },
    {
        key: "access-rights",
        label: "Access Rights",
        icon: <SolutionOutlined />,
        children: [
            { key: "access-rights/grant", label: "Grant" },
            { key: "access-rights/revoke", label: "Revoke" },
            { key: "access-rights/list", label: "List" },
            { key: "access-rights/owned", label: "Owned" },
            { key: "access-rights/obtained", label: "Obtained" },
        ],
    },
];
