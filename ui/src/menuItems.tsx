import {
    AmazonOutlined,
    AuditOutlined,
    CloudOutlined,
    EyeInvisibleOutlined,
    ForkOutlined,
    GoogleOutlined,
    InboxOutlined,
    LockOutlined,
    SafetyCertificateOutlined,
    SearchOutlined,
    SolutionOutlined,
    TeamOutlined,
    ToolOutlined,
    WindowsOutlined,
} from "@ant-design/icons";

export interface MenuItem {
    key: string;
    label: string;
    description?: string;
    icon?: React.ReactNode;
    collapsedlabel?: string;
    children?: MenuItem[];
    component?: React.ComponentType;
    disabled?: boolean;
}

// Covercrypt is conditionally shown based on branding.enableCovercrypt

const baseMenu: MenuItem[] = [
    {
        key: "locate",
        label: "Locate",
        icon: <SearchOutlined />,
    },
    {
        key: "sym",
        label: "Symmetric",
        icon: <SafetyCertificateOutlined />,
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
            { key: "sym/hash", label: "Hash" },
        ],
    },
    {
        key: "rsa",
        label: "RSA",
        icon: <SafetyCertificateOutlined />,
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
            { key: "rsa/sign", label: "Sign" },
            { key: "rsa/verify", label: "Verify" },
        ],
    },
    {
        key: "ec",
        label: "Elliptic Curve",
        icon: <SafetyCertificateOutlined />,
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
            { key: "ec/sign", label: "Sign" },
            { key: "ec/verify", label: "Verify" },
        ],
    },
    // Covercrypt section is inserted after PQC by getMenuItems()
    {
        key: "pqc",
        label: "__PQC_LABEL__",
        icon: <SafetyCertificateOutlined />,
        collapsedlabel: "PQC",
        children: [
            {
                key: "pqc/keys",
                label: "Keys",
                children: [
                    { key: "pqc/keys/create", label: "Create" },
                    { key: "pqc/keys/export", label: "Export" },
                    { key: "pqc/keys/import", label: "Import" },
                    { key: "pqc/keys/revoke", label: "Revoke" },
                    { key: "pqc/keys/destroy", label: "Destroy" },
                ],
            },
            { key: "pqc/encapsulate", label: "Encapsulate" },
            { key: "pqc/decapsulate", label: "Decapsulate" },
            { key: "pqc/sign", label: "Sign" },
            { key: "pqc/verify", label: "Verify" },
        ],
    },
    {
        key: "mac",
        label: "MAC",
        icon: <AuditOutlined />,
        collapsedlabel: "MAC",
        children: [
            { key: "mac/compute", label: "Compute" },
            { key: "mac/verify", label: "Verify" },
        ],
    },
    {
        key: "fpe",
        label: "FPE",
        icon: <LockOutlined />,
        collapsedlabel: "FPE",
        children: [
            {
                key: "fpe/keys",
                label: "Keys",
                children: [
                    { key: "fpe/keys/create", label: "Create" },
                    { key: "fpe/keys/export", label: "Export" },
                    { key: "fpe/keys/import", label: "Import" },
                    { key: "fpe/keys/revoke", label: "Revoke" },
                    { key: "fpe/keys/destroy", label: "Destroy" },
                ],
            },
            { key: "fpe/encrypt", label: "Encrypt" },
            { key: "fpe/decrypt", label: "Decrypt" },
        ],
    },
    {
        key: "tokenize",
        label: "Anonymize",
        icon: <EyeInvisibleOutlined />,
        collapsedlabel: "Anon",
        children: [
            { key: "tokenize/hash", label: "Hash" },
            { key: "tokenize/noise", label: "Add Noise" },
            { key: "tokenize/word-mask", label: "Word Mask" },
            { key: "tokenize/word-tokenize", label: "Word Tokenize" },
            { key: "tokenize/word-pattern-mask", label: "Pattern Mask" },
            { key: "tokenize/aggregate-number", label: "Aggregate Number" },
            { key: "tokenize/aggregate-date", label: "Aggregate Date" },
            { key: "tokenize/scale-number", label: "Scale Number" },
        ],
    },
    {
        key: "sd",
        label: "Secret Data",
        icon: <LockOutlined />,
        collapsedlabel: "SD",
        children: [
            { key: "secret-data/create", label: "Create" },
            { key: "secret-data/export", label: "Export" },
            { key: "secret-data/import", label: "Import" },
            { key: "secret-data/revoke", label: "Revoke" },
            { key: "secret-data/destroy", label: "Destroy" },
        ],
    },
    {
        key: "opaque-object",
        label: "Opaque Object",
        icon: <InboxOutlined />,
        collapsedlabel: "Opaque",
        children: [
            { key: "opaque-object/create", label: "Create" },
            { key: "opaque-object/export", label: "Export" },
            { key: "opaque-object/import", label: "Import" },
            { key: "opaque-object/revoke", label: "Revoke" },
            { key: "opaque-object/destroy", label: "Destroy" },
        ],
    },
    {
        key: "derive-key",
        label: "Derive Key",
        icon: <ForkOutlined />,
        collapsedlabel: "DRV",
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
            { key: "attributes/modify", label: "Modify" },
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
    {
        key: "hyperscalers",
        label: "Hyperscalers",
        icon: <CloudOutlined />,
        collapsedlabel: "Cloud",
        children: [
            {
                key: "azure",
                label: "Azure",
                icon: <WindowsOutlined />,
                collapsedlabel: "Azure",
                children: [
                    { key: "azure/import-kek", label: "Import KEK" },
                    { key: "azure/export-byok", label: "Export BYOK" },
                ],
            },
            {
                key: "aws",
                label: "AWS",
                icon: <AmazonOutlined />,
                collapsedlabel: "AWS",
                children: [
                    { key: "aws/import-kek", label: "Import KEK" },
                    { key: "aws/export-key-material", label: "Export key material" },
                ],
            },
            {
                key: "google-cse",
                label: "Google CSE",
                icon: <GoogleOutlined />,
                collapsedlabel: "CSE",
            },
        ],
    },
];

const covercryptSection: MenuItem = {
    key: "cc",
    label: "Covercrypt",
    icon: <TeamOutlined />,
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
};

export function getMenuItems(options?: { enableCovercrypt?: boolean; pqcLabel?: string; isFips?: boolean }): MenuItem[] {
    const enableCc = options?.enableCovercrypt ?? true;
    const pqcLabel = options?.pqcLabel ?? "PQC";
    const isFips = options?.isFips ?? false;

    let menu = baseMenu.map((item) => (item.key === "pqc" ? { ...item, label: pqcLabel } : item));

    // Hide PQC, MAC, FPE, and Tokenize/Anonymize in FIPS mode (not approved / not available in FIPS build)
    if (isFips) {
        menu = menu.filter((item) => item.key !== "pqc" && item.key !== "mac" && item.key !== "fpe" && item.key !== "tokenize");
    }

    // Insert Covercrypt immediately after PQC so Hyperscalers stays last
    if (enableCc && !isFips) {
        const pqcIndex = menu.findIndex((item) => item.key === "pqc");
        if (pqcIndex !== -1) {
            menu = [...menu.slice(0, pqcIndex + 1), covercryptSection, ...menu.slice(pqcIndex + 1)];
        } else {
            menu = [...menu, covercryptSection];
        }
    }

    return menu;
}
