/* eslint-disable @typescript-eslint/no-explicit-any */
import { CopyOutlined } from "@ant-design/icons";
import { Button, Card, Tooltip, Typography, message } from "antd";
import React from "react";
import { useTranslation } from "react-i18next";

const { Title } = Typography;

interface HashMapDisplayProps {
    data?: Map<any, any>;
}

const HashMapDisplay: React.FC<HashMapDisplayProps> = ({ data }) => {
    const { t } = useTranslation("common");
    // Function to copy Map to clipboard as JSON
    const copyToClipboard = (): void => {
        if (data) {
            const mapObject = Object.fromEntries(data);
            navigator.clipboard.writeText(JSON.stringify(mapObject, null, 2));
            message.success(t("copiedToClipboard"));
        }
    };

    // Format a key for display
    const formatDisplayKey = (key: any): React.ReactNode => {
        if (typeof key === "string") return <span className="text-yellow-600">"{key}"</span>;
        if (typeof key === "number") return <span className="text-orange-600">{key}</span>;
        return <span className="text-gray-800">{String(key)}</span>;
    };

    // Render values, handling nested Maps properly
    const renderValueWithColor = (value: any): React.ReactNode => {
        if (value === null) return <span className="text-gray-600">null</span>;
        if (value === undefined) return <span className="text-gray-600">undefined</span>;
        if (typeof value === "string") return <span className="text-green-600">"{value}"</span>;
        if (typeof value === "number") return <span className="text-orange-600">{value}</span>;
        if (typeof value === "boolean") return <span className="text-blue-600">{String(value)}</span>;

        if (Array.isArray(value)) {
            return (
                <span className="text-yellow-600">
                    [{" "}
                    {value.map((item, i) => (
                        <span key={i}>
                            {renderValueWithColor(item)}
                            {i < value.length - 1 && ", "}
                        </span>
                    ))}{" "}
                    ]
                </span>
            );
        }

        if (value instanceof Map) {
            return <div className="ml-4">{renderMapPreview(value)}</div>; // Recursively render nested Maps
        }

        if (typeof value === "object") {
            return <span className="text-blue-600">{JSON.stringify(value, null, 2)}</span>;
        }

        return <span>{String(value)}</span>;
    };

    // Recursively remove empty values (empty strings, null, undefined, and empty Maps)
    // from a Map so that certificate attributes with no meaningful data are omitted.
    const recursivelyCleanEmpty = (map: Map<any, any>): Map<any, any> => {
        const cleaned = new Map<any, any>();
        for (const [key, value] of map.entries()) {
            if (value === "" || value === null || value === undefined) continue;
            if (value instanceof Map) {
                const subCleaned = recursivelyCleanEmpty(value);
                if (subCleaned.size > 0) {
                    cleaned.set(key, subCleaned);
                }
            } else {
                cleaned.set(key, value);
            }
        }
        return cleaned;
    };

    // Create Map preview with syntax highlighting.
    // Empty values are recursively pruned and entries are sorted alphabetically by key.
    const renderMapPreview = (map: Map<any, any>): React.ReactNode => {
        const cleaned = recursivelyCleanEmpty(map);
        const entries = Array.from(cleaned.entries()).sort(([a], [b]) => String(a).localeCompare(String(b)));
        return (
            <div className="p-2 rounded-md overflow-auto text-sm font-mono border border-gray-300 bg-gray-100">
                <div className="space-y-2">
                    {entries.map(([key, value], index) => (
                        <div key={index} className="flex">
                            <span className="text-blue-600">{"{"}</span>
                            <div className="ml-2">
                                {formatDisplayKey(key)}
                                <span className="text-blue-600 mx-2">{" => "}</span>
                                {renderValueWithColor(value)}
                            </div>
                            <span className="text-blue-600">{"}"}</span>
                        </div>
                    ))}
                </div>
            </div>
        );
    };

    return (
        <>
            {data && (
                <Card
                    title={
                        <div className="flex justify-between items-center">
                            <Title level={4} className="m-0">
                                {t("hashMapDisplay")}
                            </Title>
                            <Tooltip title={t("copyJson")}>
                                <Button type="text" icon={<CopyOutlined />} onClick={copyToClipboard} />
                            </Tooltip>
                        </div>
                    }
                    className="shadow-md"
                >
                    <div>
                        <Title level={5}>{t("hashMapPreview")}</Title>
                        {renderMapPreview(data)}
                    </div>
                </Card>
            )}
        </>
    );
};

export default HashMapDisplay;
