import { CopyOutlined } from "@ant-design/icons";
import { Button, Card, Tooltip, Typography, message } from "antd";
import React from "react";

const { Title } = Typography;

interface HashMapDisplayProps {
    data?: Map<any, any>;
}

const HashMapDisplay: React.FC<HashMapDisplayProps> = ({ data }) => {
    // Function to copy Map to clipboard as JSON
    const copyToClipboard = (): void => {
        if (data) {
            const mapObject = Object.fromEntries(data);
            navigator.clipboard.writeText(JSON.stringify(mapObject, null, 2));
            message.success("Copied to clipboard");
        }
    };

    // Format a value for display
    const formatDisplayKey = (key: any): React.ReactNode => {
        if (typeof key === "string") {
            return <span className="text-yellow-600">"{key}"</span>;
        }
        if (typeof key === "number") {
            return <span className="text-orange-600">{key}</span>;
        }
        if (key === null) {
            return <span className="text-gray-600">null</span>;
        }
        if (key === undefined) {
            return <span className="text-gray-600">undefined</span>;
        }
        return <span className="text-gray-800">{String(key)}</span>;
    };

    // Render value with appropriate color
    const renderValueWithColor = (value: any): React.ReactNode => {
        if (value === null) {
            return <span className="text-gray-600">null</span>;
        }
        if (value === undefined) {
            return <span className="text-gray-600">undefined</span>;
        }

        if (typeof value === "string") {
            return <span className="text-green-600">"{value}"</span>;
        }
        if (typeof value === "number") {
            return <span className="text-orange-600">{value}</span>;
        }
        if (typeof value === "boolean") {
            return <span className="text-blue-600">{String(value)}</span>;
        }

        if (Array.isArray(value)) {
            return (
                <div className="inline">
                    <span className="text-yellow-600">[</span>
                    <div className="inline-flex flex-wrap gap-1">
                        {value.map((item, i) => (
                            <span key={i} className="flex">
                                {renderValueWithColor(item)}
                                {i < value.length - 1 && <span className="text-gray-800">,</span>}
                            </span>
                        ))}
                    </div>
                    <span className="text-yellow-600">]</span>
                </div>
            );
        }

        if (value instanceof Map) {
            return <span className="text-blue-600">Map({value.size})</span>;
        }

        if (typeof value === "object") {
            return <span className="text-blue-600">{JSON.stringify(value)}</span>;
        }

        return <span>{String(value)}</span>;
    };

    // Create Map preview with syntax highlighting
    const renderMapPreview = (map: Map<any, any>): React.ReactNode => {
        return (
            <div className="p-4 rounded-md overflow-auto max-h-96 text-sm font-mono">
                <div className="space-y-3">
                    {Array.from(map.entries()).map(([key, value], index) => {
                        return (
                            <div key={index} className="flex items-start">
                                <div className="flex items-start">
                                    <span className="text-blue-600">{"{"}</span>
                                    <div className="mx-1">
                                        {formatDisplayKey(key)}
                                        <span className="text-blue-600 mx-2">{" => "}</span>
                                        {renderValueWithColor(value)}
                                    </div>
                                    <span className="text-blue-600">{"}"}</span>
                                </div>
                            </div>
                        );
                    })}
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
                                HashMap Display
                            </Title>
                            <Tooltip title="Copy JSON">
                                <Button type="text" icon={<CopyOutlined />} onClick={copyToClipboard} className="flex items-center" />
                            </Tooltip>
                        </div>
                    }
                    className="shadow-md"
                >
                    <div>
                        {/* HashMap JSON Preview */}
                        <div className="w-full">
                            <Title level={5}>HashMap Preview</Title>
                            {renderMapPreview(data)}
                        </div>
                    </div>
                </Card>
            )}
        </>
    );
};

export default HashMapDisplay;
